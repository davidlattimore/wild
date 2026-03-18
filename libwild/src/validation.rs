//! Code to double-check that we did certain things correctly. Generally only used in debug builds.

use crate::elf::Elf;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout::Layout;
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use linker_utils::elf::secnames::GOT_SECTION_NAME_STR;
use object::LittleEndian;
use object::read::elf::SectionHeader as _;

type ElfLayout<'data> = Layout<'data, Elf>;

pub(crate) fn validate_bytes(layout: &ElfLayout, file_bytes: &[u8]) -> Result {
    let object = crate::elf::File::parse_bytes(file_bytes, true)
        .context("Failed to parse our output file")?;
    validate_object(&object, layout).context("Output validation failed")
}

/// Checks that what we actually wrote to our output file matches what we intended to write in
/// `layout`.
fn validate_object(object: &crate::elf::File, layout: &ElfLayout) -> Result {
    if layout.symbol_db.output_kind.is_relocatable() {
        // For now, we don't do any validation of relocatable outputs. The only thing we're
        // currently validating is GOT entries and they'll all have dynamic relocations.
        return Ok(());
    }
    let Some((_, got)) = object.section_by_name(GOT_SECTION_NAME_STR) else {
        return Ok(());
    };

    let got_data = got.data(LittleEndian, object.data)?;

    for (symbol_name, symbol_id) in layout.symbol_db.all_unversioned_symbols() {
        match layout.local_symbol_resolution(*symbol_id) {
            None => {}
            Some(resolution) => {
                <Elf as Platform>::validate_resolution(
                    symbol_name.bytes(),
                    resolution,
                    got,
                    got_data,
                )?;
            }
        }
    }
    for group in &layout.group_layouts {
        for file in &group.files {
            match file {
                crate::layout::FileLayout::Object(obj) => {
                    for (sec_index, sec) in obj.object.sections.enumerate() {
                        if let Some(resolution) =
                            obj.section_resolutions[sec_index.0].full_resolution()
                        {
                            <Elf as Platform>::validate_resolution(
                                obj.object.section_name(sec)?,
                                &resolution,
                                got,
                                got_data,
                            )?;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
