//! Code to double-check that we did certain things correctly. Generally only used in debug builds.

use crate::error::Result;
use crate::layout::Layout;
use crate::layout::ResolutionFlags;
use crate::resolution::ValueFlags;
use crate::storage::StorageModel;
use crate::storage::SymbolNameMap;
use anyhow::Context;
use anyhow::bail;
use linker_utils::elf::secnames::GOT_SECTION_NAME_STR;
use object::LittleEndian;
use object::read::elf::SectionHeader as _;

pub(crate) fn validate_bytes<S: StorageModel>(layout: &Layout<S>, file_bytes: &[u8]) -> Result {
    let object =
        crate::elf::File::parse(file_bytes, true).context("Failed to parse our output file")?;
    validate_object(&object, layout).context("Output validation failed")
}

/// Checks that what we actually wrote to our output file matches what we intended to write in
/// `layout`.
fn validate_object<S: StorageModel>(object: &crate::elf::File, layout: &Layout<S>) -> Result {
    if layout.args().is_relocatable() {
        // For now, we don't do any validation of relocatable outputs. The only thing we're
        // currently validating is GOT entries and they'll all have dynamic relocations.
        return Ok(());
    }
    let Some((_, got)) = object.section_by_name(GOT_SECTION_NAME_STR) else {
        return Ok(());
    };

    let got_data = got.data(LittleEndian, object.data)?;

    for (symbol_name, symbol_id) in layout.symbol_db.global_names.all_symbols() {
        match layout.local_symbol_resolution(*symbol_id) {
            None => {}
            Some(resolution) => {
                validate_resolution(symbol_name.bytes(), resolution, got, got_data)?;
            }
        }
    }
    for group in &layout.group_layouts {
        for file in &group.files {
            match file {
                crate::layout::FileLayout::Prelude(_) => {}
                crate::layout::FileLayout::Object(obj) => {
                    for (sec_index, sec) in obj.object.sections.enumerate() {
                        if let Some(resolution) =
                            obj.section_resolutions[sec_index.0].full_resolution()
                        {
                            validate_resolution(
                                obj.object.section_name(sec)?,
                                &resolution,
                                got,
                                got_data,
                            )?;
                        }
                    }
                }
                crate::layout::FileLayout::Dynamic(_) => {}
                crate::layout::FileLayout::Epilogue(_) => {}
                crate::layout::FileLayout::NotLoaded => {}
            }
        }
    }
    Ok(())
}

fn validate_resolution(
    name: &[u8],
    resolution: &crate::layout::Resolution,
    got: &crate::elf::SectionHeader,
    got_data: &[u8],
) -> Result {
    let res_flags = resolution.resolution_flags;
    let value_flags = resolution.value_flags;
    if value_flags.contains(ValueFlags::IFUNC)
        || res_flags.contains(ResolutionFlags::GOT_TLS_MODULE)
        || res_flags.contains(ResolutionFlags::GOT_TLS_OFFSET)
        || res_flags.contains(ResolutionFlags::GOT_TLS_DESCRIPTOR)
    {
        return Ok(());
    };
    if let Some(got_address) = resolution.got_address {
        let start_offset = (got_address.get() - got.sh_addr(LittleEndian)) as usize;
        let end_offset = start_offset + size_of::<u64>();
        if end_offset > got_data.len() {
            bail!("GOT offset beyond end of GOT 0x{end_offset}");
        }
        if resolution.value_flags.contains(ValueFlags::DYNAMIC)
            || resolution.value_flags.contains(ValueFlags::IFUNC)
        {
            return Ok(());
        }
        let expected = resolution.raw_value;
        let address = bytemuck::pod_read_unaligned(&got_data[start_offset..end_offset]);
        if expected != address {
            let name = String::from_utf8_lossy(name);
            bail!(
                "res={res_flags:?} `{name}` has address 0x{expected:x}, but GOT \
                 (at 0x{got_address:x}) points to 0x{address:x}"
            );
        }
    }
    Ok(())
}
