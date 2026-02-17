//! Uses DWARF debug info, if available, to find file and line number information for a particular
//! offset in an input section.

use crate::elf::File;
use crate::elf::Rela;
use crate::error::Result;
use crate::platform::ObjectFile as _;
use crate::platform::Platform;
use crate::platform::Relocation;
use crate::platform::RelocationSequence as _;
use anyhow::Context;
use object::LittleEndian;
use object::read::elf::Crel;
use object::read::elf::RelocationSections;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Display;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct SourceInfo(Option<SourceInfoDetails>);

#[derive(Debug)]
pub(crate) struct SourceInfoDetails {
    path: PathBuf,
    line: u64,
}

/// The address at which we'll pretend that we loaded the section we're interested in. This value is
/// arbitrary, but should be larger than the largest input section we expect to encounter and small
/// enough to fit comfortably in a u32.
const SECTION_LOAD_ADDRESS: u64 = 0x1_000_000_000;

/// Attempts to locate source info for `offset_in_section` within `section`.
pub(crate) fn get_source_info<'data, P: Platform<'data>>(
    object: &File,
    relocations: &RelocationSections,
    section: &object::elf::SectionHeader64<LittleEndian>,
    offset_in_section: u64,
) -> Result<SourceInfo> {
    let dwarf_sections =
        gimli::DwarfSections::load(&|id: gimli::SectionId| -> Result<Cow<[u8]>> {
            section_data_with_relocations::<P>(object, relocations, id, section)
        })?;

    let borrow_section: &dyn for<'a> Fn(
        &'a Cow<[u8]>,
    ) -> gimli::EndianSlice<'a, gimli::LittleEndian> =
        &|section| gimli::EndianSlice::new(section, gimli::LittleEndian);

    let dwarf = dwarf_sections.borrow(borrow_section);

    let mut details = None;

    let address_of_interest = SECTION_LOAD_ADDRESS + offset_in_section;

    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;

        let Some(program) = unit.line_program.clone() else {
            continue;
        };

        let comp_dir = unit
            .comp_dir
            .as_ref()
            .map(|dir| Path::new(OsStr::from_bytes(dir)).to_owned())
            .unwrap_or_default();

        let mut rows = program.rows();

        while let Some((header, row)) = rows.next_row()? {
            if row.address() > address_of_interest {
                break;
            }

            // Computing the path for every row seems a bit wasteful. If it turns out that this is
            // actually a problem, then we could experiment with iterating through the rows twice.
            // Once to determine which row we want then a second time to get the relevant properties
            // from the row.
            let mut path = PathBuf::new();
            if let Some(file) = row.file(header) {
                path = comp_dir.clone();

                path.push(OsStr::from_bytes(
                    &dwarf.attr_string(&unit, file.path_name())?,
                ));
            }

            let line = row.line().map_or(0, |l| l.get());

            details = Some(SourceInfoDetails { path, line });
        }
    }

    Ok(SourceInfo(details))
}

/// Gets the data for section `id` from `object` and applies relocations to it.
fn section_data_with_relocations<'data, P: Platform<'data>>(
    object: &File,
    relocations: &RelocationSections,
    id: gimli::SectionId,
    section_of_interest: &object::elf::SectionHeader64<LittleEndian>,
) -> Result<Cow<'static, [u8]>> {
    let data = match object.section_by_name(id.name()) {
        Some((index, section)) => {
            let mut section_data = object.section_data_cow(section)?.into_owned();

            // Apply relocations.
            match object.relocations(index, relocations)? {
                crate::elf::RelocationList::Rela(relocations) => {
                    apply_section_relocations::<P, Rela>(
                        object,
                        section_of_interest,
                        &mut section_data,
                        relocations.rel_iter(),
                    )?;
                }
                crate::elf::RelocationList::Crel(relocations) => {
                    apply_section_relocations::<P, Crel>(
                        object,
                        section_of_interest,
                        &mut section_data,
                        relocations.flat_map(|r| r.ok()),
                    )?;
                }
            }

            Cow::Owned(section_data)
        }
        None => Cow::Borrowed(&[][..]),
    };

    Ok(data)
}

fn apply_section_relocations<'data, P: Platform<'data>, R: Relocation>(
    object: &File<'_>,
    section_of_interest: &object::elf::SectionHeader64<LittleEndian>,
    section_data: &mut [u8],
    relocations: impl Iterator<Item = R>,
) -> Result {
    for rel in relocations {
        let sym_index = rel.symbol().context("Relocation for undefine symbol")?;
        let symbol = object.symbol(sym_index)?;

        let mut value = symbol
            .st_value
            .get(LittleEndian)
            .wrapping_add(rel.addend() as u64);

        let symbol_section = object.section(object::SectionIndex(
            symbol.st_shndx.get(LittleEndian) as usize,
        ))?;

        let data_offset = rel.offset() as usize;

        if symbol_section.sh_offset.get(LittleEndian)
            == section_of_interest.sh_offset.get(LittleEndian)
        {
            value += SECTION_LOAD_ADDRESS;
        }

        let r_type = P::relocation_from_raw(rel.raw_type())?;

        let linker_utils::elf::RelocationSize::ByteSize(num_bytes) = r_type.size else {
            continue;
        };

        if r_type.kind == linker_utils::elf::RelocationKind::Absolute {
            section_data
                .get_mut(data_offset..data_offset + num_bytes)
                .context("Invalid relocation offset")?
                .copy_from_slice(&value.to_le_bytes()[..num_bytes]);
        }
    }
    Ok(())
}

impl Display for SourceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(details) = self.0.as_ref() {
            let SourceInfoDetails { path, line } = details;
            write!(f, "\n    {}:{}", path.display(), line)?;
        }
        Ok(())
    }
}
