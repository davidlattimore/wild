use crate::header_diff::DiffMode;
use crate::Diff;
use crate::DiffValues;
use crate::Object;
use crate::Report;
use anyhow::Result;
use fallible_iterator::FallibleIterator;
use gimli::LittleEndian;
use itertools::Itertools;
use object::ObjectSection;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;

#[derive(Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct CompilationUnitIdentifier {
    name: String,
    comp_dir: String,
}

#[derive(Debug, Default, PartialEq, Eq, Hash)]
struct CompilationUnit {
    size: usize,
}

impl Display for CompilationUnitIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} ({})", self.name, self.comp_dir))
    }
}

type DebugInfo = HashMap<CompilationUnitIdentifier, CompilationUnit>;

const DEBUG_INFO_ERROR_KEY: &str = "debug_info";

fn parse_unit_info(
    unit: gimli::UnitRef<'_, gimli::EndianSlice<'_, LittleEndian>>,
    size: usize,
) -> Result<(CompilationUnitIdentifier, CompilationUnit)> {
    let mut name = None;
    let mut comp_dir = None;

    let mut entries = unit.entries();
    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        if delta_depth == 1 {
            break;
        }
        let mut attrs = entry.attrs();
        let attr_to_string = |attr: gimli::Attribute<_>| -> Result<String> {
            Ok(unit
                .attr_string(attr.value())?
                .to_string_lossy()
                .to_string())
        };

        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = Some(attr_to_string(attr)?);
                }
                gimli::DW_AT_comp_dir => {
                    comp_dir = Some(attr_to_string(attr)?);
                }
                _ => {}
            }
        }
    }

    let Some(name) = name else {
        anyhow::bail!("Missing name for a compilation unit");
    };
    let Some(comp_dir) = comp_dir else {
        anyhow::bail!("Missing comp_dir for a compilation unit");
    };
    Ok((
        CompilationUnitIdentifier { name, comp_dir },
        CompilationUnit { size },
    ))
}

fn read_file_debug_info(obj: &Object) -> Result<DebugInfo> {
    let load_section = |id: gimli::SectionId| -> Result<Cow<[u8]>> {
        Ok(match obj.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => Cow::Borrowed(&[]),
        })
    };

    let borrow_section = |section| gimli::EndianSlice::new(Cow::as_ref(section), LittleEndian);
    let dwarf_sections = gimli::DwarfSections::load(&load_section)?;
    let dwarf = dwarf_sections.borrow(borrow_section);

    let units: Vec<_> = dwarf.units().collect()?;

    units
        .iter()
        .map(|unit| parse_unit_info(dwarf.unit(*unit)?.unit_ref(&dwarf), unit.unit_length()))
        .collect::<Result<DebugInfo>>()
}

fn diff_debug_info(
    objects: &[Object<'_>],
    get_fields_fn: impl Fn(&Object<'_>) -> Result<DebugInfo>,
    diff_mode: DiffMode,
) -> Vec<Diff> {
    let debug_infos = objects.iter().map(get_fields_fn).collect_vec();
    if diff_mode == DiffMode::IgnoreIfAllErrors && debug_infos.iter().all(Result::is_err) {
        return vec![];
    }

    let mut mismatches = Vec::new();
    let mut ok = Vec::new();
    let mut errors = Vec::new();
    let mut has_errors = false;
    for d in debug_infos {
        match d {
            Ok(o) => {
                ok.push(o);
                errors.push("OK".to_owned());
            }
            Err(e) => {
                errors.push(e.to_string());
                has_errors = true;
            }
        }
    }
    if has_errors {
        return vec![Diff {
            key: DEBUG_INFO_ERROR_KEY.to_owned(),
            values: DiffValues::PerObject(errors),
        }];
    }

    for (ref_unit_ident, ref_unit) in ok.first().unwrap() {
        for (object_id, info) in ok.iter().enumerate().skip(1) {
            let unit = info.get(ref_unit_ident);
            match unit {
                Some(unit) => {
                    if ref_unit.size != unit.size {
                        mismatches.push(Diff {
                            key: format!("{DEBUG_INFO_ERROR_KEY}.size_mismatch"),
                            values: DiffValues::PreFormatted(format!(
                                "Size mismatch for {ref_unit_ident} in {}, expected: {}, got: {}",
                                objects[object_id].name, ref_unit.size, unit.size
                            )),
                        });
                    }
                }
                None => {
                    mismatches.push(Diff {
                        key: format!("{DEBUG_INFO_ERROR_KEY}.missing_unit"),
                        values: DiffValues::PreFormatted(format!(
                            "Missing compilation unit: {ref_unit_ident} in {}",
                            objects[object_id].name
                        )),
                    });
                }
            }
        }
    }

    mismatches
}

pub(crate) fn check_debug_info(report: &mut Report, objects: &[crate::Object]) {
    report.add_diffs(diff_debug_info(
        objects,
        read_file_debug_info,
        DiffMode::IgnoreIfAllErrors,
    ));
}
