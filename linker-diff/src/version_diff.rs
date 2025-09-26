use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Result;
use linker_utils::elf::secnames::GNU_VERSION_D_SECTION_NAME_STR;
use object::LittleEndian;
use object::Object;
use object::elf::VER_FLG_BASE;
use object::read::elf::SectionHeader;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_version_d_fields,
        "version_d",
        DiffMode::Normal,
    ));
}

fn read_version_d_fields(object: &crate::Binary) -> Result<FieldValues> {
    let e = LittleEndian;
    let mut values = FieldValues::default();

    // Copied and adapted from asm_diff.rs
    let maybe_verdef = object
        .elf_file
        .sections()
        .find_map(|section| {
            section
                .elf_section_header()
                .gnu_verdef(e, object.elf_file.data())
                .transpose()
        })
        .transpose()?;

    let Some((mut verdef_iterator, strings_index)) = maybe_verdef else {
        values.insert_string_owned(
            GNU_VERSION_D_SECTION_NAME_STR.to_owned(),
            "Missing".to_owned(),
        );
        return Ok(values);
    };

    let strings =
        object
            .elf_file
            .elf_section_table()
            .strings(e, object.elf_file.data(), strings_index)?;

    while let Some((verdef, mut aux_iterator)) = verdef_iterator.next()? {
        let verdef_index = verdef.vd_ndx.get(e);
        let mut verdef_versions = String::new();

        if let Some(aux) = aux_iterator.next()? {
            let name = std::str::from_utf8(aux.name(e, strings)?)?;
            verdef_versions = format!("Version name: {name}");
        }

        // The base version point to the name of the binary, thus strip the linker suffix.
        if verdef.vd_flags.get(e) & VER_FLG_BASE != 0 {
            // First strip the .so suffix, if present.
            verdef_versions = verdef_versions.trim_end_matches(".so").to_string();
            if let Some(pos) = verdef_versions.rfind(".") {
                verdef_versions.truncate(pos);
            }
        }

        let mut version_parents = Vec::new();
        while let Some(aux) = aux_iterator.next()? {
            version_parents.push(std::str::from_utf8(aux.name(e, strings)?)?);
        }
        if !version_parents.is_empty() {
            verdef_versions += &format!(" Version parents: {}", version_parents.join(","));
        }

        values.insert_string_owned(format!("verdef_{verdef_index}"), verdef_versions);
    }

    Ok(values)
}
