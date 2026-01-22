use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Result;
use linker_utils::elf::secnames::GNU_VERSION_D_SECTION_NAME_STR;
use linker_utils::elf::secnames::GNU_VERSION_SECTION_NAME_STR;
use object::LittleEndian;
use object::Object;
use object::ObjectSymbol;
use object::elf;
use object::elf::VER_FLG_BASE;
use object::elf::VERSYM_HIDDEN;
use object::elf::VERSYM_VERSION;
use object::read::elf::Sym;
use object::read::elf::VersionIndex;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_gnu_version_d,
        "version_d",
        DiffMode::Normal,
    ));
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_gnu_version,
        "version",
        DiffMode::Normal,
    ));
}

// Reads version names defined in the binary's version_d section and their parent name to find
// whether all the versions are present.
fn read_gnu_version_d(bin: &crate::Binary) -> Result<FieldValues> {
    let e = LittleEndian;
    let mut values = FieldValues::default();

    let Some((mut verdef_iterator, strings_index)) = bin
        .elf_file
        .elf_section_table()
        .gnu_verdef(e, bin.elf_file.data())?
    else {
        values.insert_string_owned(
            GNU_VERSION_D_SECTION_NAME_STR.to_owned(),
            "Missing".to_owned(),
        );
        return Ok(values);
    };

    let strings =
        bin.elf_file
            .elf_section_table()
            .strings(e, bin.elf_file.data(), strings_index)?;

    while let Some((verdef, mut aux_iterator)) = verdef_iterator.next()? {
        let verdef_index = verdef.vd_ndx.get(e);
        let mut verdef_version = String::new();

        if let Some(aux) = aux_iterator.next()? {
            let name = std::str::from_utf8(aux.name(e, strings)?)?;
            verdef_version = format!("Version name: {name}");
        }

        // The base version points to the name of the binary, which is problematic for integration
        // tests. They will add `.<linker_name>` or `.<linker_name>.so` to the output name.
        // Thus, we strip it here.
        if verdef.vd_flags.get(e) & VER_FLG_BASE != 0 {
            verdef_version = verdef_version.trim_end_matches(".so").to_string();
            if let Some(pos) = verdef_version.rfind(".") {
                verdef_version.truncate(pos);
            }
        }

        let mut version_parents = Vec::new();
        while let Some(aux) = aux_iterator.next()? {
            version_parents.push(std::str::from_utf8(aux.name(e, strings)?)?);
        }
        if !version_parents.is_empty() {
            verdef_version += &format!(" Version parents: {}", version_parents.join(","));
        }

        values.insert_string_owned(format!("verdef_{verdef_index}"), verdef_version);
    }

    Ok(values)
}

// Reads dynamic symbol names and their corresponding version names to find whether all dynamic
// symbols have the correct version.
fn read_gnu_version(bin: &crate::Binary) -> Result<FieldValues> {
    let e = LittleEndian;
    let mut values = FieldValues::default();

    let Some((versyms, _)) = bin
        .elf_file
        .elf_section_table()
        .gnu_versym(e, bin.elf_file.data())?
    else {
        values.insert_string_owned(
            GNU_VERSION_SECTION_NAME_STR.to_owned(),
            "Missing".to_owned(),
        );
        return Ok(values);
    };

    let versions = bin
        .elf_file
        .elf_section_table()
        .versions(e, bin.elf_file.data())?
        .unwrap();

    let dynsym_iter = bin.elf_file.dynamic_symbols();

    // dynsym_iter skips the first symbol, make versym the same.
    for (versym, dynsym) in versyms.iter().skip(1).zip(dynsym_iter) {
        let sym_name = dynsym.name_bytes()?;

        // GNU ld sometimes creates symbols for sections, like .data or .init. Wild doesn't, so we
        // skip them.
        if dynsym.elf_symbol().st_type() == elf::STT_SECTION {
            continue;
        }

        // TODO: this duplicates `symbol_diff.rs`
        // On aarch64, GNU ld emits a dynamic symbol called "_stack", which it puts in some section
        // or other that doesn't make sense. e.g. ".got.plt". It probably puts it in that section
        // because it's closest to the value that it assigns to the symbol. It's not clear where
        // this symbol comes from. It's neither in any input files, nor in GNU ld's built-in linker
        // script.
        if sym_name == b"_stack" {
            continue;
        }

        let version_index_raw = versym.0.get(e);
        let version_index = version_index_raw & VERSYM_VERSION;
        let hidden = version_index_raw & VERSYM_HIDDEN == VERSYM_HIDDEN;

        // TODO: Currently Wild doesn't differentiate between local and global versions.
        let version_name = if version_index <= 1 {
            b"local or global"
        } else {
            versions
                .version(VersionIndex(version_index))?
                .unwrap()
                .name()
        };

        // GNU ld creates an empty symbol for each version, Wild doesn't, so we skip it.
        if dynsym.elf_symbol().st_type() == elf::STT_OBJECT
            && dynsym.elf_symbol().is_absolute(e)
            && sym_name == version_name
        {
            continue;
        }

        values.insert_string_owned(
            str::from_utf8(sym_name)?.to_string(),
            format!(
                "{}{}",
                str::from_utf8(version_name)?,
                if hidden { " (hidden)" } else { "" }
            ),
        );
    }

    values.sort_values();

    Ok(values)
}
