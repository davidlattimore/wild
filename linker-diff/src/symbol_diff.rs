use crate::Result;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;

pub(crate) fn report_diffs(report: &mut crate::Report, bins: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        bins,
        read_dynsym,
        "dynsym",
        DiffMode::Normal,
    ));
}

fn read_dynsym(bin: &crate::Binary) -> Result<FieldValues> {
    let mut values = FieldValues::default();

    for sym in bin.elf_file.dynamic_symbols() {
        let Ok(name) = sym.name_bytes() else {
            continue;
        };

        if sym.is_local() {
            continue;
        }

        // On aarch64, GNU ld emits a dynamic symbol called "_stack", which it puts in some section
        // or other that doesn't make sense. e.g. ".got.plt". It probably puts it in that section
        // because it's closest to the value that it assigns to the symbol. It's not clear where
        // this symbol comes from. It's neither in any input files, nor in GNU ld's built-in linker
        // script.
        if name == b"_stack" {
            continue;
        }

        // TODO: Diff type, binding and visibility. Also, diff undefined symbols.
        if let Some(section_index) = sym.section_index() {
            let section = bin.elf_file.section_by_index(section_index)?;
            let section_name = String::from_utf8_lossy(section.name_bytes()?).into_owned();

            values.insert_string_owned(
                format!("{}.section", String::from_utf8_lossy(name)),
                section_name,
            );
        };
    }

    Ok(values)
}
