use crate::Object;
use crate::Result;
use anyhow::bail;
use object::read::elf::SectionHeader as _;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSymbol;
use std::ops::Not;

pub(crate) fn validate_debug(object: &Object) -> Result {
    validate(object, false)
}

pub(crate) fn validate_dynamic(object: &Object) -> Result {
    validate(object, true)
}

fn validate(object: &Object, dynamic: bool) -> Result {
    let mut symtab_info = 0;
    let (symtab_section_type, mut symbols) = if dynamic {
        (object::elf::SHT_DYNSYM, object.elf_file.dynamic_symbols())
    } else {
        (object::elf::SHT_SYMTAB, object.elf_file.symbols())
    };
    for section in object.elf_file.elf_section_table().iter() {
        if section.sh_type(LittleEndian) == symtab_section_type {
            symtab_info = section.sh_info(LittleEndian);
        }
    }
    let first_non_local = symbols.find_map(|sym| sym.is_local().not().then(|| sym.index()));
    if let Some(first_non_local) = first_non_local {
        if first_non_local.0 != symtab_info as usize {
            bail!("info={symtab_info}, but first non-local is {first_non_local}")
        }
    }

    Ok(())
}
