//! Checks order in sections that contain pointers. e.g. `.init_array`, `.fini_array`.

use crate::Arch;
use crate::Binary;
use crate::Result;
use crate::arch::RType as _;
use crate::get_r_type;
use crate::header_diff::ResolvedValue;
use anyhow::Context;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::secnames;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::ObjectSymbolTable;
use object::RelocationTarget;
use object::SymbolKind;
use std::borrow::Cow;

pub(crate) fn report_diffs<A: Arch>(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_array(
        objects,
        |bin| get_pointer_list::<A>(bin, secnames::INIT_ARRAY_SECTION_NAME_STR),
        "init_array",
    ));

    report.add_diffs(crate::header_diff::diff_array(
        objects,
        |bin| get_pointer_list::<A>(bin, secnames::FINI_ARRAY_SECTION_NAME_STR),
        "fini_array",
    ));
}

fn get_pointer_list<A: Arch>(bin: &Binary, section_name: &str) -> Result<Vec<ResolvedValue>> {
    let Some(sec) = bin.section_by_name(section_name) else {
        return Ok(Vec::new());
    };

    let section_address = sec.address();

    let data = sec.data()?;

    const ADDRESS_SIZE: usize = size_of::<u64>();

    let mut names = Vec::with_capacity(data.len() / ADDRESS_SIZE);

    for (entry_num, address_bytes) in data.chunks_exact(ADDRESS_SIZE).enumerate() {
        let mut address = u64::from_le_bytes(*address_bytes.first_chunk::<ADDRESS_SIZE>().unwrap());
        let entry_address = section_address + (entry_num * ADDRESS_SIZE) as u64;
        let mut symbol_names = Vec::new();

        let relocation = bin.address_index.relocation_at_address(entry_address);

        if let Some(relocation) = relocation {
            if let RelocationTarget::Symbol(symbol_index) = relocation.target() {
                let dynsym = bin
                    .elf_file
                    .dynamic_symbol_table()
                    .context("Missing .dynsym")?;

                symbol_names.push(String::from_utf8_lossy(
                    dynsym.symbol_by_index(symbol_index)?.name_bytes()?,
                ));
            }

            let r_type = get_r_type::<A::RType>(relocation);

            match r_type.dynamic_relocation_kind() {
                Some(DynamicRelocationKind::Relative) => {
                    address = relocation.addend() as u64;
                }
                Some(other) => {
                    symbol_names.push(Cow::Owned(format!("Rel({other:?})")));
                }
                None => {}
            }
        }

        if symbol_names.is_empty() && address != 0 {
            for symbol_index in bin.address_index.symbols_at_address(address) {
                let symbol = bin.elf_file.symbol_by_index(*symbol_index)?;

                let name_bytes = symbol.name_bytes()?;

                if name_bytes.is_empty() || symbol.kind() != SymbolKind::Text {
                    continue;
                }

                symbol_names.push(String::from_utf8_lossy(name_bytes));
            }
        }

        if symbol_names.is_empty() {
            if let Some(relocation) = relocation {
                symbol_names.push(Cow::Owned(format!("{:?}", relocation.kind())));
            } else if address == 0 {
                symbol_names.push(Cow::Borrowed("0x0"));
            }
        }

        symbol_names.sort();

        if symbol_names.is_empty() {
            names.push(ResolvedValue {
                for_comparison: "??".to_owned(),
                formatted: format!("0x{address:x}"),
            });
        } else {
            let joined = symbol_names.join(" / ");

            names.push(ResolvedValue {
                for_comparison: joined.clone(),
                formatted: joined,
            });
        }
    }

    Ok(names)
}
