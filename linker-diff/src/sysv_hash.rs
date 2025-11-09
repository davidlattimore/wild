use crate::Binary;
use crate::Result;
use anyhow::Context;
use anyhow::bail;
use anyhow::ensure;
use linker_utils::elf::secnames::HASH_SECTION_NAME_STR;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::ObjectSymbolTable;
use object::SymbolIndex;
use object::elf::FileHeader64;
use object::read::elf::ElfSymbolTable;
use std::convert::TryInto;

pub(crate) fn check_object(obj: &Binary) -> Result {
    let num_symbols = obj
        .elf_file
        .dynamic_symbols()
        .map(|s| s.index().0)
        .max()
        .unwrap_or(0)
        + 1;
    if num_symbols <= 1 {
        return Ok(());
    }

    let dynsym = obj
        .elf_file
        .dynamic_symbol_table()
        .context("Missing dynamic symbol table")?;

    let hash_section = obj
        .elf_file
        .section_by_name(HASH_SECTION_NAME_STR)
        .context("Missing .hash")?;

    if hash_section.align() < 4 {
        bail!(".hash has alignment {}", hash_section.align());
    }

    let data = hash_section.data()?;
    ensure!(data.len() >= 8, "Insufficient .hash bytes");

    let nbucket = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let nchain = u32::from_le_bytes(data[4..8].try_into().unwrap());

    ensure!(nbucket != 0, ".hash has zero buckets");
    ensure!(
        usize::try_from(nchain).ok() == Some(num_symbols),
        ".hash nchain {nchain} does not match number of dynamic symbols {num_symbols}"
    );

    let mut offset = 8;
    let bucket_len = usize::try_from(nbucket).unwrap() * 4;
    ensure!(
        data.len() >= offset + bucket_len,
        "Insufficient data for .hash buckets"
    );
    let buckets = data[offset..offset + bucket_len]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();
    offset += bucket_len;

    let chain_len = usize::try_from(nchain).unwrap() * 4;
    ensure!(
        data.len() >= offset + chain_len,
        "Insufficient data for .hash chains"
    );
    let chains = data[offset..offset + chain_len]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>();

    for sym in obj.elf_file.dynamic_symbols() {
        if !sym.is_definition() {
            continue;
        }

        let name = sym.name()?;
        let name_bytes = sym.name_bytes()?;
        let symbol_index = lookup_symbol(name_bytes, &buckets, &chains, dynsym)
            .with_context(|| format!("Hash lookup of symbol `{name}` failed"))?;
        if symbol_index != sym.index().0 {
            bail!(
                "Dynamic symbol `{}` hash lookup found {}, expected {}",
                sym.name()?,
                symbol_index,
                sym.index().0
            );
        }
    }

    Ok(())
}

fn lookup_symbol(
    sym_name: &[u8],
    buckets: &[u32],
    chains: &[u32],
    dynsym: ElfSymbolTable<FileHeader64<LittleEndian>>,
) -> Result<usize> {
    if buckets.is_empty() {
        bail!("Empty .hash bucket table");
    }

    let hash = object::elf::hash(sym_name);
    let bucket = (hash % buckets.len() as u32) as usize;
    let mut index = buckets[bucket] as usize;
    if index == 0 {
        bail!("Symbol not found");
    }

    loop {
        ensure!(index < chains.len(), "Chain index {index} out of range");
        let dynsym_entry = dynsym
            .symbol_by_index(SymbolIndex(index))
            .context("Invalid symbol index in .hash")?;
        if dynsym_entry
            .name_bytes()
            .is_ok_and(|bytes| bytes == sym_name)
        {
            return Ok(index);
        }
        let next = chains[index] as usize;
        if next == 0 {
            bail!("Symbol not found");
        }
        index = next;
    }
}
