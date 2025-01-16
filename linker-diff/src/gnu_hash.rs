use crate::Binary;
use crate::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use linker_utils::elf::secnames::GNU_HASH_SECTION_NAME_STR;
use object::elf::FileHeader64;
use object::read::elf::ElfSymbolTable;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::ObjectSymbolTable;
use object::SymbolIndex;

type GnuHashHeader = object::elf::GnuHashHeader<LittleEndian>;

pub(crate) fn check_object(obj: &Binary) -> Result {
    let num_symbols = obj
        .elf_file
        .dynamic_symbols()
        .map(|s| s.index().0)
        .max()
        .unwrap_or(0)
        + 1;
    if num_symbols == 0 {
        return Ok(());
    }
    let gnu_hash = obj
        .elf_file
        .section_by_name(GNU_HASH_SECTION_NAME_STR)
        .context("Missing .gnu.hash")?;

    if gnu_hash.align() != 8 {
        bail!(".gnu.hash has alignment {}", gnu_hash.align());
    }

    let gnu_hash_bytes = gnu_hash.data()?;
    let e = LittleEndian;

    let (header, rest) = object::from_bytes::<GnuHashHeader>(gnu_hash_bytes)
        .map_err(|_| anyhow!("Insufficient .gnu.hash bytes"))?;

    let bloom_count = header.bloom_count.get(e);
    let (bloom_values, rest) = object::slice_from_bytes::<u64>(rest, bloom_count as usize)
        .map_err(|_| anyhow!("Insufficient data for .gnu.hash bloom filter"))?;

    let bucket_count = header.bucket_count.get(e);
    let (buckets, rest) = object::slice_from_bytes::<u32>(rest, bucket_count as usize)
        .map_err(|_| anyhow!("Insufficient data for .gnu.hash buckets"))?;

    let symbol_base = header.symbol_base.get(e);
    let chain_count = num_symbols
        .checked_sub(symbol_base as usize)
        .with_context(|| {
            format!(
                ".gnu.hash symbol base ({symbol_base}) is greater than number of \
                dynamic symbols ({num_symbols})"
            )
        })?;

    // For a simple binary, both LLD and BFD create .gnu.hash section that does not contain any chain:
    // Contents of section .gnu.hash:
    // objdump -s -j .gnu.hash
    // 4003e8 01000000 01000000 01000000 00000000
    // 4003f8 00000000 00000000 00000000
    if buckets == [0] && rest.is_empty() {
        return Ok(());
    }

    let (chains, _) = object::slice_from_bytes::<u32>(rest, chain_count).map_err(|_| {
        anyhow!(
            "Insufficient data for .gnu.hash chains. \
                num_symbols={num_symbols} symbol_base={symbol_base}"
        )
    })?;

    let dynsym = obj
        .elf_file
        .dynamic_symbol_table()
        .context("Missing dynamic symbol table")?;

    for sym in obj.elf_file.dynamic_symbols() {
        if !sym.is_definition() {
            // It's somewhat tempting to verify that the symbol index is >= symbol_base. However
            // it seems like if all the dynamic symbols are undefined that GNU ld sets
            // symbol_base to the index of the last undefined symbol rather than one higher as
            // you might expect.
            continue;
        }
        let name = sym.name()?;
        let name_bytes = sym.name_bytes()?;
        let symbol_index = lookup_symbol(name_bytes, header, bloom_values, buckets, chains, dynsym)
            .with_context(|| {
                let hash = object::elf::gnu_hash(name_bytes);
                format!(
                    "Hash lookup of symbol `{name}` failed. \
                        hash=0x{hash:x} \
                        buckets={buckets:?} \
                        symbol_base={symbol_base} \
                        chains={chains:x?}"
                )
            })?;
        if symbol_index != sym.index().0 {
            bail!(
                "Dynamic symbol `{}` hash lookup found {symbol_index}, expected {}",
                sym.name()?,
                sym.index().0
            );
        }
    }

    Ok(())
}

fn lookup_symbol(
    sym_name: &[u8],
    header: &object::elf::GnuHashHeader<LittleEndian>,
    bloom_values: &[u64],
    buckets: &[u32],
    chains: &[u32],
    dynsym: ElfSymbolTable<FileHeader64<LittleEndian>>,
) -> Result<usize> {
    let e = LittleEndian;
    let symbol_base = header.symbol_base.get(e) as usize;
    let hash = object::elf::gnu_hash(sym_name);
    let elf_class_bits = size_of::<u64>() as u32 * 8;
    let bloom_shift = header.bloom_shift.get(e);
    let bloom_count = bloom_values.len() as u32;
    let bucket_count = buckets.len() as u32;
    let bloom_value = bloom_values[((hash / elf_class_bits) % bloom_count) as usize];
    let bloom_mask =
        (1 << (hash % elf_class_bits)) | (1 << ((hash >> bloom_shift) % elf_class_bits));
    if (bloom_value & bloom_mask) != bloom_mask {
        bail!("Bloom filter excludes symbol");
    }
    let bucket = hash % bucket_count;
    let mut symbol_index = buckets[bucket as usize] as usize;
    if symbol_index < symbol_base {
        bail!("symbol_index ({symbol_index}) < symbol_base ({symbol_base}). bucket={bucket}");
    }
    loop {
        let chain_value = chains[symbol_index - symbol_base];
        if chain_value & !1 == hash & !1
            && dynsym
                .symbol_by_index(SymbolIndex(symbol_index))
                .and_then(|sym| sym.name_bytes())
                .is_ok_and(|n| n == sym_name)
        {
            return Ok(symbol_index);
        }
        if chain_value & 1 == 1 {
            bail!("Symbol not found");
        }
        symbol_index += 1;
    }
}
