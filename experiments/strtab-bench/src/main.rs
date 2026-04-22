//! Measures suffix-sharing savings on a real ELF's `.strtab` /
//! `.dynstr`. Point it at any ELF and it prints "naive size vs
//! packed size" so we can decide whether wiring suffix-sharing
//! into wild's writer is worth the refactor.
//!
//! Usage:
//!   cargo run --release -p strtab-bench -- <path/to/elf>

use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use rayon::slice::ParallelSliceMut;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::ExitCode;

/// Pack a set of strings with suffix sharing. Returns (packed_bytes_len).
/// Copy of `libwild::suffix_share::pack` minus the offsets map (we only
/// care about the size here).
fn packed_size(names: Vec<Vec<u8>>) -> usize {
    let set: BTreeSet<Vec<u8>> = names.into_iter().collect();
    let mut unique: Vec<Vec<u8>> = set.into_iter().collect();
    unique.retain(|s| !s.is_empty());
    unique.par_sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));

    let mut size: usize = 1; // leading NUL
    for i in 0..unique.len() {
        let absorbed = i + 1 < unique.len() && unique[i + 1].ends_with(&unique[i]);
        if !absorbed {
            size += unique[i].len() + 1;
        }
    }
    size
}

fn extract_strtab_strings(bytes: &[u8]) -> Vec<Vec<u8>> {
    // strtab is a concat of NUL-terminated strings. First byte is
    // the leading NUL (offset 0 = empty string).
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_vec())
        .collect()
}

fn report(name: &str, section_bytes: &[u8]) {
    let naive = section_bytes.len();
    let strings = extract_strtab_strings(section_bytes);
    let count = strings.len();
    let unique: BTreeSet<&Vec<u8>> = strings.iter().collect();
    let unique_count = unique.len();
    let packed = packed_size(strings);
    let saved = naive.saturating_sub(packed);
    let pct = if naive == 0 {
        0.0
    } else {
        100.0 * saved as f64 / naive as f64
    };
    println!(
        "  {:>12}: {:>10} bytes, {:>7} strings ({:>7} unique), packed = {:>10} bytes, saved = {:>10} bytes ({:>5.2} %)",
        name, naive, count, unique_count, packed, saved, pct
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <path/to/elf> [more ELFs...]", args[0]);
        return ExitCode::from(1);
    }

    for path in &args[1..] {
        println!("\n== {path}");
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  failed to read: {e}");
                continue;
            }
        };
        let obj = match object::File::parse(&*bytes) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("  not a recognised object: {e}");
                continue;
            }
        };
        // Section-level report (ELF / COFF).
        for section_name in [".strtab", ".dynstr", ".shstrtab"] {
            if let Some(section) = obj.section_by_name(section_name)
                && let Ok(data) = section.data()
            {
                report(section_name, data);
            }
        }

        // Symbol-derived report (format-agnostic; works for Mach-O too).
        // We synthesise a strtab-equivalent by concatenating each
        // symbol's NUL-terminated name, then packing.
        let mut symtab_bytes = vec![0u8]; // leading NUL
        let mut names_collected = Vec::new();
        for sym in obj.symbols() {
            if let Ok(name) = sym.name_bytes()
                && !name.is_empty()
            {
                names_collected.push(name.to_vec());
                symtab_bytes.extend_from_slice(name);
                symtab_bytes.push(0);
            }
        }
        if !names_collected.is_empty() {
            report("symtab (synthesised)", &symtab_bytes);
        }

        let mut dynsym_bytes = vec![0u8];
        let mut dyn_collected = Vec::new();
        for sym in obj.dynamic_symbols() {
            if let Ok(name) = sym.name_bytes()
                && !name.is_empty()
            {
                dyn_collected.push(name.to_vec());
                dynsym_bytes.extend_from_slice(name);
                dynsym_bytes.push(0);
            }
        }
        if !dyn_collected.is_empty() {
            report("dynsym (synthesised)", &dynsym_bytes);
        }
    }
    ExitCode::SUCCESS
}
