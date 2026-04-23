//! Estimates the size delta from converting `.debug_line` v4 → v5
//! at link time, with cross-CU path deduplication via a shared
//! `.debug_line_str` pool.
//!
//! For every CU's line program in the input ELF:
//!   1. Read v4 header (include_directories + file_names + opcodes).
//!   2. Compute the v5 header size assuming:
//!      * `directory_entry_format = (DW_LNCT_path, DW_FORM_line_strp)`
//!      * `file_name_entry_format = (DW_LNCT_path, DW_FORM_line_strp,
//!         DW_LNCT_directory_index, DW_FORM_udata)`
//!      * No mtime / length fields (rustc emits them as 0 anyway).
//!      * Each path becomes a 4-byte offset into a shared
//!        `.debug_line_str` pool.
//!   3. Aggregate all unique paths into the pool and measure.
//!
//! Reports per-section sizes and the projected delta. Does NOT
//! modify the binary — that's phase 2.

use gimli::EndianSlice;
use gimli::LittleEndian;
use object::Object;
use object::ObjectSection;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::ExitCode;

type Slice<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Default, Debug)]
struct Stats {
    cu_count: usize,
    debug_line_v4_total: u64,
    /// Estimated total when converted to v5 with shared
    /// `.debug_line_str` pool. Includes the `.debug_line_str` cost.
    debug_line_v5_estimate: u64,
    /// Estimated `.debug_line_str` size on its own (counted in
    /// the v5 estimate too, broken out for visibility).
    debug_line_str_estimate: u64,
    /// Sum of v4 header sizes (file/dir tables + fixed bytes).
    /// The opcodes themselves don't change between v4 and v5.
    v4_header_total: u64,
    v5_header_estimate: u64,
    /// Distinct path strings across all CUs after dedup.
    distinct_paths: usize,
    /// Total path string bytes before dedup (sum across all CUs).
    path_bytes_pre_dedup: u64,
    /// Total path string bytes after dedup.
    path_bytes_post_dedup: u64,
    /// Distinct CUs whose dir/file table is non-trivial (>0 entries).
    cus_with_files: usize,
}

fn analyse(elf_bytes: &[u8]) -> Result<Stats, String> {
    let obj = object::File::parse(elf_bytes).map_err(|e| format!("parse: {e}"))?;
    let mut stats = Stats::default();

    let load_section = |id: gimli::SectionId| -> Result<Slice<'_>, String> {
        let data = obj
            .section_by_name(id.name())
            .map(|s| s.data().unwrap_or(&[]))
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };

    let dwarf = gimli::Dwarf::load(load_section).map_err(|e| format!("dwarf load: {e}"))?;

    if let Some(s) = obj.section_by_name(".debug_line") {
        stats.debug_line_v4_total = s.size();
    }

    let mut path_pool: BTreeSet<Vec<u8>> = BTreeSet::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| format!("units: {e}"))? {
        stats.cu_count += 1;
        let unit = dwarf
            .unit(header)
            .map_err(|e| format!("unit @ {:?}: {e}", header.offset()))?;
        let Some(line_program) = unit.line_program else {
            continue;
        };
        let lp_header = line_program.header();
        // For DWARF 4 (which rustc emits), units are always 32-bit
        // format → unit_length is the 4-byte field's value, plus 4
        // bytes for the length field itself.
        let unit_total = lp_header.unit_length() as u64 + 4;
        // Header length in line-program v4 = bytes from end of the
        // header_length field to start of the opcode program. The
        // total prologue (everything before the program) is
        // unit_length(4) + version(2) + header_length(4) + that
        // many bytes.
        let prologue_len = 4u64 + 2 + 4 + lp_header.header_length() as u64;
        let header_bytes = prologue_len;
        let _ = unit_total;
        stats.v4_header_total += header_bytes;

        // Paths in include_directories.
        let mut dir_count = 0usize;
        for dir in lp_header.include_directories() {
            let bytes = dir
                .string_value(&dwarf.debug_str)
                .ok_or_else(|| "dir string_value".to_string())?
                .slice()
                .to_vec();
            stats.path_bytes_pre_dedup += (bytes.len() + 1) as u64;
            path_pool.insert(bytes);
            dir_count += 1;
        }
        // Paths in file_names.
        let mut file_count = 0usize;
        for file in lp_header.file_names() {
            let bytes = file
                .path_name()
                .string_value(&dwarf.debug_str)
                .ok_or_else(|| "file string_value".to_string())?
                .slice()
                .to_vec();
            stats.path_bytes_pre_dedup += (bytes.len() + 1) as u64;
            path_pool.insert(bytes);
            file_count += 1;
        }
        if dir_count > 0 || file_count > 0 {
            stats.cus_with_files += 1;
        }

        // v5 header estimate:
        // Fixed bytes: unit_length(4) + version(2) + address_size(1)
        //              + segment_selector_size(1) + header_length(4)
        //              + minimum_instruction_length(1) + max_ops(1)
        //              + default_is_stmt(1) + line_base(1) + line_range(1)
        //              + opcode_base(1) + standard_opcode_lengths(opcode_base-1)
        //              ≈ 18 + 12 = 30 bytes.
        // directory_entry_format_count(1) + (DW_LNCT_path=1 + DW_FORM_line_strp=1) = 3 bytes.
        // directories_count (ULEB ≈ 1-2) + N × 4 bytes (line_strp offset).
        // file_name_entry_format_count(1) + 4 (path + dir_index pairs) = 5 bytes.
        // file_names_count (ULEB ≈ 1-3) + N × (4 + ULEB(dir_index ≈ 1)).
        let v5_header = 30u64
            + 3
            + 2 // dir count ULEB
            + (dir_count as u64) * 4
            + 5
            + 3 // file count ULEB
            + (file_count as u64) * 5;
        stats.v5_header_estimate += v5_header;
    }

    // Now compute the dedup'd .debug_line_str pool size.
    // Each entry is the path bytes + 1 NUL terminator.
    for path in &path_pool {
        stats.path_bytes_post_dedup += (path.len() + 1) as u64;
    }
    stats.distinct_paths = path_pool.len();
    stats.debug_line_str_estimate = stats.path_bytes_post_dedup;

    // Total v5 estimate = sum(per-CU v5 header) + program bytes (unchanged) + .debug_line_str.
    //
    // Program bytes = .debug_line v4 total - sum(v4 headers).
    let program_bytes = stats
        .debug_line_v4_total
        .saturating_sub(stats.v4_header_total);
    stats.debug_line_v5_estimate =
        stats.v5_header_estimate + program_bytes + stats.debug_line_str_estimate;

    Ok(stats)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <path/to/elf>", args[0]);
        return ExitCode::from(1);
    }
    let bytes = match fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read: {e}");
            return ExitCode::from(1);
        }
    };
    let stats = match analyse(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("analyse: {e}");
            return ExitCode::from(2);
        }
    };

    println!("== {}", args[1]);
    println!("  CUs (with line programs): {}", stats.cu_count);
    println!("  CUs with non-empty file tables: {}", stats.cus_with_files);
    println!("  distinct paths across all CUs: {}", stats.distinct_paths);
    println!();
    println!(
        "  .debug_line v4 total:           {} bytes",
        stats.debug_line_v4_total
    );
    println!(
        "  v4 header bytes (sum across CUs): {} ({:.1}%)",
        stats.v4_header_total,
        100.0 * stats.v4_header_total as f64 / stats.debug_line_v4_total.max(1) as f64
    );
    println!();
    println!(
        "  v5 header estimate (sum across CUs): {}",
        stats.v5_header_estimate
    );
    println!(
        "  .debug_line_str estimate (deduped pool): {}",
        stats.debug_line_str_estimate
    );
    println!(
        "  paths pre-dedup: {}, post-dedup: {} ({:.2}× compression)",
        stats.path_bytes_pre_dedup,
        stats.path_bytes_post_dedup,
        stats.path_bytes_pre_dedup as f64 / stats.path_bytes_post_dedup.max(1) as f64
    );
    println!();
    println!(
        "  v5 total estimate (program + headers + line_str): {} bytes",
        stats.debug_line_v5_estimate
    );
    let delta = stats.debug_line_v4_total as i64 - stats.debug_line_v5_estimate as i64;
    let pct = 100.0 * delta as f64 / stats.debug_line_v4_total.max(1) as f64;
    if delta > 0 {
        println!("  estimated saving: {} bytes ({:.2}%)", delta, pct);
    } else {
        println!("  estimated COST: {} bytes ({:.2}%)", -delta, -pct);
    }
    ExitCode::SUCCESS
}
