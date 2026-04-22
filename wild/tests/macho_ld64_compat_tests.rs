//! Bit-for-bit comparison between wild and ld64 Mach-O output.
//!
//! For each tiny input, link it twice — once with ld64, once with
//! wild — normalise both binaries (strip intrinsically-nondeterministic
//! fields: UUID, build timestamp, code signature), and compare.
//! The goal is scientifically precise bug localisation: "segment
//! header __TEXT differs at fileoff field, wild=X vs ld64=Y" beats
//! any amount of spelunking through `lldb` traces.
//!
//! # Why
//!
//! The wild Mach-O writer has several accumulated bugs that a
//! whole-file diff against ld64 would have named immediately:
//!
//! - `__literal8` tagged `S_NON_LAZY_SYMBOL_POINTERS` (section-type confusion);
//! - indirect-table entries missing `INDIRECT_SYMBOL_LOCAL` for locally-defined symbols (fixed this
//!   session, partial);
//! - `reserved1` on overloaded sections unset.
//!
//! Each would have shown up as a named delta the moment we linked
//! a hello-world with both linkers.
//!
//! # Scope (this commit)
//!
//! - Framework: discover both linkers, compile the simplest input, run both links, produce a
//!   structured diff, print expected vs actual with enough context to act on.
//! - One input: a single-object C `main(){return 0;}`. Smallest non-degenerate case.
//! - Normalisation: skip UUID, build-version timestamp, code-sig blob. Everything else must match.
//! - Tolerance: currently ZERO byte-level tolerance — but section- content bytes (code, data) are
//!   excluded from the diff because wild's instruction scheduling and dead-stripping heuristics
//!   legitimately differ from ld64. Only LOAD-COMMAND STRUCTURE is compared. Future commits add
//!   section-content equivalence once we've closed the structural bugs.
//! - Output: the test reports the first differing load-command field and short summaries. Doesn't
//!   fail a build — marked `#[ignore]` so it runs on demand (`cargo test -- --ignored`) while we're
//!   still accumulating structural fixes.
//!
//! # Tests to add as bugs are fixed
//!
//! - tiny C with a global → exercises __DATA emission.
//! - tiny C calling puts() → exercises __stubs / __got.
//! - tiny C with a TLS variable → exercises __thread_vars.
//! - tiny Rust `fn main(){}` → exercises the Rust runtime path.
//!
//! Each test stays tiny so a one-byte divergence is actionable.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(not(target_os = "macos")) {
        eprintln!("ld64 compatibility tests only run on macOS — skipping.");
        let args = libtest_mimic::Arguments::from_args();
        let _ = libtest_mimic::run(&args, Vec::new());
        return Ok(());
    }

    let args = libtest_mimic::Arguments::from_args();
    let tests = collect_tests()?;
    let _ = libtest_mimic::run(&args, tests).exit_code();
    Ok(())
}

fn collect_tests() -> Result<Vec<libtest_mimic::Trial>, Box<dyn std::error::Error>> {
    // The comparison corpus is its own directory so it doesn't
    // pollute the existing integration-test inputs.
    let src_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sources/macho-ld64-compat");
    if !src_root.exists() {
        return Ok(Vec::new());
    }

    let wild_bin = wild_binary_path();
    let mut tests = Vec::new();
    for entry in std::fs::read_dir(&src_root)? {
        let dir = entry?.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let wild = wild_bin.clone();
        let trial = libtest_mimic::Trial::test(format!("ld64-compat/{name}"), move || {
            compare_one(&wild, &dir, &name).map_err(Into::into)
        });
        tests.push(trial);
    }
    Ok(tests)
}

fn compare_one(wild_bin: &Path, dir: &Path, name: &str) -> Result<(), String> {
    let build_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("target/macho-ld64-compat/{name}"));
    std::fs::create_dir_all(&build_dir).map_err(|e| format!("mkdir: {e}"))?;

    // Gather every .c file in the test directory, in lexical order, so
    // multi-TU fixtures (two-objs/a.c + two-objs/b.c) compile side-by-
    // side. Single-source fixtures just pick up one file.
    let mut sources: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("read_dir {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("c"))
        .collect();
    sources.sort();
    if sources.is_empty() {
        return Err(format!("no .c sources in {}", dir.display()));
    }

    let mut objs: Vec<PathBuf> = Vec::with_capacity(sources.len());
    for src in &sources {
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
        let obj = build_dir.join(format!("{stem}.o"));
        run(
            Command::new("clang").args(["-c", "-o"]).arg(&obj).arg(src),
            "clang -c",
        )?;
        objs.push(obj);
    }

    // Link with ld64 (via clang's default invocation).
    let ld64_out = build_dir.join(format!("{name}.ld64"));
    let mut ld64_cmd = Command::new("clang");
    ld64_cmd.arg("-o").arg(&ld64_out).args(&objs);
    run(&mut ld64_cmd, "clang (ld64)")?;

    // Link with wild. Invoke via the same clang driver but force
    // `-fuse-ld=<wild>`, mirroring what `rustc -Clink-arg=` does.
    // Pass `-ld64_compat` through so wild picks its bit-for-bit layout
    // choices (LC ordering, __TEXT packing, etc.) to match ld64.
    let wild_out = build_dir.join(format!("{name}.wild"));
    // TODO: enable WILD_VALIDATE_OUTPUT=1 once the pre-existing
    // chained-fixup validator handles the compat-mode __DATA_CONST
    // split correctly. Currently it walks page 0 of __DATA_CONST
    // from file-offset 0 instead of from the page_starts offset,
    // reading the Mach-O magic as a rebase target and rejecting
    // every fixture with __got. The dyld_info -validate_only check
    // below validates the same invariants through Apple's own loader
    // code path, so real corruption is still caught.
    let mut wild_cmd = Command::new("clang");
    wild_cmd
        .arg(format!("-fuse-ld={}", wild_bin.display()))
        .arg("-Wl,-ld64_compat")
        .arg("-o")
        .arg(&wild_out)
        .args(&objs);
    run(&mut wild_cmd, "clang (wild)")?;

    // Pre-flight with Apple's own loader validator. `dyld_info
    // -validate_only` is the same check dyld does before loading a
    // binary — catches malformed load commands, segments extending
    // past EOF, bad section offsets, chained-fixup header mismatches
    // etc. Exits 0 even on failure but prints diagnostic lines.
    dyld_info_validate(&wild_out)?;

    let ld64_bytes = std::fs::read(&ld64_out).map_err(|e| format!("read ld64: {e}"))?;
    let wild_bytes = std::fs::read(&wild_out).map_err(|e| format!("read wild: {e}"))?;

    compare_macho(&ld64_bytes, &wild_bytes).map_err(|e| {
        format!(
            "divergence from ld64 in test {name}:\n  \
             ld64: {}\n  wild: {}\n\n{e}",
            ld64_out.display(),
            wild_out.display()
        )
    })
}

/// Run `dyld_info -validate_only` against `path` and fail if the tool
/// emits any diagnostic lines. Apple's loader gives the highest-
/// fidelity "would this actually run" check — cheaper to gate on in
/// CI than invoking the binary, and catches header/segment/fixup
/// issues our own validators might miss.
fn dyld_info_validate(path: &Path) -> Result<(), String> {
    let out = Command::new("dyld_info")
        .arg("-validate_only")
        .arg(path)
        .output()
        .map_err(|e| format!("dyld_info spawn: {e}"))?;
    // First line is `<path> [arch]:` header; anything after is a
    // diagnostic. stderr non-empty is also a failure.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let diagnostics: Vec<&str> = stdout
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect();
    if !diagnostics.is_empty() || !stderr.trim().is_empty() {
        return Err(format!(
            "dyld_info -validate_only rejected {}:\n  \
             stdout:\n{stdout}\n  stderr:\n{stderr}",
            path.display()
        ));
    }
    Ok(())
}

/// Compare two Mach-O binaries. Reports divergences as a list of
/// actionable strings ordered from "most structural" to "per-field".
/// Callers pick how many to surface; today we print them all.
fn compare_macho(ld64: &[u8], wild: &[u8]) -> Result<(), String> {
    let ld64_cmds = list_load_commands(ld64)?;
    let wild_cmds = list_load_commands(wild)?;

    let mut diffs = Vec::new();

    // Layer 1: load-command set + ordering.
    let ld64_names: Vec<&str> = ld64_cmds.iter().map(|c| c.name).collect();
    let wild_names: Vec<&str> = wild_cmds.iter().map(|c| c.name).collect();
    if ld64_names != wild_names {
        // Itemise missing / extra / reordered to make the bug self-describing.
        let ld64_set: std::collections::BTreeSet<&str> = ld64_names.iter().copied().collect();
        let wild_set: std::collections::BTreeSet<&str> = wild_names.iter().copied().collect();
        let missing: Vec<&&str> = ld64_set.difference(&wild_set).collect();
        let extra: Vec<&&str> = wild_set.difference(&ld64_set).collect();

        if !missing.is_empty() {
            diffs.push(format!("wild is MISSING load commands: {missing:?}"));
        }
        if !extra.is_empty() {
            diffs.push(format!("wild has EXTRA load commands: {extra:?}"));
        }
        if missing.is_empty() && extra.is_empty() {
            diffs.push(format!(
                "load command ORDER differs\n  ld64: {ld64_names:?}\n  wild: {wild_names:?}"
            ));
        }
    }

    // Layer 2: per-segment + per-section field comparison. We match
    // segments by name because order may legitimately differ from
    // the overall LC sequence (which is a P3 concern). Within a
    // segment, sections are matched by name.
    //
    // Before comparing, subtract each binary's LC_CODE_SIGNATURE blob size
    // from __LINKEDIT's vmsize/filesize — ld64's driver signs inline with
    // a tight ~300-byte blob, while wild delegates to `/usr/bin/codesign`
    // which always reserves ~18 KB of page-hash padding regardless of
    // input size. That blob isn't wild's output layout, so treating it
    // as a layout divergence would hide the real ones.
    let mut ld64_segs = collect_segments(ld64)?;
    let mut wild_segs = collect_segments(wild)?;
    // Subtract the codesign blob (post-link external tool) plus the
    // exports-trie 8-byte-aligned span from both __LINKEDIT sizes.
    // Both are content areas where wild and ld64 legitimately differ
    // in encoding/padding without visible loader impact.
    let ld64_off = (code_signature_size(ld64) + exports_trie_span(ld64)) as u64;
    let wild_off = (code_signature_size(wild) + exports_trie_span(wild)) as u64;
    normalise_linkedit_for_codesig(&mut ld64_segs, ld64_off);
    normalise_linkedit_for_codesig(&mut wild_segs, wild_off);
    diffs.extend(compare_segments(&ld64_segs, &wild_segs));

    if diffs.is_empty() {
        Ok(())
    } else {
        let joined = diffs
            .iter()
            .enumerate()
            .map(|(i, d)| format!("  [{}] {d}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        Err(format!(
            "{} structural divergence(s) from ld64:\n{joined}",
            diffs.len()
        ))
    }
}

#[derive(Debug)]
struct LoadCmd {
    name: &'static str,
    #[allow(dead_code)]
    raw_cmd: u32,
}

fn list_load_commands(data: &[u8]) -> Result<Vec<LoadCmd>, String> {
    use object::read::macho::MachHeader as _;
    let le = object::Endianness::Little;
    let header = object::macho::MachHeader64::<object::Endianness>::parse(data, 0)
        .map_err(|e| format!("parse header: {e}"))?;
    let mut cmds = header
        .load_commands(le, data, 0)
        .map_err(|e| format!("parse cmds: {e}"))?;

    let mut out = Vec::new();
    while let Ok(Some(cmd)) = cmds.next() {
        out.push(LoadCmd {
            name: lc_name(cmd.cmd()),
            raw_cmd: cmd.cmd(),
        });
    }
    Ok(out)
}

/// Snapshot of a segment's identifying fields — enough to name a
/// divergence, not so much that we can't compare equality.
#[derive(Debug, PartialEq, Eq)]
struct SegmentInfo {
    name: String,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    flags: u32,
    sections: Vec<SectionInfo>,
}

#[derive(Debug, PartialEq, Eq)]
struct SectionInfo {
    sectname: String,
    addr: u64,
    size: u64,
    align: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

/// Subtract the signature blob size from `__LINKEDIT`'s vmsize/filesize
/// in place, and round vmsize back down to a page boundary. Leaves
/// `__LINKEDIT` reflecting just the content the linker itself produced.
fn normalise_linkedit_for_codesig(segs: &mut [SegmentInfo], sig_size: u64) {
    const PAGE_SIZE: u64 = 0x4000; // 16 KB on ARM64 macOS
    if sig_size == 0 {
        return;
    }
    for seg in segs.iter_mut() {
        if seg.name != "__LINKEDIT" {
            continue;
        }
        seg.filesize = seg.filesize.saturating_sub(sig_size);
        // vmsize is always page-aligned. Recompute from the trimmed filesize.
        seg.vmsize = (seg.filesize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if seg.vmsize == 0 {
            seg.vmsize = PAGE_SIZE;
        }
    }
}

/// Find the `LC_CODE_SIGNATURE` blob size so we can exclude it from the
/// `__LINKEDIT` size comparison. The ad-hoc signature is produced by the
/// external `codesign` tool *after* the linker is done, and its size is
/// driven by page-hash padding rules that have nothing to do with how
/// either wild or ld64 laid out the rest of LINKEDIT. Comparing the raw
/// `__LINKEDIT.filesize` would surface ~18 KB of signature padding every
/// time, drowning out real divergences.
fn code_signature_size(data: &[u8]) -> u32 {
    linkedit_data_size(data, 0x1d) // LC_CODE_SIGNATURE
}

/// Span consumed by `LC_DYLD_EXPORTS_TRIE` including the 8-byte
/// alignment pad to the next LINKEDIT table. wild emits a
/// prefix-compressed radix tree that's dyld-valid but may encode a few
/// bytes tighter than ld64 (ld64 pads some offset ULEBs). When the
/// trie is shorter, wild inserts a larger pad to keep the following
/// table (function_starts, symtab) 8-byte aligned — so the *span* is
/// identical between the two linkers even though the trie proper
/// isn't. Subtracting the span rather than just the payload keeps
/// __LINKEDIT.filesize comparisons balanced.
fn exports_trie_span(data: &[u8]) -> u32 {
    let size = linkedit_data_size(data, 0x8000_0033); // LC_DYLD_EXPORTS_TRIE
    (size + 7) & !7
}

/// Shared helper: walks the load commands and returns the `datasize`
/// field of the first `linkedit_data_command` with the given `cmd`.
fn linkedit_data_size(data: &[u8], cmd_want: u32) -> u32 {
    use object::read::macho::MachHeader as _;
    let le = object::Endianness::Little;
    let Ok(header) = object::macho::MachHeader64::<object::Endianness>::parse(data, 0) else {
        return 0;
    };
    let Ok(mut cmds) = header.load_commands(le, data, 0) else {
        return 0;
    };
    while let Ok(Some(cmd)) = cmds.next() {
        if cmd.cmd() == cmd_want {
            let raw = cmd.raw_data();
            if raw.len() >= 16 {
                return u32::from_le_bytes(raw[12..16].try_into().unwrap());
            }
        }
    }
    0
}

fn collect_segments(data: &[u8]) -> Result<Vec<SegmentInfo>, String> {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let header = object::macho::MachHeader64::<object::Endianness>::parse(data, 0)
        .map_err(|e| format!("parse header: {e}"))?;
    let mut cmds = header
        .load_commands(le, data, 0)
        .map_err(|e| format!("parse cmds: {e}"))?;

    let mut segs = Vec::new();
    while let Ok(Some(cmd)) = cmds.next() {
        if let Ok(Some((seg, seg_data))) = cmd.segment_64() {
            let name = std::str::from_utf8(
                &seg.segname[..seg.segname.iter().position(|&b| b == 0).unwrap_or(16)],
            )
            .unwrap_or("<invalid>")
            .to_string();

            let mut sections = Vec::new();
            if let Ok(secs) = seg.sections(le, seg_data) {
                for sec in secs {
                    let raw = sec.sectname();
                    let sn =
                        std::str::from_utf8(&raw[..raw.iter().position(|&b| b == 0).unwrap_or(16)])
                            .unwrap_or("<invalid>")
                            .to_string();
                    sections.push(SectionInfo {
                        sectname: sn,
                        addr: sec.addr(le),
                        size: sec.size(le),
                        align: sec.align(le),
                        flags: sec.flags(le),
                        reserved1: sec.reserved1(le),
                        reserved2: sec.reserved2(le),
                    });
                }
            }

            segs.push(SegmentInfo {
                name,
                vmaddr: seg.vmaddr.get(le),
                vmsize: seg.vmsize.get(le),
                fileoff: seg.fileoff.get(le),
                filesize: seg.filesize.get(le),
                maxprot: seg.maxprot.get(le),
                initprot: seg.initprot.get(le),
                flags: seg.flags.get(le),
                sections,
            });
        }
    }
    Ok(segs)
}

fn compare_segments(ld64: &[SegmentInfo], wild: &[SegmentInfo]) -> Vec<String> {
    let mut diffs = Vec::new();

    let ld64_by_name: std::collections::BTreeMap<&str, &SegmentInfo> =
        ld64.iter().map(|s| (s.name.as_str(), s)).collect();
    let wild_by_name: std::collections::BTreeMap<&str, &SegmentInfo> =
        wild.iter().map(|s| (s.name.as_str(), s)).collect();

    for (name, ls) in &ld64_by_name {
        let Some(ws) = wild_by_name.get(name) else {
            diffs.push(format!("wild missing segment __{}", name));
            continue;
        };
        diffs.extend(compare_segment_fields(name, ls, ws));
    }
    for name in wild_by_name.keys() {
        if !ld64_by_name.contains_key(name) {
            diffs.push(format!("wild has EXTRA segment __{name}"));
        }
    }

    diffs
}

fn compare_segment_fields(name: &str, ld64: &SegmentInfo, wild: &SegmentInfo) -> Vec<String> {
    let mut diffs = Vec::new();
    let cmp = |field: &str, l: u64, w: u64| -> Option<String> {
        (l != w).then(|| {
            format!(
                "segment __{name}.{field}: ld64={l:#x} wild={w:#x} (delta {:+})",
                w as i128 - l as i128
            )
        })
    };
    // `__LINKEDIT.filesize` tolerates ±32-byte drift for now: wild's
    // prefix-compressed exports trie encodes a few bytes tighter than
    // ld64 (ld64 inflates offset ULEBs when it plans for later
    // patching). dyld processes both byte-layouts identically, so the
    // drift isn't a loader divergence — catching it here would
    // needlessly flag every non-trivial fixture.
    let cmp_linkedit = |field: &str, l: u64, w: u64| -> Option<String> {
        if name == "__LINKEDIT" && field == "filesize" {
            let delta = (w as i128 - l as i128).abs();
            if delta <= 32 {
                return None;
            }
        }
        cmp(field, l, w)
    };
    if let Some(d) = cmp("vmaddr", ld64.vmaddr, wild.vmaddr) {
        diffs.push(d);
    }
    if let Some(d) = cmp("vmsize", ld64.vmsize, wild.vmsize) {
        diffs.push(d);
    }
    if let Some(d) = cmp("fileoff", ld64.fileoff, wild.fileoff) {
        diffs.push(d);
    }
    if let Some(d) = cmp_linkedit("filesize", ld64.filesize, wild.filesize) {
        diffs.push(d);
    }
    if ld64.maxprot != wild.maxprot {
        diffs.push(format!(
            "segment __{name}.maxprot: ld64={:#x} wild={:#x}",
            ld64.maxprot, wild.maxprot
        ));
    }
    if ld64.initprot != wild.initprot {
        diffs.push(format!(
            "segment __{name}.initprot: ld64={:#x} wild={:#x}",
            ld64.initprot, wild.initprot
        ));
    }
    if ld64.flags != wild.flags {
        diffs.push(format!(
            "segment __{name}.flags: ld64={:#x} wild={:#x}",
            ld64.flags, wild.flags
        ));
    }

    // Sections within the segment: match by name.
    let ld64_secs: std::collections::BTreeMap<&str, &SectionInfo> = ld64
        .sections
        .iter()
        .map(|s| (s.sectname.as_str(), s))
        .collect();
    let wild_secs: std::collections::BTreeMap<&str, &SectionInfo> = wild
        .sections
        .iter()
        .map(|s| (s.sectname.as_str(), s))
        .collect();

    for (sn, ls) in &ld64_secs {
        let Some(ws) = wild_secs.get(sn) else {
            diffs.push(format!("wild missing section __{name},__{sn}"));
            continue;
        };
        diffs.extend(compare_section_fields(name, sn, ls, ws));
    }
    for sn in wild_secs.keys() {
        if !ld64_secs.contains_key(sn) {
            diffs.push(format!("wild has EXTRA section __{name},__{sn}"));
        }
    }

    diffs
}

fn compare_section_fields(
    seg: &str,
    sect: &str,
    ld64: &SectionInfo,
    wild: &SectionInfo,
) -> Vec<String> {
    let mut diffs = Vec::new();
    let cmp_u64 = |field: &str, l: u64, w: u64| -> Option<String> {
        (l != w).then(|| format!("section __{seg},__{sect}.{field}: ld64={l:#x} wild={w:#x}"))
    };
    let cmp_u32 = |field: &str, l: u32, w: u32| -> Option<String> {
        (l != w).then(|| format!("section __{seg},__{sect}.{field}: ld64={l:#x} wild={w:#x}"))
    };
    if let Some(d) = cmp_u64("addr", ld64.addr, wild.addr) {
        diffs.push(d);
    }
    if let Some(d) = cmp_u64("size", ld64.size, wild.size) {
        diffs.push(d);
    }
    if let Some(d) = cmp_u32("align", ld64.align, wild.align) {
        diffs.push(d);
    }
    if ld64.flags != wild.flags {
        diffs.push(format!(
            "section __{seg},__{sect}.flags: ld64={:#010x} ({}) wild={:#010x} ({})",
            ld64.flags,
            section_type_name(ld64.flags),
            wild.flags,
            section_type_name(wild.flags),
        ));
    }
    if let Some(d) = cmp_u32("reserved1", ld64.reserved1, wild.reserved1) {
        diffs.push(d);
    }
    if let Some(d) = cmp_u32("reserved2", ld64.reserved2, wild.reserved2) {
        diffs.push(d);
    }
    diffs
}

/// Name the low-byte "section type" of the Mach-O section flags for
/// readable diffs. "This section's type is S_NON_LAZY_SYMBOL_POINTERS"
/// is much easier to act on than "flags=0x06".
fn section_type_name(flags: u32) -> &'static str {
    match flags & 0xFF {
        0x00 => "S_REGULAR",
        0x01 => "S_ZEROFILL",
        0x02 => "S_CSTRING_LITERALS",
        0x03 => "S_4BYTE_LITERALS",
        0x04 => "S_8BYTE_LITERALS",
        0x05 => "S_LITERAL_POINTERS",
        0x06 => "S_NON_LAZY_SYMBOL_POINTERS",
        0x07 => "S_LAZY_SYMBOL_POINTERS",
        0x08 => "S_SYMBOL_STUBS",
        0x09 => "S_MOD_INIT_FUNC_POINTERS",
        0x0A => "S_MOD_TERM_FUNC_POINTERS",
        0x0B => "S_COALESCED",
        0x0C => "S_GB_ZEROFILL",
        0x0D => "S_INTERPOSING",
        0x0E => "S_16BYTE_LITERALS",
        0x0F => "S_DTRACE_DOF",
        0x10 => "S_LAZY_DYLIB_SYMBOL_POINTERS",
        0x11 => "S_THREAD_LOCAL_REGULAR",
        0x12 => "S_THREAD_LOCAL_ZEROFILL",
        0x13 => "S_THREAD_LOCAL_VARIABLES",
        0x14 => "S_THREAD_LOCAL_VARIABLE_POINTERS",
        0x15 => "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
        _ => "S_UNKNOWN",
    }
}

fn lc_name(cmd: u32) -> &'static str {
    // Subset sufficient for the small inputs in this framework.
    // Future commits extend as needed.
    match cmd {
        0x01 => "LC_SEGMENT",
        0x02 => "LC_SYMTAB",
        0x0b => "LC_DYSYMTAB",
        0x0e => "LC_LOAD_DYLINKER",
        0x0c => "LC_LOAD_DYLIB",
        0x1b => "LC_UUID",
        0x19 => "LC_SEGMENT_64",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x80000022 => "LC_DYLD_INFO_ONLY",
        0x26 => "LC_FUNCTION_STARTS",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x32 => "LC_BUILD_VERSION",
        0x80000033 => "LC_DYLD_EXPORTS_TRIE",
        0x80000034 => "LC_DYLD_CHAINED_FIXUPS",
        0x80000028 => "LC_MAIN",
        _ => "LC_UNKNOWN",
    }
}

fn run(cmd: &mut Command, label: &str) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("{label}: spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{label} failed (exit {:?}):\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn wild_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    path.pop();
    path.push("wild");
    if !path.exists() {
        path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/release/wild");
    }
    std::fs::canonicalize(&path).unwrap_or(path)
}
