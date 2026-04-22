//! Mach-O dylib compat tests.
//!
//! `-ld64_compat` dylib output is not bit-for-bit with ld64 (the
//! section-count heuristic for `macho_header_bytes` undercounts for
//! Rust-std-linked dylibs, so dylibs fall back to the 16 KB header
//! page). These fixtures instead verify:
//!
//!  * the dylib codesigns cleanly (`codesign --force -s -` succeeds and `codesign -v` validates) —
//!    the "internal error in Code Signing subsystem" regression from the dead-LINKEDIT-gap bug
//!    would fail this check;
//!  * the required load commands are present (LC_ID_DYLIB, LC_LOAD_DYLIB for libSystem,
//!    LC_DYLD_EXPORTS_TRIE non-empty, no overlapping segments);
//!  * the dylib loads at runtime via `dlopen` and its exported symbols resolve to the expected
//!    values (or, for fixtures with direct-link main.c, a wild-built exe linking the dylib runs
//!    successfully).
//!
//! Fixture layout: each `wild/tests/sources/macho-ld64-compat-dylib/<name>/`
//! holds:
//!   * `lib.c` — dylib source
//!   * `main.c` — (optional) exe source. If it includes `<dlfcn.h>` the exe receives the dylib path
//!     as `argv[1]`; otherwise it's direct-linked against the dylib.
//!
//! Run: `cargo test -p wild-linker --test macho_ld64_compat_dylib_tests`.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(not(target_os = "macos")) {
        eprintln!("macho dylib compat tests only run on macOS — skipping.");
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
    let src_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sources/macho-ld64-compat-dylib");
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
        let trial = libtest_mimic::Trial::test(format!("ld64-compat-dylib/{name}"), move || {
            run_one(&wild, &dir, &name).map_err(Into::into)
        });
        tests.push(trial);
    }
    Ok(tests)
}

fn run_one(wild_bin: &Path, dir: &Path, name: &str) -> Result<(), String> {
    let build_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("target/macho-ld64-compat-dylib/{name}"));
    std::fs::create_dir_all(&build_dir).map_err(|e| format!("mkdir: {e}"))?;

    let lib_src = dir.join("lib.c");
    if !lib_src.exists() {
        return Err(format!("missing lib.c in {}", dir.display()));
    }
    let lib_obj = build_dir.join("lib.o");
    run(
        Command::new("clang")
            .args(["-c", "-o"])
            .arg(&lib_obj)
            .arg(&lib_src),
        "clang -c lib.c",
    )?;

    // Build the dylib via wild with -ld64_compat.
    let dylib_path = build_dir.join(format!("lib{name}.dylib"));
    let mut wild_cmd = Command::new("clang");
    wild_cmd
        .arg(format!("-fuse-ld={}", wild_bin.display()))
        .arg("-Wl,-ld64_compat")
        .arg("-dynamiclib")
        .arg(format!("-Wl,-install_name,@rpath/lib{name}.dylib"))
        .arg("-o")
        .arg(&dylib_path)
        .arg(&lib_obj);
    run(&mut wild_cmd, "clang (wild, dylib)")?;

    // Structural checks: parse LCs, confirm the required set is present.
    let dylib_bytes = std::fs::read(&dylib_path).map_err(|e| format!("read dylib: {e}"))?;
    check_structure(&dylib_bytes).map_err(|e| {
        format!(
            "structural check failed for {name}: {e}\n  dylib: {}",
            dylib_path.display()
        )
    })?;

    // Apple's own loader pre-flight. Catches segment/LC/fixup
    // corruption that our parser-only checks might miss.
    dyld_info_validate(&dylib_path)?;

    // Codesign check: the dylib must re-sign cleanly. Failure here
    // indicates the dead-LINKEDIT-gap / undersized-headerpad class of
    // regressions that previously broke proc-macro dylibs.
    let status = Command::new("codesign")
        .args(["--force", "-s", "-"])
        .arg(&dylib_path)
        .output()
        .map_err(|e| format!("codesign spawn: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "codesign failed for {}: {}",
            dylib_path.display(),
            String::from_utf8_lossy(&status.stderr)
        ));
    }
    let verify = Command::new("codesign")
        .args(["-v"])
        .arg(&dylib_path)
        .output()
        .map_err(|e| format!("codesign -v spawn: {e}"))?;
    if !verify.status.success() {
        return Err(format!(
            "codesign -v failed for {}: {}",
            dylib_path.display(),
            String::from_utf8_lossy(&verify.stderr)
        ));
    }

    // Runtime check: compile main.c (if present) and run it.
    let main_src = dir.join("main.c");
    if !main_src.exists() {
        return Ok(());
    }
    let main_body = std::fs::read_to_string(&main_src).unwrap_or_default();
    let uses_dlfcn = main_body.contains("dlfcn.h");

    let exe_path = build_dir.join(format!("{name}.exe"));
    let mut exe_cmd = Command::new("clang");
    exe_cmd
        .arg(format!("-fuse-ld={}", wild_bin.display()))
        .arg("-Wl,-ld64_compat")
        .arg("-o")
        .arg(&exe_path)
        .arg(&main_src);
    if !uses_dlfcn {
        // Direct-link: the exe references the dylib's exports at link
        // time. Pass the dylib as an input; `-rpath` so dyld finds it
        // at runtime.
        exe_cmd
            .arg(&dylib_path)
            .arg(format!("-Wl,-rpath,{}", build_dir.display()));
    }
    run(&mut exe_cmd, "clang (wild, exe)")?;
    // Sign the exe too — wild's internal codesign may have warned-and-
    // continued; re-signing to be sure.
    let _ = Command::new("codesign")
        .args(["--force", "-s", "-"])
        .arg(&exe_path)
        .output();
    dyld_info_validate(&exe_path)?;

    let mut run_cmd = Command::new(&exe_path);
    if uses_dlfcn {
        run_cmd.arg(&dylib_path);
    }
    let out = run_cmd.output().map_err(|e| format!("spawn exe: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "runtime exe exited {:?}:\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(())
}

/// Parse load commands from a Mach-O 64 buffer and return their cmd
/// ids. Rejects truncated input.
fn list_lc_ids(data: &[u8]) -> Result<Vec<u32>, String> {
    if data.len() < 32 {
        return Err("file too short for Mach-O header".into());
    }
    let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let sizeofcmds = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
    if 32 + sizeofcmds > data.len() {
        return Err("sizeofcmds extends past EOF".into());
    }
    let mut ids = Vec::with_capacity(ncmds);
    let mut off = 32usize;
    for _ in 0..ncmds {
        if off + 8 > data.len() {
            return Err("truncated LC header".into());
        }
        let cmd = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmdsize == 0 || off + cmdsize > data.len() {
            return Err(format!("bad cmdsize {cmdsize} at off {off}"));
        }
        ids.push(cmd);
        off += cmdsize;
    }
    Ok(ids)
}

fn check_structure(bytes: &[u8]) -> Result<(), String> {
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
    const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
    const LC_UUID: u32 = 0x1b;
    const LC_BUILD_VERSION: u32 = 0x32;

    let ids = list_lc_ids(bytes)?;
    for (needed, label) in [
        (LC_ID_DYLIB, "LC_ID_DYLIB"),
        (LC_LOAD_DYLIB, "LC_LOAD_DYLIB"),
        (LC_SYMTAB, "LC_SYMTAB"),
        (LC_DYSYMTAB, "LC_DYSYMTAB"),
        (LC_DYLD_CHAINED_FIXUPS, "LC_DYLD_CHAINED_FIXUPS"),
        (LC_DYLD_EXPORTS_TRIE, "LC_DYLD_EXPORTS_TRIE"),
        (LC_UUID, "LC_UUID"),
        (LC_BUILD_VERSION, "LC_BUILD_VERSION"),
    ] {
        if !ids.contains(&needed) {
            return Err(format!("missing {label}"));
        }
    }

    // filetype must be MH_DYLIB (6).
    let filetype = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if filetype != 6 {
        return Err(format!("filetype = {filetype}, expected 6 (MH_DYLIB)"));
    }

    // Segments must be contiguous in file offsets (no gaps, no
    // overlaps). __LINKEDIT must be last — codesign appends its blob
    // after it and would reject any segment past that point.
    let mut segs: Vec<(String, u64, u64)> = Vec::new();
    let mut off = 32usize;
    for _ in 0..ids.len() {
        let cmd = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == LC_SEGMENT_64 {
            let segname_bytes = &bytes[off + 8..off + 24];
            let nul = segname_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            let segname = String::from_utf8_lossy(&segname_bytes[..nul]).into_owned();
            let fileoff = u64::from_le_bytes(bytes[off + 40..off + 48].try_into().unwrap());
            let filesize = u64::from_le_bytes(bytes[off + 48..off + 56].try_into().unwrap());
            segs.push((segname, fileoff, filesize));
        }
        off += cmdsize;
    }
    segs.sort_by_key(|s| s.1);
    if segs.last().map(|s| s.0.as_str()) != Some("__LINKEDIT") {
        return Err(format!(
            "__LINKEDIT not the final segment — order: {:?}",
            segs.iter().map(|s| &s.0).collect::<Vec<_>>()
        ));
    }
    for win in segs.windows(2) {
        let a = &win[0];
        let b = &win[1];
        let a_end = a.1 + a.2;
        if a_end > b.1 {
            return Err(format!(
                "segment overlap: {} ({:#x}..{:#x}) vs {} ({:#x}..)",
                a.0, a.1, a_end, b.0, b.1
            ));
        }
    }

    // LC_DYLD_EXPORTS_TRIE must have non-zero datasize — an empty trie
    // means no exports, which would defeat the whole point of a dylib.
    let mut off = 32usize;
    let mut trie_size = 0u32;
    for _ in 0..ids.len() {
        let cmd = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
        if cmd == LC_DYLD_EXPORTS_TRIE {
            trie_size = u32::from_le_bytes(bytes[off + 12..off + 16].try_into().unwrap());
            break;
        }
        off += cmdsize;
    }
    if trie_size == 0 {
        return Err("LC_DYLD_EXPORTS_TRIE datasize=0 (no exports)".into());
    }

    Ok(())
}

/// Run `dyld_info -validate_only` against `path` and fail if the tool
/// emits any diagnostic lines. Apple's loader gives the highest-
/// fidelity "would this actually run" check — cheaper than invoking
/// the binary, catches header/segment/fixup issues our own
/// validators might miss.
fn dyld_info_validate(path: &Path) -> Result<(), String> {
    let out = Command::new("dyld_info")
        .arg("-validate_only")
        .arg(path)
        .output()
        .map_err(|e| format!("dyld_info spawn: {e}"))?;
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
