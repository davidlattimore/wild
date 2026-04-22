//! End-to-end integration test: rustc-driven Rust → wasm32-wasip2
//! linked by wild must produce a structurally-valid wasm module.
//!
//! This covers a gap in `lld_wasm_tests` / `wasm_regression_tests`:
//! those suites feed wild hand-written `.s` object files via
//! `llvm-mc`, which exercise specific relocation / section shapes
//! but *not* the rustc toolchain's own output shape (sysroot
//! `.rlib`s, `crt1-command.o`, the `--export __main_void` /
//! `--allow-undefined` / `--stack-first` flag set, `-flavor wasm`
//! invocation convention, etc.). Bugs that only manifest for the
//! rustc-driven link slip through.
//!
//! The test driver:
//!   1. Writes a trivial hello-world `main.rs` to a tempdir.
//!   2. Builds it with `cargo build --release --target
//!      wasm32-wasip2`, routing the link step through a capture
//!      shim that forwards to rust-lld's `wasm-ld` so cargo's own
//!      build succeeds but we also record the linker argv + input
//!      files.
//!   3. Replays the captured link with wild (invoked as
//!      `wasm-ld` via a symlink — wild's arg parser detects wasm
//!      mode from the filename) and validates the output with
//!      wasmparser.
//!
//! Marked `#[ignore]` by default because it needs an installed
//! `wasm32-wasip2` target and a rust-lld bundled with the
//! toolchain — both normal on dev machines, not guaranteed in
//! every CI matrix. Run explicitly with:
//!
//!     cargo test --test wasm_rustc_integration -- --ignored
//!
//! Once wild's rustc-driven wasm output is valid, flip the ignore
//! to `false` so the test gates every commit by default.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn wild_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wild"))
}

/// Locate a `wasm-ld` that rustc will happily accept as the
/// forwarded linker (i.e. rust-lld's wasm front-end, not a
/// standalone lld install). Prefer the active toolchain's
/// `rust-lld` under `<sysroot>/lib/rustlib/<host>/bin/gcc-ld/`.
fn find_rust_wasm_ld() -> Option<PathBuf> {
    let sysroot = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()?;
    if !sysroot.status.success() {
        return None;
    }
    let sysroot = String::from_utf8(sysroot.stdout).ok()?;
    let sysroot = sysroot.trim();
    // Search every host triple under rustlib/.
    let rustlib = Path::new(sysroot).join("lib").join("rustlib");
    for host in std::fs::read_dir(&rustlib).ok()?.flatten() {
        let candidate = host.path().join("bin").join("gcc-ld").join("wasm-ld");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Confirm the active toolchain has wasm32-wasip2 installed.
fn has_wasip2_target() -> bool {
    let out = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.lines().any(|l| l.trim() == "wasm32-wasip2")
        }
        _ => false,
    }
}

/// Fingerprint the bug we expect this test to eventually catch —
/// "type mismatch" complaints from wasmparser on wild's output.
/// When wild's fix lands the assertion becomes "no validation
/// errors at all".
///
/// As of 0339e36 wild produces an invalid wasm module from a
/// rustc-driven hello-world build. Two distinct sub-bugs surfaced:
///
/// 1. **Element-segment init expr** — fixed in 08f3d02. Wild was
///    emitting `global.get <__table_base>` even when __table_base
///    is a defined (synth) global; spec §3.4.5 requires the
///    referenced global to be imported. Static-PIC mode now folds
///    to `i32.const 1` directly.
///
/// 2. **Function-type / index desync** — STILL OPEN. Reproduces at
///    `-O0` (wilt off) on the simplest possible Rust input:
///    `fn main() { println!("hi"); }`. wasm-validate reports
///    "type mismatch in call, expected [i32, i32, i32, i32] but
///    got [i32]" at calls to functions whose name-section entry
///    matches a 2-arg signature but whose type-table entry says
///    4 args. So either wild's GC / type-compaction phase remaps
///    function indices without updating the per-function type
///    assignment, or vice versa. Investigation breadcrumb: look at
///    `wasm_writer::gc_functions` + `mark_used_types` — the
///    type_map computed there must stay consistent with the
///    function index space.
#[test]
#[ignore = "needs installed wasm32-wasip2 target + a bundled rust-lld"]
fn rustc_hello_produces_valid_wasm() {
    if !has_wasip2_target() {
        eprintln!("skipping: wasm32-wasip2 target not installed");
        return;
    }
    let Some(wasm_ld) = find_rust_wasm_ld() else {
        eprintln!("skipping: no rust-lld / wasm-ld found under the active rustc sysroot");
        return;
    };

    let td = tempfile::tempdir().expect("tempdir");
    let root = td.path();

    // 1. Write a tiny cargo project. Standalone `[workspace]` so we
    //    don't get dragged into wild's host workspace.
    std::fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
[package]
name = "hello-wasm-rustc"
version = "0.1.0"
edition = "2024"
[[bin]]
name = "hello-wasm-rustc"
path = "src/main.rs"
[profile.release]
panic = "abort"
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/main.rs"),
        r#"fn main() { println!("hi"); }
"#,
    )
    .unwrap();

    // 2. Build via cargo, capturing the link via our shim. Cargo's
    //    own build uses wasm-ld so it succeeds — we just record the
    //    argv + inputs for step 3.
    let capture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("benchmarks/wasm-savedirs/capture-link.sh");
    assert!(
        capture.exists(),
        "capture-link.sh not found at {} — did the repo move?",
        capture.display()
    );

    let save_dir = root.join("save");
    let target_dir = root.join("target");
    std::fs::create_dir_all(&save_dir).unwrap();

    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--quiet",
        ])
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("CARGO_TARGET_WASM32_WASIP2_LINKER", &capture)
        .env("WASM_LINK_REAL", &wasm_ld)
        .env("WASM_LINK_SAVE_DIR", &save_dir)
        // rustc emits the artefact as `hello_wasm_rustc-<hash>.wasm`
        // (Cargo turns `-` into `_` for the file name). Match the
        // underscore form so the capture script saves the right
        // invocation.
        .env("WASM_LINK_SAVE_FILTER", "hello_wasm_rustc")
        .status()
        .expect("spawn cargo");
    assert!(status.success(), "cargo build failed");

    let run_with = save_dir.join("run-with");
    assert!(
        run_with.exists(),
        "capture-link.sh didn't produce a run-with — was cargo's link captured?"
    );

    // 3. Replay the captured link with wild, via a `wasm-ld`
    //    symlink so wild's arg parser picks wasm mode from the
    //    invocation name. Our run-with template knows to skip the
    //    `--target wasm32` injection when the linker's basename is
    //    `wasm-ld`, so wild-as-wasm-ld behaves like wasm-ld here.
    let wild = wild_binary_path();
    let shim = root.join("wasm-ld");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&wild, &shim).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(&wild, &shim).unwrap();

    let wild_out = root.join("wild-out.wasm");
    let output = Command::new(&run_with)
        .arg(&shim)
        .env("OUT", &wild_out)
        .output()
        .expect("spawn run-with");
    assert!(
        output.status.success(),
        "wild link failed:\nstderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let bytes = std::fs::read(&wild_out).expect("read wild output");
    let mut validator = wasmparser::Validator::new();
    match validator.validate_all(&bytes) {
        Ok(_) => {} // Pass: wild's output is structurally valid.
        Err(e) => panic!(
            "wild produced a structurally-invalid wasm module from a rustc-driven \
             Rust → wasm32-wasip2 build (fn main() {{ println!(\"hi\"); }}):\n\
             {e}\n\
             \n\
             Reminder: `lld_wasm_tests` fixtures are hand-written `.s` files and \
             don't exercise the rustc toolchain output shape. This test gates \
             that gap. See `benchmarks/wasm.toml::bench.wasm-rust-medium` comment \
             for the fuller story."
        ),
    }
}
