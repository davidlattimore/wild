//! Smoke tests for the `wilt` CLI binary — guards the wasm-opt-
//! compatible surface so future changes don't break drop-in usage.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    // Tests run from the wilt/ crate dir; the binary lives in the
    // workspace target/ (one level up).
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // .../wild
    p.push("target");
    // Honour CARGO_TARGET_DIR if set.
    if let Ok(d) = std::env::var("CARGO_TARGET_DIR") {
        p = PathBuf::from(d);
    }
    // Prefer release build if present, fall back to debug.
    let rel = p.join("release").join("wilt");
    let dbg = p.join("debug").join("wilt");
    if rel.exists() { rel } else { dbg }
}

fn build_tiny_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (func (export "f") (result i32)
            i32.const 0
            i32.const 0
            i32.add))
    "#,
    )
    .unwrap()
}

#[test]
fn cli_default_output_path() {
    let bin = bin();
    if !bin.exists() {
        eprintln!("skip: build `cargo build --bin wilt` first");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("wilt_cli_{}.wasm", std::process::id()));
    std::fs::write(&tmp, build_tiny_wasm()).unwrap();
    let status = Command::new(&bin).arg(&tmp).status().unwrap();
    assert!(status.success());
    let expected_out = tmp.with_file_name(format!(
        "{}.opt.wasm",
        tmp.file_stem().unwrap().to_str().unwrap()
    ));
    assert!(
        expected_out.exists(),
        "default output path {:?} not written",
        expected_out
    );
    std::fs::remove_file(&tmp).ok();
    std::fs::remove_file(&expected_out).ok();
}

#[test]
fn cli_accepts_wasm_opt_flags() {
    let bin = bin();
    if !bin.exists() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("wilt_cli_wo_{}.wasm", std::process::id()));
    let out = std::env::temp_dir().join(format!("wilt_cli_wo_out_{}.wasm", std::process::id()));
    std::fs::write(&tmp, build_tiny_wasm()).unwrap();
    // wasm-opt-style invocation wilt should accept silently.
    let status = Command::new(&bin)
        .arg("-O3")
        .arg(&tmp)
        .arg("-o")
        .arg(&out)
        .arg("--enable-bulk-memory")
        .arg("--enable-simd")
        .arg("--disable-gc")
        .arg("--strip-debug")
        .status()
        .unwrap();
    assert!(status.success(), "exit code = {status:?}");
    assert!(out.exists());
    std::fs::remove_file(&tmp).ok();
    std::fs::remove_file(&out).ok();
}

#[test]
fn cli_print_to_stdout() {
    let bin = bin();
    if !bin.exists() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("wilt_cli_print_{}.wasm", std::process::id()));
    std::fs::write(&tmp, build_tiny_wasm()).unwrap();
    let output = Command::new(&bin)
        .arg(&tmp)
        .arg("--print")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        output.stdout.starts_with(b"\0asm\x01\x00\x00\x00"),
        "stdout does not look like a wasm binary"
    );
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn cli_unknown_flag_exits_2() {
    let bin = bin();
    if !bin.exists() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("wilt_cli_bad_{}.wasm", std::process::id()));
    std::fs::write(&tmp, build_tiny_wasm()).unwrap();
    // `--no-*` / `--enable-*` / `--disable-*` / `--pass-*` are wasm-opt
    // shapes we silently accept. `--zzz-bogus` is truly unknown.
    let status = Command::new(&bin)
        .arg(&tmp)
        .arg("--zzz-bogus")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    std::fs::remove_file(&tmp).ok();
}

#[test]
fn cli_missing_input_exits_2() {
    let bin = bin();
    if !bin.exists() {
        return;
    }
    let status = Command::new(&bin).status().unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn cli_help_exits_0() {
    let bin = bin();
    if !bin.exists() {
        return;
    }
    let output = Command::new(&bin).arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("wasm-opt"));
}
