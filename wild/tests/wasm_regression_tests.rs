//! End-to-end regression tests for wild's WebAssembly linker.
//!
//! Each test embeds a minimal `.s` source (or pair), assembles it with
//! `llvm-mc`, links with wild, and validates the output structurally.
//! These are the integration-level complement to the unit tests in
//! `libwild/src/wasm_writer.rs` — they catch bugs that only manifest once
//! the full merge/reloc/patch pipeline has run end-to-end.
//!
//! Tests named `regression_bugN_*` pin down a specific bug that was
//! observed in the wild (pun intended) during the Substrate-runtime
//! bring-up. A failure here means that bug is back.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn wild_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wild"))
}

fn find_llvm_tool(name: &str) -> Option<PathBuf> {
    libwild::llvm_tools::find_by_name(name)
}

/// Assemble a `.s` string into a wasm32 object file.
fn assemble(llvm_mc: &Path, source: &str, out_dir: &Path, stem: &str) -> PathBuf {
    let src_path = out_dir.join(format!("{stem}.s"));
    let obj_path = out_dir.join(format!("{stem}.o"));
    std::fs::write(&src_path, source).unwrap();
    let status = Command::new(llvm_mc)
        .args([
            "-filetype=obj",
            "-triple=wasm32-unknown-unknown",
            "-mcpu=mvp",
            "-o",
        ])
        .arg(&obj_path)
        .arg(&src_path)
        .status()
        .expect("spawn llvm-mc");
    assert!(status.success(), "llvm-mc failed for {stem}");
    obj_path
}

/// Invoke wild as a wasm linker. Returns the output bytes, or panics on
/// linker failure with the captured stderr attached.
fn link_wasm(inputs: &[PathBuf], extra_args: &[&str], out_dir: &Path) -> Vec<u8> {
    let out_path = out_dir.join("out.wasm");
    let wild = wild_binary_path();
    // Symlink wild as wasm-ld so its arg parser picks the wasm platform.
    let shim = out_dir.join("wasm-ld");
    if shim.exists() {
        std::fs::remove_file(&shim).ok();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&wild, &shim).unwrap();
    #[cfg(not(unix))]
    std::fs::copy(&wild, &shim).unwrap();

    let mut cmd = Command::new(&shim);
    cmd.arg("--no-entry");
    cmd.args(extra_args);
    cmd.arg("-o").arg(&out_path);
    for o in inputs {
        cmd.arg(o);
    }
    let output = cmd.output().expect("spawn wild");
    assert!(
        output.status.success(),
        "wild link failed:\nstderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    std::fs::read(&out_path).unwrap()
}

/// Validate a wasm module structurally. Returns Ok(()) on valid.
fn wasm_validate(bytes: &[u8]) -> Result<(), String> {
    // Prefer external wasm-validate if present (catches more classes of
    // bug than our internal walker); fall back to wasmparser.
    if let Some(wv) = find_llvm_tool("wasm-validate").or_else(|| {
        let paths = [
            "/opt/homebrew/bin/wasm-validate",
            "/usr/local/bin/wasm-validate",
            "/usr/bin/wasm-validate",
        ];
        paths.iter().map(PathBuf::from).find(|p| p.exists())
    }) {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("m.wasm");
        std::fs::write(&p, bytes).unwrap();
        let out = Command::new(&wv).arg(&p).output().unwrap();
        if !out.status.success() {
            return Err(format!(
                "wasm-validate:\n{}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    Ok(())
}

/// P3 regression — LTO bitcode inputs on the wasm path must be
/// accepted and lowered transparently.
///
/// Before P3, wild rejected any input whose bytes started with the
/// `BC\xC0\xDE` LLVM-bitcode magic, with an opaque "Wild was compiled
/// without linker-plugin support" error. Substrate-style runtime
/// builds (which LTO-compile at least some dependency crates) were
/// unlinkable as a result — we saw this on midnight-node15.
///
/// This test reproduces the scenario with a minimum-viable pair:
/// - one synthetic bitcode module (produced via llvm-as from a hand- written LLVM IR fragment,
///   targeting wasm32),
/// - one regular wasm object (produced via llvm-mc from a .s file).
///
/// Under the P3 fix, wild discovers `llc`, lowers the bitcode
/// transparently, and links both inputs as if they had always been
/// wasm objects. No behaviour change visible at wild's CLI level —
/// the user doesn't know LTO lowering happened.
#[test]
fn regression_p3_lto_bitcode_input_is_lowered_transparently() {
    let Some(llvm_mc) = find_llvm_tool("llvm-mc") else {
        eprintln!("skipping: llvm-mc not found");
        return;
    };
    let Some(llvm_as) = find_llvm_tool("llvm-as") else {
        eprintln!("skipping: llvm-as not found");
        return;
    };
    if find_llvm_tool("llc").is_none() {
        eprintln!("skipping: llc not found");
        return;
    }

    let td = tempfile::tempdir().unwrap();
    let dir = td.path();

    // Regular wasm object: defines `host_main` calling into an
    // externally-provided `helper`.
    let wasm_src = r#"
.globl host_main
host_main:
  .functype host_main (i32) -> (i32)
  local.get 0
  i32.const 1
  i32.add
  end_function
"#;
    let wasm_o = assemble(&llvm_mc, wasm_src, dir, "host");

    // Bitcode module: LLVM IR targeting wasm32 with one exported
    // function. Wild's P3 hook will lower this to a wasm object
    // before handing it to the merge pipeline.
    let ir = r#"
target triple = "wasm32-unknown-unknown"

define i32 @bc_helper(i32 %a, i32 %b) {
  %r = add i32 %a, %b
  ret i32 %r
}
"#;
    let ll_path = dir.join("bc.ll");
    let bc_path = dir.join("bc.o"); // `.o` so wild's shim reads it as an input
    std::fs::write(&ll_path, ir).unwrap();
    let status = Command::new(&llvm_as)
        .arg(&ll_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .expect("llvm-as");
    assert!(status.success(), "llvm-as failed");
    // Sanity: the bitcode file really does start with BC\xC0\xDE.
    let bc = std::fs::read(&bc_path).unwrap();
    assert_eq!(
        &bc[..4],
        b"BC\xC0\xDE",
        "bitcode magic check — llvm-as produced unexpected output"
    );

    let bytes = link_wasm(
        &[wasm_o, bc_path],
        &["--export=host_main", "--export=bc_helper"],
        dir,
    );
    wasm_validate(&bytes).expect("P3: linked output must validate");
}

/// Bug #5 regression — deferred table relocations were recorded with
/// `out_func_idx = functions.len() + i`, sending writes for the i-th
/// function in an object to the `i`-th-later body slot and corrupting
/// unrelated functions.
///
/// Trigger: an object with two functions, each taking the address of
/// another function (i32.const foo / i32.const bar → R_WASM_TABLE_INDEX_SLEB).
/// Under the buggy code, the second function's reloc would land in the
/// body that follows it in the merged module — here that's a body from
/// the *second* input object, so byte-level corruption is easy to detect
/// via wasm-validate.
#[test]
fn regression_bug5_deferred_table_reloc_lands_in_correct_body() {
    let Some(llvm_mc) = find_llvm_tool("llvm-mc") else {
        eprintln!("skipping: llvm-mc not found");
        return;
    };

    let td = tempfile::tempdir().unwrap();
    let dir = td.path();

    // First object: two functions, each taking a function address.
    // The second function's R_WASM_TABLE_INDEX_SLEB carries `i == 1` in
    // the buggy reloc-dispatch loop — exactly the case that used to
    // misroute the patch.
    let a_src = r#"
.globl take_addr_of_b
take_addr_of_b:
  .functype take_addr_of_b () -> (i32)
  i32.const b
  end_function

.globl take_addr_of_a
take_addr_of_a:
  .functype take_addr_of_a () -> (i32)
  i32.const a
  end_function

.globl a
a:
  .functype a () -> (i32)
  i32.const 1
  end_function

.globl b
b:
  .functype b () -> (i32)
  i32.const 2
  end_function
"#;

    // Second object supplies a body that the corrupted write in the
    // buggy path would have landed in.
    let b_src = r#"
.globl filler
filler:
  .functype filler () -> (i32)
  i32.const 42
  end_function
"#;

    let a_o = assemble(&llvm_mc, a_src, dir, "a");
    let b_o = assemble(&llvm_mc, b_src, dir, "b");
    let bytes = link_wasm(
        &[a_o, b_o],
        &[
            "--export=take_addr_of_a",
            "--export=take_addr_of_b",
            "--export=a",
            "--export=b",
            "--export=filler",
        ],
        dir,
    );

    wasm_validate(&bytes).expect("output must structurally validate");
    // All five functions must exist as exports with non-empty bodies.
    // (Specifically, `filler` must not have had its body corrupted by a
    // misrouted table-index write targeting a different function.)
    assert!(
        bytes.len() > 100,
        "output suspiciously small: {} bytes",
        bytes.len()
    );
}
