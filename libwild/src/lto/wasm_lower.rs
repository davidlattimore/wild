//! Wasm bitcode → wasm object lowering via subprocess `llc`.
//!
//! This is phase P3 of `wild-lto-plan.md`: the "L1 lower-only"
//! approach. No cross-module optimisation; each bitcode input becomes
//! its own wasm object and feeds wild's existing merge pipeline as if
//! it had always been a regular wasm `.o`.
//!
//! The companion [`WasmSubprocessDriver`] implements [`LtoDriver<Wasm>`]
//! for forward-compatibility with phases P4/P5, but input_data.rs
//! calls the free function [`lower_to_wasm_object`] directly on the
//! per-input hot path — P3 doesn't need the batch-then-compile flow
//! that the trait accommodates.

use crate::error::Error;
use crate::error::Result;
use crate::llvm_tools::Tool;
use crate::llvm_tools::find;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

/// Lower a single LLVM bitcode blob to a wasm32 object file.
///
/// Writes the bitcode to a tempfile, invokes `llc -march=wasm32
/// -filetype=obj -O0`, reads the result, and returns the bytes.
/// Optimisation stays at `-O0`: wilt is the optimiser for linked
/// wasm output; running llc at higher levels would duplicate
/// (or fight with) wilt's passes. The user's `-C opt-level`
/// intent was already captured in the bitcode rustc emitted.
///
/// Error cases:
/// - `llc` not found → rustc-style guidance pointing at `rustup component add llvm-tools-preview`.
/// - `llc` exits non-zero → its stderr is surfaced verbatim.
/// - filesystem trouble → wrapped with the attempted paths.
pub(crate) fn lower_to_wasm_object(bitcode: &[u8]) -> Result<Vec<u8>> {
    let llc = find(Tool::Llc).ok_or_else(|| {
        Error::with_message(
            "LTO bitcode input found but `llc` is not available. \
             Install it with `rustup component add llvm-tools-preview`, \
             or set $WILD_LLC to a specific path. \
             See wild-lto-plan.md for the full LTO pipeline design."
                .to_string(),
        )
    })?;

    // Use tempfile crate for automatic cleanup on drop.
    let tmp = tempfile::tempdir()
        .map_err(|e| Error::with_message(format!("tempdir for bitcode lowering: {e}")))?;
    let bc_path = tmp.path().join("input.bc");
    let obj_path = tmp.path().join("output.o");
    {
        let mut f = std::fs::File::create(&bc_path).map_err(|e| {
            Error::with_message(format!("write bitcode to {}: {e}", bc_path.display()))
        })?;
        f.write_all(bitcode).map_err(|e| {
            Error::with_message(format!("write bitcode to {}: {e}", bc_path.display()))
        })?;
    }

    let output = Command::new(&llc)
        .args(["-march=wasm32", "-filetype=obj", "-O0", "-o"])
        .arg(&obj_path)
        .arg(&bc_path)
        .output()
        .map_err(|e| Error::with_message(format!("failed to spawn `{}`: {e}", llc.display())))?;

    if !output.status.success() {
        return Err(Error::with_message(format!(
            "llc failed lowering bitcode (exit {:?}):\n\
             stderr:\n{}\n\
             stdout:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        )));
    }

    std::fs::read(&obj_path).map_err(|e| {
        Error::with_message(format!(
            "llc claimed success but {} is missing: {e}",
            obj_path.display()
        ))
    })
}

/// Write the lowered wasm object to a persistent path and return it.
/// Used by `input_data` to produce a file that can be mmap'd with the
/// lifetime that wild's input machinery expects. The returned path is
/// under `obj_cache_dir` so it survives the lowering call's stack
/// frame — the tempdir pattern used by `lower_to_wasm_object` would
/// drop the file before wild could mmap it.
pub(crate) fn lower_to_wasm_object_file(
    bitcode: &[u8],
    cache_dir: &std::path::Path,
    stem: &str,
) -> Result<PathBuf> {
    std::fs::create_dir_all(cache_dir).map_err(|e| {
        Error::with_message(format!(
            "create LTO object cache dir {}: {e}",
            cache_dir.display()
        ))
    })?;
    let bytes = lower_to_wasm_object(bitcode)?;
    let out = cache_dir.join(format!("{stem}.wasm32.o"));
    std::fs::write(&out, &bytes)
        .map_err(|e| Error::with_message(format!("write lowered object {}: {e}", out.display())))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip-if-not-available smoke test: if llc is installed, lower a
    /// tiny bitcode blob produced by llvm-as and check the output has
    /// the wasm magic.
    #[test]
    fn lowers_trivial_bitcode_when_tools_present() {
        let Some(llvm_as) = crate::llvm_tools::find_by_name("llvm-as") else {
            eprintln!("skipping: llvm-as not found");
            return;
        };
        if find(Tool::Llc).is_none() {
            eprintln!("skipping: llc not found");
            return;
        }

        // Tiny LLVM IR module with one exported function. llvm-as
        // converts to bitcode.
        let ir = r#"
target triple = "wasm32-unknown-unknown"

define i32 @add(i32 %a, i32 %b) {
  %r = add i32 %a, %b
  ret i32 %r
}
"#;
        let td = tempfile::tempdir().unwrap();
        let ll_path = td.path().join("t.ll");
        let bc_path = td.path().join("t.bc");
        std::fs::write(&ll_path, ir).unwrap();
        let status = Command::new(&llvm_as)
            .arg(&ll_path)
            .arg("-o")
            .arg(&bc_path)
            .status()
            .unwrap();
        assert!(status.success(), "llvm-as failed");

        let bitcode = std::fs::read(&bc_path).unwrap();
        let obj = lower_to_wasm_object(&bitcode).expect("lowering succeeds");
        assert!(
            obj.len() >= 8,
            "too-small lowered object: {} bytes",
            obj.len()
        );
        assert_eq!(&obj[..4], b"\0asm", "output must start with wasm magic");
    }

    #[test]
    fn missing_llc_gives_actionable_error() {
        // Force a bogus llc path and confirm the error message points
        // at the rustup component.
        // SAFETY: single-threaded test; env mutation is process-wide
        // but scoped by the test.
        unsafe {
            std::env::set_var("WILD_LLC", "/definitely/not/here/llc-not-installed");
        }
        let result = lower_to_wasm_object(&[0; 8]);
        unsafe {
            std::env::remove_var("WILD_LLC");
        }
        let err = result.expect_err("must fail when llc is missing");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("llvm-tools-preview") || msg.contains("$WILD_LLC"),
            "unexpected error (no actionable guidance): {msg}"
        );
    }
}
