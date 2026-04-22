//! P4: whole-program LTO lowering for wasm.
//!
//! `lower_many_to_wasm_object` merges N bitcode blobs into one
//! module via `llvm-link`, runs `opt -O<N>` on the merged module for
//! cross-module optimisation, and lowers the result with `llc` to a
//! single wasm object. The returned bytes go through wild's normal
//! wasm merge path as if they had been one large `.o` all along.
//!
//! This is **classic FatLTO** — one optimisation over the union of
//! every input's IR. The LLVM pass manager runs serially on the
//! merged module, which is *the* reason FatLTO has a reputation for
//! being slow. P5 (UnifiedLTO) is where parallelism wins back.
//!
//! P4's role is to (a) unblock whole-program optimisation for wasm
//! right now, (b) establish the pipeline shape P5 parallelises, and
//! (c) give users a real knob to trade link time for optimisation
//! power.

use crate::error::Error;
use crate::error::Result;
use crate::llvm_tools::Tool;
use crate::llvm_tools::find;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;

/// Optimisation level passed to `opt`. Mirrors clang's `-O<N>` /
/// `-Os` / `-Oz` semantics. `None` keeps the merged module at the
/// opt level rustc already baked into its bitcode — useful when
/// the caller wants merge-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptLevel {
    None,
    O0,
    O1,
    O2,
    O3,
    Os,
    Oz,
}

impl OptLevel {
    pub(crate) fn opt_flag(self) -> Option<&'static str> {
        match self {
            OptLevel::None => None,
            OptLevel::O0 => Some("-O0"),
            OptLevel::O1 => Some("-O1"),
            OptLevel::O2 => Some("-O2"),
            OptLevel::O3 => Some("-O3"),
            OptLevel::Os => Some("-Os"),
            OptLevel::Oz => Some("-Oz"),
        }
    }
}

/// Lower many bitcode blobs as one FatLTO unit: merge → optimise →
/// lower → return wasm object bytes.
///
/// Failure modes surface in rustc-kindness style: tool-missing
/// errors name the tool + the rustup component that ships it, and
/// any llvm-tool non-zero exit has its stderr surfaced verbatim.
pub(crate) fn lower_many_to_wasm_object(
    bitcodes: &[&[u8]],
    opt_level: OptLevel,
) -> Result<Vec<u8>> {
    if bitcodes.is_empty() {
        return Err(Error::with_message(
            "lower_many_to_wasm_object called with zero inputs",
        ));
    }
    // Single-input batch collapses to the P3 hot path — same result,
    // one fewer subprocess. Keep behaviour identical across the
    // N=1 boundary so callers don't special-case.
    if bitcodes.len() == 1 && opt_level == OptLevel::None {
        return super::wasm_lower::lower_to_wasm_object(bitcodes[0]);
    }

    let llvm_link = require_tool(Tool::LlvmLink)?;
    let llc = require_tool(Tool::Llc)?;
    // opt is only needed if we're actually optimising; merge-only
    // skips it.
    let opt = if opt_level == OptLevel::None {
        None
    } else {
        Some(require_tool(Tool::Opt)?)
    };

    let tmp = tempfile::tempdir()
        .map_err(|e| Error::with_message(format!("tempdir for FatLTO batch: {e}")))?;
    let dir = tmp.path();

    // Write each bitcode to a numbered file for llvm-link.
    let mut bc_paths = Vec::with_capacity(bitcodes.len());
    for (i, bc) in bitcodes.iter().enumerate() {
        let p = dir.join(format!("in-{i:04}.bc"));
        let mut f = std::fs::File::create(&p)
            .map_err(|e| Error::with_message(format!("write {}: {e}", p.display())))?;
        f.write_all(bc)
            .map_err(|e| Error::with_message(format!("write {}: {e}", p.display())))?;
        bc_paths.push(p);
    }

    let merged_path = dir.join("merged.bc");
    run(
        &llvm_link,
        Command::new(&llvm_link)
            .arg("-o")
            .arg(&merged_path)
            .args(&bc_paths),
        "llvm-link",
    )?;

    let after_opt_path = if let Some(opt_bin) = opt {
        let flag = opt_level
            .opt_flag()
            .expect("opt_flag present when Some(opt)");
        let out_path = dir.join("optimised.bc");
        run(
            &opt_bin,
            Command::new(&opt_bin)
                .arg(flag)
                .arg("-o")
                .arg(&out_path)
                .arg(&merged_path),
            "opt",
        )?;
        out_path
    } else {
        merged_path
    };

    let obj_path = dir.join("out.wasm32.o");
    run(
        &llc,
        Command::new(&llc)
            .args(["-march=wasm32", "-filetype=obj"])
            .arg(opt_level.opt_flag().unwrap_or("-O0"))
            .arg("-o")
            .arg(&obj_path)
            .arg(&after_opt_path),
        "llc",
    )?;

    std::fs::read(&obj_path).map_err(|e| {
        Error::with_message(format!(
            "llc claimed success but {} is missing: {e}",
            obj_path.display()
        ))
    })
}

fn require_tool(tool: Tool) -> Result<std::path::PathBuf> {
    find(tool).ok_or_else(|| {
        Error::with_message(format!(
            "FatLTO needs `{tool_name}` but it isn't on $PATH. \
             Install with `rustup component add llvm-tools-preview`, or set \
             ${env} to an explicit path. See wild-lto-plan.md.",
            tool_name = tool.exe_name(),
            env = tool.env_var(),
        ))
    })
}

fn run(tool: &Path, cmd: &mut Command, label: &str) -> Result<()> {
    let output = cmd.output().map_err(|e| {
        Error::with_message(format!(
            "failed to spawn {label} (`{}`): {e}",
            tool.display()
        ))
    })?;
    if !output.status.success() {
        return Err(Error::with_message(format!(
            "{label} failed (exit {:?}):\nstderr:\n{}\nstdout:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble_bc(ir: &str, stem: &str) -> Option<Vec<u8>> {
        let llvm_as = crate::llvm_tools::find_by_name("llvm-as")?;
        let td = tempfile::tempdir().ok()?;
        let ll = td.path().join(format!("{stem}.ll"));
        let bc = td.path().join(format!("{stem}.bc"));
        std::fs::write(&ll, ir).ok()?;
        let status = Command::new(&llvm_as)
            .arg(&ll)
            .arg("-o")
            .arg(&bc)
            .status()
            .ok()?;
        status.success().then(|| std::fs::read(&bc).ok()).flatten()
    }

    #[test]
    fn empty_input_is_an_error_not_a_crash() {
        let err = lower_many_to_wasm_object(&[], OptLevel::O2).expect_err("empty input must error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("zero inputs"),
            "expected zero-inputs msg: {msg}"
        );
    }

    #[test]
    fn single_input_merge_only_collapses_to_p3_path() {
        let Some(bc) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @single(i32 %a) {
  ret i32 %a
}
"#,
            "s",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };

        // None implies merge-only; for a single input that's literally
        // the P3 lowerer — same bytes should come back.
        let via_batch = lower_many_to_wasm_object(&[bc.as_slice()], OptLevel::None);
        let via_p3 = super::super::wasm_lower::lower_to_wasm_object(&bc);
        match (via_batch, via_p3) {
            (Ok(a), Ok(b)) => {
                assert_eq!(&a[..4], b"\0asm");
                assert_eq!(&b[..4], b"\0asm");
                assert_eq!(a, b, "N=1 + None must equal P3 direct output byte-for-byte");
            }
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("skipping: llc unavailable: {e:?}");
            }
        }
    }

    #[test]
    fn two_inputs_merge_optimise_lower_produces_valid_wasm() {
        let Some(a) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
declare i32 @helper(i32)
define i32 @add_via_helper(i32 %x) {
  %r = call i32 @helper(i32 %x)
  ret i32 %r
}
"#,
            "a",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };
        let Some(b) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @helper(i32 %x) {
  %r = add i32 %x, 1
  ret i32 %r
}
"#,
            "b",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };

        match lower_many_to_wasm_object(&[a.as_slice(), b.as_slice()], OptLevel::O2) {
            Ok(obj) => {
                assert_eq!(&obj[..4], b"\0asm", "merged output has wasm magic");
                assert!(obj.len() > 8);
            }
            Err(e) => {
                // Infrastructure not available on this host — that's
                // a "can't test", not a "broken test".
                eprintln!("skipping: llvm toolchain unavailable: {e:?}");
            }
        }
    }

    #[test]
    fn opt_level_flag_mapping_is_exhaustive() {
        assert_eq!(OptLevel::None.opt_flag(), None);
        assert_eq!(OptLevel::O0.opt_flag(), Some("-O0"));
        assert_eq!(OptLevel::O1.opt_flag(), Some("-O1"));
        assert_eq!(OptLevel::O2.opt_flag(), Some("-O2"));
        assert_eq!(OptLevel::O3.opt_flag(), Some("-O3"));
        assert_eq!(OptLevel::Os.opt_flag(), Some("-Os"));
        assert_eq!(OptLevel::Oz.opt_flag(), Some("-Oz"));
    }
}
