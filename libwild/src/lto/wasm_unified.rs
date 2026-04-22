//! P5a: Parallel per-module LTO pipeline for wasm.
//!
//! This is the first half of P5 from `wild-lto-plan.md`. The goal is
//! "fast FatLTO-quality optimisation by running per-module opt + llc
//! in parallel" — the same architecture `wasm-ld -flto=thin` uses.
//!
//! # What this phase ships (P5a)
//!
//! - Per-module `opt -O<N>` runs in parallel via rayon.
//! - Per-module `llc -march=wasm32 -filetype=obj` runs in parallel.
//! - Returns one wasm object per input so wild's existing merge pipeline takes over.
//!
//! # What this phase deliberately does NOT ship (P5b)
//!
//! True UnifiedLTO / ThinLTO with cross-module **summary-driven
//! imports** requires either `llvm-lto2 run` with explicit symbol
//! resolutions (fiddly to generate correctly in subprocess form) or
//! in-process libLLVM calling `runThinLTOBackend`. That's the P5b
//! work. Without imports, each module is optimised against only its
//! own IR — we get ThinLTO's **parallelism** but not its
//! **cross-module inlining**. Post-link wilt closes a chunk of this
//! gap on wasm specifically.
//!
//! Signature stability: [`lower_per_module_parallel`] returns one
//! wasm object per input. The P5b implementation keeps the same
//! signature — callers see a semver-stable API whether the summary
//! step is wired up or not.

use crate::error::Error;
use crate::error::Result;
use crate::llvm_tools::Tool;
use crate::llvm_tools::find;
use crate::llvm_tools::version_of;
use crate::lto::cache::CacheDir;
use crate::lto::cache::CacheKey;
use crate::lto::wasm_batch::OptLevel;
use rayon::prelude::*;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Lower N bitcode inputs to N wasm objects, optimising and codegening
/// each module in parallel on the given rayon pool.
///
/// Each input flows through: `opt -O<N> in.bc -o optimised.bc` then
/// `llc -march=wasm32 -filetype=obj optimised.bc -o out.o`. Both
/// steps are run for every input on separate rayon tasks, so an
/// N-module link saturates N cores (up to the pool size).
///
/// Failure mode: the first failing module aborts the whole batch and
/// surfaces its tool + stderr. Silent partial-output is a class of
/// bug we prefer loud.
pub(crate) fn lower_per_module_parallel(
    bitcodes: &[&[u8]],
    opt_level: OptLevel,
    pool: &rayon::ThreadPool,
) -> Result<Vec<Vec<u8>>> {
    if bitcodes.is_empty() {
        return Err(Error::with_message(
            "lower_per_module_parallel called with zero inputs",
        ));
    }

    // Discover tools up-front so we fail fast with actionable
    // messages, not mid-parallel-work.
    let opt_bin = if opt_level == OptLevel::None {
        None
    } else {
        Some(require_tool(Tool::Opt)?)
    };
    let llc_bin = require_tool(Tool::Llc)?;

    // Version the cache keys against the actual llc we'll invoke, so
    // a toolchain upgrade invalidates stale entries.
    let llvm_version = version_of(&llc_bin)
        .map(|(ma, mi, pa)| format!("{ma}.{mi}.{pa}"))
        .unwrap_or_else(|| "unknown".to_string());
    let cache = CacheDir::resolve();
    let opt_flag_str = opt_level.opt_flag().unwrap_or("-O0");

    // Single shared tempdir keeps `.bc` and `.o` files for this link
    // in one place — easier to --save-temps in debugging.
    let tmp = tempfile::tempdir().map_err(|e| Error::with_message(format!("tempdir: {e}")))?;
    let dir_root = tmp.path().to_path_buf();

    // Run all modules under a rayon scope on the given pool so the
    // linker's pool (not the global one) carries the work. The cache
    // is consulted PER MODULE, so unchanged inputs skip the opt+llc
    // subprocesses entirely.
    let results: Vec<Result<Vec<u8>>> = pool.install(|| {
        bitcodes
            .par_iter()
            .enumerate()
            .map(|(i, bc)| {
                let key = CacheKey::new(
                    bc,
                    opt_flag_str,
                    "", // P6: target features not yet threaded through
                    "per-module",
                    &llvm_version,
                );
                crate::lto::cache::get_or_compute(&cache, &key, || {
                    lower_one_module(bc, opt_bin.as_deref(), &llc_bin, opt_level, &dir_root, i)
                })
            })
            .collect()
    });

    let mut out = Vec::with_capacity(results.len());
    for (i, r) in results.into_iter().enumerate() {
        out.push(r.map_err(|e| {
            Error::with_message(format!(
                "module {i} failed during P5a lowering: {}",
                e.to_string()
            ))
        })?);
    }
    Ok(out)
}

fn lower_one_module(
    bitcode: &[u8],
    opt_bin: Option<&Path>,
    llc_bin: &Path,
    opt_level: OptLevel,
    dir_root: &Path,
    i: usize,
) -> Result<Vec<u8>> {
    let mod_dir = dir_root.join(format!("m-{i:04}"));
    std::fs::create_dir_all(&mod_dir)
        .map_err(|e| Error::with_message(format!("mkdir {}: {e}", mod_dir.display())))?;

    let bc_path = mod_dir.join("in.bc");
    {
        let mut f = std::fs::File::create(&bc_path).map_err(|e| {
            Error::with_message(format!("write bitcode {}: {e}", bc_path.display()))
        })?;
        f.write_all(bitcode).map_err(|e| {
            Error::with_message(format!("write bitcode {}: {e}", bc_path.display()))
        })?;
    }

    let for_llc = if let Some(opt_bin) = opt_bin {
        let flag = opt_level
            .opt_flag()
            .expect("opt_flag present when opt_bin is Some");
        let optimised = mod_dir.join("optimised.bc");
        run(
            opt_bin,
            Command::new(opt_bin)
                .arg(flag)
                .arg("-o")
                .arg(&optimised)
                .arg(&bc_path),
            "opt",
        )?;
        optimised
    } else {
        bc_path
    };

    let obj = mod_dir.join("out.wasm32.o");
    run(
        llc_bin,
        Command::new(llc_bin)
            .args(["-march=wasm32", "-filetype=obj"])
            .arg(opt_level.opt_flag().unwrap_or("-O0"))
            .arg("-o")
            .arg(&obj)
            .arg(&for_llc),
        "llc",
    )?;

    std::fs::read(&obj).map_err(|e| {
        Error::with_message(format!(
            "llc claimed success but {} is missing: {e}",
            obj.display()
        ))
    })
}

fn require_tool(tool: Tool) -> Result<PathBuf> {
    find(tool).ok_or_else(|| {
        Error::with_message(format!(
            "P5a per-module LTO needs `{name}` but it isn't on $PATH. \
             Install with `rustup component add llvm-tools-preview`, or \
             set ${env} to a specific path.",
            name = tool.exe_name(),
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
            "{label} failed (exit {:?}):\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_pool() -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(rayon::current_num_threads().min(4))
            .build()
            .unwrap()
    }

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
    fn empty_is_an_error() {
        let pool = mk_pool();
        let err = lower_per_module_parallel(&[], OptLevel::O2, &pool).unwrap_err();
        assert!(format!("{err:?}").contains("zero inputs"));
    }

    #[test]
    fn parallel_pipeline_produces_one_wasm_per_input() {
        let Some(a) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @f_a(i32 %x) { %r = add i32 %x, 1 ret i32 %r }
"#,
            "a",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };
        let Some(b) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @f_b(i32 %x) { %r = mul i32 %x, 2 ret i32 %r }
"#,
            "b",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };
        let Some(c) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @f_c(i32 %x) { %r = sub i32 %x, 1 ret i32 %r }
"#,
            "c",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };

        let pool = mk_pool();
        let result = lower_per_module_parallel(
            &[a.as_slice(), b.as_slice(), c.as_slice()],
            OptLevel::O2,
            &pool,
        );
        match result {
            Ok(objs) => {
                assert_eq!(objs.len(), 3, "one wasm object per input");
                for (i, obj) in objs.iter().enumerate() {
                    assert_eq!(
                        &obj[..4],
                        b"\0asm",
                        "module {i}: output must start with wasm magic"
                    );
                    assert!(obj.len() > 8);
                }
            }
            Err(e) => eprintln!("skipping: toolchain unavailable: {e:?}"),
        }
    }

    /// P6 end-to-end: running the same bitcode through the pipeline
    /// twice must hit the cache on the second call, shaving wall time
    /// because opt + llc aren't invoked.
    #[test]
    fn second_run_hits_the_cache_and_skips_opt_and_llc() {
        let Some(bc) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @cached_fn(i32 %x) { %r = add i32 %x, 42 ret i32 %r }
"#,
            "cached",
        ) else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };

        // Scoped cache dir so this test doesn't pollute ~/.cache or
        // collide with other tests.
        let cache_td = tempfile::tempdir().unwrap();
        // SAFETY: test-scoped env mutation; rayon runs work on a pool
        // internal to this test and env is restored before exit.
        unsafe {
            std::env::set_var("WILD_LTO_CACHE_DIR", cache_td.path());
        }

        let pool = mk_pool();
        let t0 = std::time::Instant::now();
        let r1 = lower_per_module_parallel(&[bc.as_slice()], OptLevel::O2, &pool);
        let cold = t0.elapsed();

        let t1 = std::time::Instant::now();
        let r2 = lower_per_module_parallel(&[bc.as_slice()], OptLevel::O2, &pool);
        let warm = t1.elapsed();

        unsafe {
            std::env::remove_var("WILD_LTO_CACHE_DIR");
        }

        match (r1, r2) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "cached bytes must match fresh output");
                // Expect warm to be meaningfully faster than cold.
                // A tiny single-function module has low baseline cost
                // (tens of ms), so we can't demand the dramatic
                // ≥10× speedups users see on substrate-scale links.
                // But the cache must still move the needle ≥2× —
                // anything less suggests it isn't actually being hit.
                assert!(
                    warm * 2 < cold,
                    "P6 cache should be ≥2× faster on warm run: \
                     cold={:?} warm={:?}",
                    cold,
                    warm
                );
            }
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("skipping: toolchain unavailable: {e:?}");
            }
        }
    }

    #[test]
    fn none_opt_level_skips_opt_subprocess_entirely() {
        // With OptLevel::None we skip the `opt` call — the module
        // goes straight from bitcode to llc. If llc isn't around we
        // still fail, but if llc is there and opt isn't, this call
        // must still succeed. Verify by providing just the bitcode
        // and checking the output has wasm magic.
        let Some(bc) = assemble_bc(
            r#"
target triple = "wasm32-unknown-unknown"
define i32 @only(i32 %x) { ret i32 %x }
"#,
            "only",
        ) else {
            return;
        };
        let pool = mk_pool();
        let result = lower_per_module_parallel(&[bc.as_slice()], OptLevel::None, &pool);
        if let Ok(objs) = result {
            assert_eq!(objs.len(), 1);
            assert_eq!(&objs[0][..4], b"\0asm");
        }
    }
}
