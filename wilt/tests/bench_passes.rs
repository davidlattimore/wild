//! Per-pass micro-benchmark on the binaryen binary corpus.
//!
//! Ignored by default. Invoke:
//!     cargo test -p wilt --release --test bench_passes -- --ignored --nocapture
//!
//! Each pass runs in isolation against fresh MutModules; reports total
//! wall time across the corpus.

use std::path::PathBuf;
use std::time::Instant;

use wilt::module::WasmModule;
use wilt::mut_module::MutModule;
use wilt::passes;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("external_test_suites/binaryen/test")
}

fn collect_wasm_files() -> Vec<Vec<u8>> {
    fn walk(dir: &std::path::Path, out: &mut Vec<Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, out); }
            else if p.extension().and_then(|s| s.to_str()) == Some("wasm") {
                if let Ok(b) = std::fs::read(&p) {
                    if WasmModule::parse(&b).is_ok() { out.push(b); }
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&corpus_root(), &mut out);
    out
}

#[test]
#[ignore]
fn per_pass_timing() {
    let files = collect_wasm_files();
    println!("\n{} input modules", files.len());

    type MutPassFn = fn(&mut MutModule<'_>);
    let mut_passes: &[(&str, MutPassFn)] = &[
        ("const_fold",         passes::const_fold::apply_mut),
        ("vacuum",             passes::vacuum::apply_mut),
        ("const_prop",         passes::const_prop::apply_mut),
        ("branch_threading",   passes::branch_threading::apply_mut),
        ("cfg_dce",            passes::cfg_dce::apply_mut),
        ("simplify_locals",    passes::simplify_locals::apply_mut),
        ("remove_unused_brs",  passes::remove_unused_brs::apply_mut),
        ("merge_blocks",       passes::merge_blocks::apply_mut),
        ("fn_merge",           passes::fn_merge::apply_mut),
        ("inline_trivial",     passes::inline_trivial::apply_mut),
        ("dae",                passes::dae::apply_mut),
        ("dead_globals",       passes::dead_globals::apply_mut),
        ("devirt",             passes::devirt::apply_mut),
        ("reorder_locals",     passes::reorder_locals::apply_mut),
        ("memory_packing",     passes::memory_packing::apply_mut),
    ];

    println!("\n{:<20} {:>10} {:>10}", "pass", "total ms", "per file");
    println!("{:-<20} {:->10} {:->10}", "", "", "");
    for &(name, f) in mut_passes {
        let mut total_us: u128 = 0;
        for input in &files {
            let mut m = match MutModule::new(input) { Ok(m) => m, Err(_) => continue };
            let t0 = Instant::now();
            f(&mut m);
            total_us += t0.elapsed().as_micros();
            // Force serialise to include rebuild work in the cost picture.
            let _ = m.serialize();
        }
        let n = files.len() as u128;
        println!("{:<20} {:>9}  {:>9}",
            name,
            format!("{}ms", total_us / 1000),
            format!("{}us", total_us / n.max(1)));
    }

    // Also report full pipeline.
    let mut total = 0u128;
    for input in &files {
        let t0 = Instant::now();
        let _ = wilt::optimise(input);
        total += t0.elapsed().as_micros();
    }
    println!();
    println!("{:<20} {:>9}", "FULL pipeline", format!("{}ms", total / 1000));
}
