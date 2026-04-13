//! Deterministic-output guarantees.
//!
//! `wilt::optimise` must be pure: same input bytes → same output bytes,
//! across repeated calls AND across different rayon thread counts.
//! This isn't free — rayon's `par_iter` + `filter_map` + `collect` is
//! deterministic (order-preserving), but any HashMap iteration inside
//! passes that drives output ordering would break it. These tests are
//! the guard.

use std::path::PathBuf;
use std::sync::Arc;

use wilt::module::WasmModule;

/// Build a small but non-trivial module: 3 exported funcs, a couple
/// of internal helpers, a mutable global, a data segment. Enough to
/// exercise most passes.
fn build_fixture() -> Vec<u8> {
    let wat = r#"
        (module
          (memory (export "mem") 1)
          (data (i32.const 0) "hello")
          (global $g (mut i32) (i32.const 0))
          (func $helper (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.add)
          (func $unused (result i32) i32.const 42)
          (func $exp (export "exp") (param i32) (result i32)
            local.get 0
            call $helper
            call $helper)
          (func $zero (export "zero") (result i32)
            global.get $g)
          (func $set (export "set") (param i32)
            local.get 0
            global.set $g))
    "#;
    wat::parse_str(wat).unwrap()
}

fn binaryen_sample() -> Option<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("external_test_suites/binaryen/test");
    for entry in walkdir(&root).into_iter().take(30) {
        if entry.extension().and_then(|s| s.to_str()) != Some("wasm") { continue; }
        if let Ok(b) = std::fs::read(&entry) {
            if WasmModule::parse(&b).is_ok() && b.len() > 500 { return Some(b); }
        }
    }
    None
}

fn walkdir(root: &std::path::Path) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(es) = std::fs::read_dir(dir) else { return };
        for e in es.flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, out); } else { out.push(p); }
        }
    }
    let mut v = Vec::new(); walk(root, &mut v); v
}

#[test]
fn repeated_calls_produce_identical_output() {
    let input = build_fixture();
    let a = wilt::optimise(&input);
    let b = wilt::optimise(&input);
    let c = wilt::optimise(&input);
    assert_eq!(a, b, "run 1 != run 2");
    assert_eq!(b, c, "run 2 != run 3");
}

#[test]
fn identical_across_thread_counts() {
    let input = Arc::new(build_fixture());
    let outputs: Vec<Vec<u8>> = [1, 2, 4, 16]
        .iter()
        .map(|&n| {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build()
                .unwrap();
            let inp = Arc::clone(&input);
            pool.install(move || wilt::optimise(&inp))
        })
        .collect();
    let first = &outputs[0];
    for (i, out) in outputs.iter().enumerate().skip(1) {
        assert_eq!(
            first, out,
            "thread count {} produced different output than thread count 1",
            [1, 2, 4, 16][i]
        );
    }
}

#[test]
fn identical_on_binaryen_sample() {
    let Some(input) = binaryen_sample() else {
        eprintln!("no binaryen sample available — skipping"); return;
    };
    // Three runs at default thread count.
    let a = wilt::optimise(&input);
    let b = wilt::optimise(&input);
    assert_eq!(a, b, "repeated runs on real sample must match");
}

/// All fixture regression .wat files should produce stable output.
/// Catches a pass that accidentally iterates a HashMap into output order.
#[test]
fn identical_across_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/regressions");
    let Ok(entries) = std::fs::read_dir(&root) else { return };
    let mut count = 0;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wat") { continue; }
        let Ok(src) = std::fs::read_to_string(&p) else { continue };
        let Ok(bytes) = wat::parse_str(&src) else { continue };
        let a = wilt::optimise(&bytes);
        let b = wilt::optimise(&bytes);
        assert_eq!(a, b, "repeated-run mismatch on fixture {}", p.display());
        count += 1;
    }
    assert!(count > 0, "should have run at least one fixture");
}
