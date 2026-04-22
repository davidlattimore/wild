//! Apples-to-apples comparison: wilt's default `optimise()` vs
//! `wasm-opt -O -g` — the flag that tells wasm-opt to preserve
//! debug info on -O. Strips the "wasm-opt silently discards name +
//! .debug_line" advantage that the plain `-O` run enjoys.
//!
//! Ignored by default. cargo test -p wilt --release --test compare_with_debug -- --ignored
//! --nocapture

use std::path::PathBuf;
use std::process::Command;
use wasmparser::Validator;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("external_test_suites/binaryen/test")
}

fn collect(root: &std::path::Path) -> Vec<PathBuf> {
    fn w(d: &std::path::Path, o: &mut Vec<PathBuf>) {
        let Ok(es) = std::fs::read_dir(d) else { return };
        for e in es.flatten() {
            let p = e.path();
            if p.is_dir() {
                w(&p, o);
            } else if p.extension().and_then(|s| s.to_str()) == Some("wasm") {
                o.push(p);
            }
        }
    }
    let mut v = Vec::new();
    w(root, &mut v);
    v
}

fn valid(b: &[u8]) -> bool {
    Validator::new().validate_all(b).is_ok()
}

fn wasm_opt(p: &std::path::Path, keep_debug: bool) -> Option<Vec<u8>> {
    let out = std::env::temp_dir().join(format!(
        "wilt_dbg_{}_{}.wasm",
        std::process::id(),
        p.file_stem().and_then(|s| s.to_str()).unwrap_or("x"),
    ));
    let mut cmd = Command::new("wasm-opt");
    cmd.arg("-O");
    if keep_debug {
        cmd.arg("-g");
    }
    cmd.arg(p)
        .arg("-o")
        .arg(&out)
        .arg("--enable-bulk-memory")
        .arg("--enable-sign-ext")
        .arg("--enable-nontrapping-float-to-int")
        .arg("--enable-mutable-globals")
        .arg("--enable-simd")
        .arg("--enable-reference-types")
        .arg("--enable-multivalue");
    let ok = cmd.status().ok()?.success();
    if !ok {
        return None;
    }
    let b = std::fs::read(&out).ok()?;
    let _ = std::fs::remove_file(&out);
    Some(b)
}

#[test]
#[ignore]
fn compare_both_preserve_debug() {
    let files = collect(&corpus_root());
    let mut n = 0;
    let mut in_total = 0usize;
    let mut wilt_total = 0usize;
    let mut opt_plain = 0usize;
    let mut opt_keepg = 0usize;

    for p in &files {
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        if !valid(&bytes) {
            continue;
        }
        let wilt_out = wilt::optimise(&bytes);
        if !valid(&wilt_out) {
            continue;
        }
        let Some(o_plain) = wasm_opt(p, false) else {
            continue;
        };
        let Some(o_keep) = wasm_opt(p, true) else {
            continue;
        };

        in_total += bytes.len();
        wilt_total += wilt_out.len();
        opt_plain += o_plain.len();
        opt_keepg += o_keep.len();
        n += 1;
    }

    let saved_wilt = in_total - wilt_total;
    let saved_plain = in_total.saturating_sub(opt_plain);
    let saved_keep = in_total.saturating_sub(opt_keepg);

    println!("\n── {n} modules compared (both tools keep debug where flag says so) ──");
    println!("total input:             {in_total} bytes");
    println!(
        "wilt:                    {wilt_total} (saved {saved_wilt}, {:.1}%)",
        100.0 * saved_wilt as f64 / in_total as f64
    );
    println!(
        "wasm-opt -O (drops name):{opt_plain} (saved {saved_plain}, {:.1}%)",
        100.0 * saved_plain as f64 / in_total as f64
    );
    println!(
        "wasm-opt -O -g (keeps):  {opt_keepg} (saved {saved_keep}, {:.1}%)",
        100.0 * saved_keep as f64 / in_total as f64
    );
    println!();
    if saved_plain > 0 {
        println!(
            "wilt / wasm-opt (-O):    {:.1}%",
            100.0 * saved_wilt as f64 / saved_plain as f64
        );
    }
    if saved_keep > 0 {
        println!(
            "wilt / wasm-opt (-O -g): {:.1}%",
            100.0 * saved_wilt as f64 / saved_keep as f64
        );
    }
    println!();
    println!("When BOTH tools preserve debug info, wilt's ratio jumps because");
    println!("wasm-opt's \"-O\" headline is partly it dropping customs by default.");
}
