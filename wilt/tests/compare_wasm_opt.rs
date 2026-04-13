//! Head-to-head: wilt vs wasm-opt on the binaryen binary corpus.
//!
//! Ignored by default — runs many hundreds of subprocess invocations.
//! Invoke with:
//!
//!     cargo test -p wilt --test compare_wasm_opt -- --ignored --nocapture
//!
//! Requires `wasm-opt` on PATH. Reports per-file and aggregate numbers:
//! input size, wilt's output size, wasm-opt's output size, saved bytes,
//! and the ratio wilt-saved / wasm-opt-saved. Also reports wall time
//! for each tool.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use wasmparser::Validator;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("external_test_suites/binaryen/test")
}

fn collect_wasm_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, out); }
            else if p.extension().and_then(|s| s.to_str()) == Some("wasm") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

fn validates(bytes: &[u8]) -> bool {
    Validator::new().validate_all(bytes).is_ok()
}

struct Row {
    name: String,
    input: usize,
    wilt_out: Option<usize>,
    wilt_ms: u128,
    opt_out: Option<usize>,
    opt_ms: u128,
}

fn run_wasm_opt(input_path: &Path, level: &str) -> Option<(Vec<u8>, u128)> {
    let out = std::env::temp_dir().join(format!(
        "wilt_cmp_{}_{}.wasm",
        std::process::id(),
        input_path.file_stem().and_then(|s| s.to_str()).unwrap_or("x"),
    ));
    let t0 = Instant::now();
    let status = Command::new("wasm-opt")
        .arg(level)
        .arg(input_path)
        .arg("-o")
        .arg(&out)
        // Enable the feature set wilt's corpus harness uses.
        .arg("--enable-bulk-memory")
        .arg("--enable-sign-ext")
        .arg("--enable-nontrapping-float-to-int")
        .arg("--enable-mutable-globals")
        .arg("--enable-simd")
        .arg("--enable-reference-types")
        .arg("--enable-multivalue")
        .status()
        .ok()?;
    let elapsed = t0.elapsed().as_millis();
    if !status.success() { return None; }
    let bytes = std::fs::read(&out).ok()?;
    let _ = std::fs::remove_file(&out);
    Some((bytes, elapsed))
}

#[test]
#[ignore]
fn compare_aggregate() {
    let root = corpus_root();
    let files = collect_wasm_files(&root);
    assert!(!files.is_empty(), "no .wasm files found under {}", root.display());

    let mut rows: Vec<Row> = Vec::new();
    let mut n_skipped_invalid = 0;
    let mut n_opt_failed = 0;

    for path in &files {
        let Ok(bytes) = std::fs::read(path) else { continue };
        if !validates(&bytes) {
            n_skipped_invalid += 1;
            continue;
        }

        // wilt.
        let t0 = Instant::now();
        let wilt_out = wilt::optimise(&bytes);
        let wilt_ms = t0.elapsed().as_millis();
        let wilt_len = if validates(&wilt_out) { Some(wilt_out.len()) } else { None };

        // wasm-opt -O.
        let (opt_out, opt_ms) = match run_wasm_opt(path, "-O") {
            Some(x) => (Some(x.0.len()), x.1),
            None => { n_opt_failed += 1; (None, 0) }
        };

        rows.push(Row {
            name: path.strip_prefix(&root).unwrap().display().to_string(),
            input: bytes.len(),
            wilt_out: wilt_len,
            wilt_ms,
            opt_out,
            opt_ms,
        });
    }

    // Aggregates over files where BOTH produced output (fair comparison).
    let mut total_in = 0usize;
    let mut total_wilt = 0usize;
    let mut total_opt = 0usize;
    let mut total_wilt_ms = 0u128;
    let mut total_opt_ms = 0u128;
    let mut both = 0usize;
    for r in &rows {
        if let (Some(w), Some(o)) = (r.wilt_out, r.opt_out) {
            total_in += r.input;
            total_wilt += w;
            total_opt += o;
            total_wilt_ms += r.wilt_ms;
            total_opt_ms += r.opt_ms;
            both += 1;
        }
    }

    println!();
    println!("── per-file ────────────────────────────────────────────────────────");
    println!(
        "{:<50}  {:>7}  {:>9}  {:>9}  {:>8}",
        "file", "input", "wilt", "wasm-opt", "Δ",
    );
    println!("{:-<50}  {:-<7}  {:-<9}  {:-<9}  {:-<8}", "", "", "", "", "");
    for r in &rows {
        let wilt_s = r.wilt_out.map(|n| format!("{}", n)).unwrap_or_else(|| "—".to_string());
        let opt_s = r.opt_out.map(|n| format!("{}", n)).unwrap_or_else(|| "—".to_string());
        let delta = match (r.wilt_out, r.opt_out) {
            (Some(w), Some(o)) => {
                let w_saved = r.input as isize - w as isize;
                let o_saved = r.input as isize - o as isize;
                if o_saved == 0 { "—".to_string() }
                else {
                    format!("{:.0}%", 100.0 * w_saved as f64 / o_saved as f64)
                }
            }
            _ => "—".to_string(),
        };
        let short = if r.name.len() > 48 { &r.name[r.name.len()-48..] } else { &r.name };
        println!(
            "{:<50}  {:>7}  {:>9}  {:>9}  {:>8}",
            short, r.input, wilt_s, opt_s, delta,
        );
    }

    println!();
    println!("── aggregate (files where both produced output) ───────────────────");
    println!("files compared:    {} of {} (skipped invalid: {}, wasm-opt failed: {})",
        both, files.len(), n_skipped_invalid, n_opt_failed);
    println!("total input:       {} bytes", total_in);
    println!(
        "wilt total out:    {} bytes  (saved {}, {:.1}%)",
        total_wilt,
        total_in - total_wilt,
        100.0 * (total_in - total_wilt) as f64 / total_in as f64,
    );
    println!(
        "wasm-opt total:    {} bytes  (saved {}, {:.1}%)",
        total_opt,
        total_in - total_opt,
        100.0 * (total_in - total_opt) as f64 / total_in as f64,
    );
    if total_in > total_opt {
        println!(
            "wilt-saved / wasm-opt-saved: {:.1}%",
            100.0 * (total_in - total_wilt) as f64 / (total_in - total_opt) as f64,
        );
    }
    println!("wall time:         wilt {} ms, wasm-opt {} ms  (ratio {:.2}x)",
        total_wilt_ms, total_opt_ms,
        total_opt_ms as f64 / total_wilt_ms.max(1) as f64,
    );
}
