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
    wilt_hint_out: Option<usize>,
    wilt_hint_ms: u128,
    opt_out: Option<usize>,
    opt_ms: u128,
    /// Compressed (gzip -9) sizes — what users actually pay over the wire.
    input_gz: usize,
    wilt_out_gz: usize,
    wilt_hint_out_gz: usize,
    opt_out_gz: usize,
}

fn gzip_size(bytes: &[u8]) -> usize {
    use std::io::Write;
    let mut child = match Command::new("gzip")
        .arg("-9").arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return bytes.len(),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(bytes);
    }
    match child.wait_with_output() {
        Ok(out) if out.status.success() => out.stdout.len(),
        _ => bytes.len(),
    }
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

        // wilt standalone.
        let t0 = Instant::now();
        let wilt_out = wilt::optimise(&bytes);
        let wilt_ms = t0.elapsed().as_millis();
        let wilt_len = if validates(&wilt_out) { Some(wilt_out.len()) } else { None };

        // wilt with derived hints (simulates wild-as-linker).
        let (wilt_hint_out, wilt_hint_ms) = if let Some(hints) =
            wilt::linker_hints::DerivedHints::from_bytes(&bytes)
        {
            let t0 = Instant::now();
            let out = wilt::optimise_with_hints(&bytes, &hints);
            let ms = t0.elapsed().as_millis();
            let len = if validates(&out) { Some(out.len()) } else { None };
            (len, ms)
        } else {
            (None, 0)
        };

        // wasm-opt -O.
        let (opt_out, opt_ms) = match run_wasm_opt(path, "-O") {
            Some(x) => (Some(x.0.len()), x.1),
            None => { n_opt_failed += 1; (None, 0) }
        };

        // Compressed sizes — what users actually pay.
        let input_gz = gzip_size(&bytes);
        let wilt_out_gz = if wilt_len.is_some() { gzip_size(&wilt_out) } else { 0 };
        let wilt_hint_out_gz = match (wilt_hint_out, &Some(()).map(|_| ())) {
            (Some(_), _) => {
                // Re-run optimise_with_hints to get the bytes for compression.
                if let Some(hints) =
                    wilt::linker_hints::DerivedHints::from_bytes(&bytes)
                {
                    let out = wilt::optimise_with_hints(&bytes, &hints);
                    gzip_size(&out)
                } else { 0 }
            }
            _ => 0,
        };
        let opt_out_gz = if opt_out.is_some() {
            // Re-run wasm-opt to get the bytes for compression.
            if let Some((b, _)) = run_wasm_opt(path, "-O") { gzip_size(&b) } else { 0 }
        } else { 0 };

        rows.push(Row {
            name: path.strip_prefix(&root).unwrap().display().to_string(),
            input: bytes.len(),
            wilt_out: wilt_len,
            wilt_ms,
            wilt_hint_out,
            wilt_hint_ms,
            opt_out,
            opt_ms,
            input_gz,
            wilt_out_gz,
            wilt_hint_out_gz,
            opt_out_gz,
        });
    }

    // Aggregates over files where ALL THREE produced output (fair).
    let mut total_in = 0usize;
    let mut total_wilt = 0usize;
    let mut total_wilt_hint = 0usize;
    let mut total_opt = 0usize;
    let mut total_wilt_ms = 0u128;
    let mut total_wilt_hint_ms = 0u128;
    let mut total_opt_ms = 0u128;
    let mut both = 0usize;
    for r in &rows {
        if let (Some(w), Some(wh), Some(o)) = (r.wilt_out, r.wilt_hint_out, r.opt_out) {
            total_in += r.input;
            total_wilt += w;
            total_wilt_hint += wh;
            total_opt += o;
            total_wilt_ms += r.wilt_ms;
            total_wilt_hint_ms += r.wilt_hint_ms;
            total_opt_ms += r.opt_ms;
            both += 1;
        }
    }

    println!();
    println!("── aggregate (files where all three produced output) ──────────────");
    println!("files compared:    {} of {} (skipped invalid: {}, wasm-opt failed: {})",
        both, files.len(), n_skipped_invalid, n_opt_failed);
    println!("total input:       {} bytes", total_in);
    println!(
        "wilt standalone:   {} bytes  (saved {}, {:.1}%)",
        total_wilt,
        total_in - total_wilt,
        100.0 * (total_in - total_wilt) as f64 / total_in as f64,
    );
    println!(
        "wilt + hints:      {} bytes  (saved {}, {:.1}%)",
        total_wilt_hint,
        total_in - total_wilt_hint,
        100.0 * (total_in - total_wilt_hint) as f64 / total_in as f64,
    );
    println!(
        "wasm-opt -O:       {} bytes  (saved {}, {:.1}%)",
        total_opt,
        total_in - total_opt,
        100.0 * (total_in - total_opt) as f64 / total_in as f64,
    );
    if total_in > total_opt {
        println!(
            "wilt-saved / wasm-opt-saved (standalone): {:.1}%",
            100.0 * (total_in - total_wilt) as f64 / (total_in - total_opt) as f64,
        );
        println!(
            "wilt-saved / wasm-opt-saved (with hints): {:.1}%",
            100.0 * (total_in - total_wilt_hint) as f64 / (total_in - total_opt) as f64,
        );
    }
    println!("wall time: wilt {} ms / wilt+hints {} ms / wasm-opt {} ms",
        total_wilt_ms, total_wilt_hint_ms, total_opt_ms);

    // Compressed-bytes column — what users actually pay.
    let mut total_in_gz = 0usize;
    let mut total_wilt_gz = 0usize;
    let mut total_wilt_hint_gz = 0usize;
    let mut total_opt_gz = 0usize;
    for r in &rows {
        if r.wilt_out.is_some() && r.wilt_hint_out.is_some() && r.opt_out.is_some() {
            total_in_gz += r.input_gz;
            total_wilt_gz += r.wilt_out_gz;
            total_wilt_hint_gz += r.wilt_hint_out_gz;
            total_opt_gz += r.opt_out_gz;
        }
    }
    println!();
    println!("── compressed (gzip -9) sizes — wire bytes ────────────────────────");
    println!("input gz:          {} bytes", total_in_gz);
    println!("wilt gz:           {} bytes  ({:.1}%)", total_wilt_gz,
        100.0 * total_wilt_gz as f64 / total_in_gz.max(1) as f64);
    println!("wilt+hints gz:     {} bytes  ({:.1}%)", total_wilt_hint_gz,
        100.0 * total_wilt_hint_gz as f64 / total_in_gz.max(1) as f64);
    println!("wasm-opt gz:       {} bytes  ({:.1}%)", total_opt_gz,
        100.0 * total_opt_gz as f64 / total_in_gz.max(1) as f64);
    if total_opt_gz > 0 {
        println!("wilt-saved-gz / wasm-opt-saved-gz (standalone): {:.1}%",
            100.0 * (total_in_gz as i64 - total_wilt_gz as i64) as f64
                / (total_in_gz as i64 - total_opt_gz as i64).max(1) as f64);
        println!("wilt-saved-gz / wasm-opt-saved-gz (with hints): {:.1}%",
            100.0 * (total_in_gz as i64 - total_wilt_hint_gz as i64) as f64
                / (total_in_gz as i64 - total_opt_gz as i64).max(1) as f64);
    }
}
