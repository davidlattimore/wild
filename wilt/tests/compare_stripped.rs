//! Apples-to-apples corpus comparison: strip DWARF/source-maps from
//! BOTH wilt's and wasm-opt's output, then compare. Factors out the
//! custom-section noise so we see pure optimisation-pass quality.
//!
//! Ignored by default.
//!   cargo test -p wilt --release --test compare_stripped -- --ignored --nocapture

use std::path::PathBuf;
use std::process::Command;

use wasmparser::Validator;
use wilt::module::WasmModule;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("external_test_suites/binaryen/test")
}

fn collect_wasm_files(root: &std::path::Path) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
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
    out
}

fn validates(b: &[u8]) -> bool {
    Validator::new().validate_all(b).is_ok()
}

fn strip(bytes: &[u8]) -> Vec<u8> {
    let Ok(m) = WasmModule::parse(bytes) else { return bytes.to_vec() };
    wilt::passes::strip::apply(&m, wilt::passes::strip::StripConfig::default_strip())
}

fn gz(bytes: &[u8]) -> usize {
    use std::io::Write;
    let Ok(mut c) = Command::new("gzip").arg("-9").arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn() else { return bytes.len() };
    // Deadlock guard: drain stdin on a thread (see real_binary.rs for
    // the full rationale).
    let stdin = c.stdin.take().unwrap();
    let buf = bytes.to_vec();
    let writer = std::thread::spawn(move || {
        let mut s = stdin; let _ = s.write_all(&buf);
    });
    let out = c.wait_with_output().map(|o| o.stdout.len()).unwrap_or(bytes.len());
    let _ = writer.join();
    out
}

fn wasm_opt(path: &std::path::Path) -> Option<Vec<u8>> {
    let out = std::env::temp_dir().join(format!(
        "wilt_strip_{}_{}.wasm", std::process::id(),
        path.file_stem().and_then(|s| s.to_str()).unwrap_or("x"),
    ));
    let ok = Command::new("wasm-opt").arg("-O").arg(path).arg("-o").arg(&out)
        .arg("--enable-bulk-memory").arg("--enable-sign-ext")
        .arg("--enable-nontrapping-float-to-int").arg("--enable-mutable-globals")
        .arg("--enable-simd").arg("--enable-reference-types")
        .arg("--enable-multivalue")
        .status().ok()?.success();
    if !ok { return None; }
    let b = std::fs::read(&out).ok()?;
    let _ = std::fs::remove_file(&out);
    Some(b)
}

#[test]
#[ignore]
fn stripped_vs_stripped() {
    let files = collect_wasm_files(&corpus_root());
    let mut n = 0;
    let mut in_total = 0usize;
    let mut in_strip = 0usize;
    let mut wilt_strip = 0usize;
    let mut opt_strip = 0usize;
    let mut in_strip_gz = 0usize;
    let mut wilt_strip_gz = 0usize;
    let mut opt_strip_gz = 0usize;

    for path in &files {
        let Ok(bytes) = std::fs::read(path) else { continue };
        if !validates(&bytes) { continue; }

        let wilt_out = wilt::optimise(&bytes);
        if !validates(&wilt_out) { continue; }
        let Some(opt_out) = wasm_opt(path) else { continue };

        let b_s = strip(&bytes);
        let w_s = strip(&wilt_out);
        let o_s = strip(&opt_out);

        in_total += bytes.len();
        in_strip += b_s.len();
        wilt_strip += w_s.len();
        opt_strip += o_s.len();
        in_strip_gz += gz(&b_s);
        wilt_strip_gz += gz(&w_s);
        opt_strip_gz += gz(&o_s);
        n += 1;
    }

    println!("\n── stripped-vs-stripped (DWARF + source maps removed both sides) ──");
    println!("files compared:    {n}");
    println!("input (stripped):  {in_strip} bytes (raw input was {in_total})");
    println!(
        "wilt (stripped):   {wilt_strip} bytes  (saved {}, {:.1}%)",
        in_strip - wilt_strip,
        100.0 * (in_strip - wilt_strip) as f64 / in_strip as f64,
    );
    println!(
        "wasm-opt:          {opt_strip} bytes  (saved {}, {:.1}%)",
        in_strip - opt_strip,
        100.0 * (in_strip - opt_strip) as f64 / in_strip as f64,
    );
    if in_strip > opt_strip {
        println!("wilt-saved / wasm-opt-saved: {:.1}%",
            100.0 * (in_strip - wilt_strip) as f64 / (in_strip - opt_strip) as f64);
    }

    println!("\n── compressed (gzip -9) ──");
    println!("input gz:   {in_strip_gz}");
    println!("wilt gz:    {wilt_strip_gz}  ({:.1}% of input)",
        100.0 * wilt_strip_gz as f64 / in_strip_gz as f64);
    println!("wasm-opt gz:{opt_strip_gz}  ({:.1}% of input)",
        100.0 * opt_strip_gz as f64 / in_strip_gz as f64);
    if in_strip_gz > opt_strip_gz {
        println!("wilt-saved-gz / wasm-opt-saved-gz: {:.1}%",
            100.0 * (in_strip_gz - wilt_strip_gz) as f64 / (in_strip_gz - opt_strip_gz) as f64);
    }
}
