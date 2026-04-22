//! Run wilt + wasm-opt on a real compiled wasm binary (not the
//! synthetic binaryen tests). Tells us where we stand on realistic
//! toolchain output.
//!
//! Expects /tmp/real.wasm — the user stages whatever real binary
//! they want to measure. Ignored by default.

use std::process::Command;
use std::time::Instant;
use wasmparser::Validator;

fn gz(bytes: &[u8]) -> usize {
    use std::io::Write;
    let Ok(mut c) = Command::new("gzip")
        .arg("-9")
        .arg("-c")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    else {
        return bytes.len();
    };
    // Must drain stdin on a separate thread — for inputs larger than
    // the pipe buffer (~64 KB on macOS) gzip's stdout fills first,
    // gzip then blocks writing, can't consume more stdin, and
    // write_all deadlocks. wait_with_output drains stdout in parallel,
    // so the only remaining risk is the stdin path, hence the thread.
    let stdin = c.stdin.take().unwrap();
    let buf = bytes.to_vec();
    let writer = std::thread::spawn(move || {
        let mut s = stdin;
        let _ = s.write_all(&buf);
    });
    let out = c
        .wait_with_output()
        .map(|o| o.stdout.len())
        .unwrap_or(bytes.len());
    let _ = writer.join();
    out
}

fn validates(b: &[u8]) -> bool {
    Validator::new().validate_all(b).is_ok()
}

fn run_wasm_opt(input_path: &str) -> Option<(Vec<u8>, u128)> {
    let out = format!("/tmp/real_out_{}.wasm", std::process::id());
    let t0 = Instant::now();
    let ok = Command::new("wasm-opt")
        .arg("-O")
        .arg(input_path)
        .arg("-o")
        .arg(&out)
        .arg("--enable-bulk-memory")
        .arg("--enable-sign-ext")
        .arg("--enable-nontrapping-float-to-int")
        .arg("--enable-mutable-globals")
        .arg("--enable-simd")
        .arg("--enable-reference-types")
        .arg("--enable-multivalue")
        .status()
        .ok()?
        .success();
    let elapsed = t0.elapsed().as_millis();
    if !ok {
        return None;
    }
    let bytes = std::fs::read(&out).ok()?;
    let _ = std::fs::remove_file(&out);
    Some((bytes, elapsed))
}

#[test]
#[ignore]
fn real_binary() {
    let path = "/tmp/real.wasm";
    let Ok(bytes) = std::fs::read(path) else {
        println!("stage a real wasm at {path} then re-run");
        return;
    };
    if !validates(&bytes) {
        println!("/tmp/real.wasm does not validate");
        return;
    }

    let t0 = Instant::now();
    let wilt_out = wilt::optimise(&bytes);
    let wilt_ms = t0.elapsed().as_millis();
    assert!(validates(&wilt_out), "wilt output must validate");

    let wilt_strip = wilt::optimise_stripped(&bytes);
    assert!(validates(&wilt_strip));

    let Some((opt_out, opt_ms)) = run_wasm_opt(path) else {
        println!("wasm-opt failed on real binary");
        return;
    };

    println!("\n── {path} — real compiled binary ──");
    println!("input:           {} bytes (gz {})", bytes.len(), gz(&bytes));
    println!(
        "wilt:            {} bytes (gz {})  [{wilt_ms} ms]",
        wilt_out.len(),
        gz(&wilt_out)
    );
    println!(
        "wilt_stripped:   {} bytes (gz {})",
        wilt_strip.len(),
        gz(&wilt_strip)
    );
    println!(
        "wasm-opt -O:     {} bytes (gz {})  [{opt_ms} ms]",
        opt_out.len(),
        gz(&opt_out)
    );

    let saved_wilt = bytes.len().saturating_sub(wilt_out.len());
    let saved_strip = bytes.len().saturating_sub(wilt_strip.len());
    let saved_opt = bytes.len().saturating_sub(opt_out.len());
    println!();
    println!(
        "wilt saved:           {saved_wilt} bytes ({:.1}%)",
        100.0 * saved_wilt as f64 / bytes.len() as f64
    );
    println!(
        "wilt_stripped saved:  {saved_strip} bytes ({:.1}%)",
        100.0 * saved_strip as f64 / bytes.len() as f64
    );
    println!(
        "wasm-opt saved:       {saved_opt} bytes ({:.1}%)",
        100.0 * saved_opt as f64 / bytes.len() as f64
    );
    if saved_opt > 0 {
        println!();
        println!(
            "wilt/wasm-opt ratio:          {:.1}%",
            100.0 * saved_wilt as f64 / saved_opt as f64
        );
        println!(
            "wilt_stripped/wasm-opt ratio: {:.1}%",
            100.0 * saved_strip as f64 / saved_opt as f64
        );
    }
}
