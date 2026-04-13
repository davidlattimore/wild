//! Per-section gap on /tmp/real.wasm. Tells us where the 37 KB
//! wasm-opt beats us on real compiled code actually lives.

use std::collections::BTreeMap;
use std::process::Command;
use wilt::module::WasmModule;

fn section_sizes(bytes: &[u8]) -> BTreeMap<u8, usize> {
    let mut out = BTreeMap::new();
    if let Ok(m) = WasmModule::parse(bytes) {
        for sec in m.sections() { *out.entry(sec.id).or_insert(0) += sec.full.len as usize; }
    }
    out
}

fn name(id: u8) -> &'static str {
    match id {
        0 => "custom", 1 => "type", 2 => "import", 3 => "function",
        4 => "table", 5 => "memory", 6 => "global", 7 => "export",
        8 => "start", 9 => "element", 10 => "code", 11 => "data",
        12 => "data_count", _ => "?",
    }
}

fn wasm_opt(path: &str) -> Option<Vec<u8>> {
    let out = format!("/tmp/gap_out_{}.wasm", std::process::id());
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
fn real_section_gap() {
    let path = "/tmp/real.wasm";
    let Ok(bytes) = std::fs::read(path) else {
        println!("stage a real wasm at {path}"); return;
    };
    let wilt_out = wilt::optimise(&bytes);
    let Some(opt_out) = wasm_opt(path) else { println!("wasm-opt failed"); return };

    let w = section_sizes(&wilt_out);
    let o = section_sizes(&opt_out);
    println!("\n── per-section (real binary) ──");
    println!("{:<14} {:>10} {:>10} {:>10}", "section", "wilt", "wasm-opt", "gap");
    let mut ids: Vec<u8> = w.keys().chain(o.keys()).copied().collect();
    ids.sort(); ids.dedup();
    for id in ids {
        let ws = *w.get(&id).unwrap_or(&0);
        let os = *o.get(&id).unwrap_or(&0);
        println!("{:<14} {:>10} {:>10} {:>10}", name(id), ws, os, ws as i64 - os as i64);
    }
}
