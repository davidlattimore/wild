//! Diagnostic — per-section byte diff between wilt and wasm-opt -O
//! across the binaryen corpus. Tells us where bytes still hide.
//!
//! Ignored by default.  cargo test -p wilt --release --test section_gap -- --ignored --nocapture

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use wilt::module::WasmModule;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("external_test_suites/binaryen/test")
}

fn collect_wasm_files() -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|s| s.to_str()) == Some("wasm") {
                if let Ok(b) = std::fs::read(&p) {
                    if WasmModule::parse(&b).is_ok() {
                        out.push((p, b));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&corpus_root(), &mut out);
    out
}

fn run_wasm_opt(input: &[u8]) -> Option<Vec<u8>> {
    let tmpdir = std::env::temp_dir();
    let inp = tmpdir.join("sg_in.wasm");
    let outp = tmpdir.join("sg_out.wasm");
    std::fs::write(&inp, input).ok()?;
    let status = Command::new("wasm-opt")
        .args(["-O", inp.to_str()?, "-o", outp.to_str()?])
        .output()
        .ok()?;
    if !status.status.success() {
        return None;
    }
    std::fs::read(&outp).ok()
}

fn section_sizes(bytes: &[u8]) -> BTreeMap<u8, usize> {
    let mut out = BTreeMap::new();
    let Ok(m) = WasmModule::parse(bytes) else {
        return out;
    };
    for sec in m.sections() {
        *out.entry(sec.id).or_insert(0) += sec.full.len as usize;
    }
    out
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        _ => "unknown",
    }
}

#[test]
#[ignore]
fn per_section_gap() {
    let files = collect_wasm_files();
    let mut wilt_sizes: BTreeMap<u8, usize> = BTreeMap::new();
    let mut wo_sizes: BTreeMap<u8, usize> = BTreeMap::new();
    let mut counted = 0;
    for (_, bytes) in &files {
        let wilt_out = wilt::optimise(bytes);
        let Some(wo_out) = run_wasm_opt(bytes) else {
            continue;
        };
        if WasmModule::parse(&wilt_out).is_err() {
            continue;
        }
        if WasmModule::parse(&wo_out).is_err() {
            continue;
        }
        for (id, sz) in section_sizes(&wilt_out) {
            *wilt_sizes.entry(id).or_insert(0) += sz;
        }
        for (id, sz) in section_sizes(&wo_out) {
            *wo_sizes.entry(id).or_insert(0) += sz;
        }
        counted += 1;
    }
    println!("\n── per-section byte totals across {counted} modules ──");
    println!(
        "{:<14} {:>12} {:>12} {:>12}",
        "section", "wilt", "wasm-opt", "gap"
    );
    let mut all_ids: Vec<u8> = wilt_sizes.keys().chain(wo_sizes.keys()).copied().collect();
    all_ids.sort();
    all_ids.dedup();
    for id in all_ids {
        let w = *wilt_sizes.get(&id).unwrap_or(&0);
        let o = *wo_sizes.get(&id).unwrap_or(&0);
        let gap = w as i64 - o as i64;
        println!("{:<14} {:>12} {:>12} {:>12}", section_name(id), w, o, gap);
    }
}
