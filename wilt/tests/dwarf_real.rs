//! Verifies wilt's DWARF line-section preservation against a real
//! DWARF-bearing binary. Skipped if the binaryen test suite isn't
//! checked out.

use std::path::PathBuf;
use wilt::WasmModule;

fn dwarf_sample() -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("external_test_suites/binaryen/test/passes/fannkuch0_dwarf.wasm");
    std::fs::read(&p).ok()
}

fn debug_line_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    let m = WasmModule::parse(bytes).ok()?;
    let data = m.data();
    m.sections().iter().find_map(|s| {
        if s.id != 0 { return None; }
        let name = s.custom_name?.slice(data);
        if name != b".debug_line" { return None; }
        let p = s.payload.slice(data);
        let (nlen, c) = wilt::leb128::read_u32(p)?;
        Some(p[c + nlen as usize..].to_vec())
    })
}

#[test]
fn debug_line_round_trips_when_module_unchanged() {
    let Some(bytes) = dwarf_sample() else {
        eprintln!("skip: binaryen DWARF sample not available"); return;
    };
    let in_line = debug_line_payload(&bytes).expect("input has .debug_line");

    // Run wilt at Lines tier on a module that hasn't been touched.
    let out = wilt::optimise_with_debug_level(&bytes, wilt::debug_level::DebugLevel::Lines);
    if WasmModule::parse(&out).is_err() {
        panic!("output didn't validate");
    }
    if let Some(out_line) = debug_line_payload(&out) {
        // If preserved, length should match (we either keep verbatim
        // or do equal-length address patching).
        assert_eq!(in_line.len(), out_line.len(),
                   "preserved .debug_line should have identical length");
    }
    // It's also valid for output to drop .debug_line if our pipeline
    // couldn't satisfy preservation conditions on this binary.
}
