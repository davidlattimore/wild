//! One-shot diagnostic: run each pass in pipeline order on a saved
//! fuzz input and report the first stage where validation breaks.

use wasmparser::Validator;
use wilt::module::WasmModule;
use wilt::passes;

fn validates(bytes: &[u8]) -> Result<(), String> {
    Validator::new()
        .validate_all(bytes)
        .map_err(|e| e.to_string())
        .map(|_| ())
}

fn report(stage: &str, bytes: &[u8]) {
    match validates(bytes) {
        Ok(()) => println!("  [OK]   {:<30} {} bytes", stage, bytes.len()),
        Err(e) => println!("  [FAIL] {:<30} {} bytes — {}", stage, bytes.len(), e),
    }
}

#[test]
fn bisect() {
    let input = match std::fs::read("/tmp/wilt_fuzz_in.wasm") {
        Ok(b) => b,
        Err(_) => {
            eprintln!("no /tmp/wilt_fuzz_in.wasm; skipping");
            return;
        }
    };
    report("input", &input);

    let mut m = WasmModule::parse(&input).unwrap();
    let after = passes::dedup_imports::apply(&mut m);
    report("after dedup_imports", &after);
    std::fs::write("/tmp/wilt_after_dedup_imports.wasm", &after).ok();

    let mut m = WasmModule::parse(&after).unwrap();
    let after = passes::dedup::apply(&mut m);
    report("after dedup", &after);

    let mut m = WasmModule::parse(&after).unwrap();
    let after = passes::dce::apply(&mut m);
    report("after dce", &after);

    let m = WasmModule::parse(&after).unwrap();
    let analysis = passes::type_gc::analyse(&m);
    println!(
        "  type_gc analysis: kept={} bail={} map={:?}",
        analysis.kept, analysis.bail, analysis.index_map
    );
    let after = passes::type_gc::apply(&m);
    report("after type_gc", &after);
    std::fs::write("/tmp/wilt_after_type_gc.wasm", &after).ok();

    // MutModule stage — do each sub-pass one at a time.
    type PassFn = fn(&mut wilt::mut_module::MutModule<'_>);
    let mut stage_in = after.clone();
    let stages: [(&str, PassFn); 8] = [
        ("const_fold", passes::const_fold::apply_mut),
        ("vacuum", passes::vacuum::apply_mut),
        ("remove_unused_brs", passes::remove_unused_brs::apply_mut),
        ("merge_blocks", passes::merge_blocks::apply_mut),
        ("simplify_locals", passes::simplify_locals::apply_mut),
        ("inline_trivial", passes::inline_trivial::apply_mut),
        ("dae", passes::dae::apply_mut),
        ("reorder_locals", passes::reorder_locals::apply_mut),
    ];
    for (name, f) in stages {
        let mut m = wilt::mut_module::MutModule::new(&stage_in).unwrap();
        f(&mut m);
        stage_in = m.serialize();
        report(&format!("after {name}"), &stage_in);
    }

    let mut m = WasmModule::parse(&stage_in).unwrap();
    let after = passes::unused_data::apply(&mut m);
    report("after unused_data", &after);

    let mut m = WasmModule::parse(&after).unwrap();
    let after = passes::unused_elem::apply(&mut m);
    report("after unused_elem", &after);

    let mut m = WasmModule::parse(&after).unwrap();
    let after = passes::reorder::apply(&mut m);
    report("after reorder", &after);
}
