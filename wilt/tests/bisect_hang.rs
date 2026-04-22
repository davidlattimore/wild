//! Time each pass individually on /tmp/big.wasm. Finds which pass hangs
//! on the 1.9 MB binary. Ignored by default; per-pass timeout logged.

use std::time::Instant;
use wilt::module::WasmModule;
use wilt::mut_module::MutModule;

macro_rules! time_step {
    ($label:expr, $code:block) => {{
        let t0 = Instant::now();
        let result = $code;
        println!("{:<32} {:>8} ms", $label, t0.elapsed().as_millis());
        result
    }};
}

#[test]
#[ignore]
fn bisect() {
    let Ok(bytes) = std::fs::read("/tmp/big.wasm") else {
        println!("stage /tmp/big.wasm");
        return;
    };
    println!("input {} bytes", bytes.len());

    // Per-pass, starting from a fresh parse each time.
    let after_didup = time_step!("dedup_imports", {
        let mut m = WasmModule::parse(&bytes).unwrap();
        wilt::passes::dedup_imports::apply(&mut m)
    });
    let after_dedup = time_step!("dedup", {
        let mut m = WasmModule::parse(&after_didup).unwrap();
        wilt::passes::dedup::apply(&mut m)
    });
    let after_dce = time_step!("dce", {
        let mut m = WasmModule::parse(&after_dedup).unwrap();
        wilt::passes::dce::apply(&mut m)
    });
    let after_type_gc = time_step!("type_gc", {
        let m = WasmModule::parse(&after_dce).unwrap();
        wilt::passes::type_gc::apply(&m)
    });

    let mut m = MutModule::new(&after_type_gc).unwrap();
    time_step!("const_fold", {
        wilt::passes::const_fold::apply_mut(&mut m)
    });
    time_step!("const_prop", {
        wilt::passes::const_prop::apply_mut(&mut m)
    });
    time_step!("copy_prop", { wilt::passes::copy_prop::apply_mut(&mut m) });
    time_step!("branch_threading", {
        wilt::passes::branch_threading::apply_mut(&mut m)
    });
    time_step!("if_fold", { wilt::passes::if_fold::apply_mut(&mut m) });
    time_step!("vacuum", { wilt::passes::vacuum::apply_mut(&mut m) });
    time_step!("cfg_dce", { wilt::passes::cfg_dce::apply_mut(&mut m) });
    time_step!("remove_unused_brs", {
        wilt::passes::remove_unused_brs::apply_mut(&mut m)
    });
    time_step!("merge_blocks", {
        wilt::passes::merge_blocks::apply_mut(&mut m)
    });
    time_step!("simplify_locals", {
        wilt::passes::simplify_locals::apply_mut(&mut m)
    });
    time_step!("fn_merge", { wilt::passes::fn_merge::apply_mut(&mut m) });
    time_step!("inline_trivial", {
        wilt::passes::inline_trivial::apply_mut(&mut m)
    });
    time_step!("reorder_locals", {
        wilt::passes::reorder_locals::apply_mut(&mut m)
    });
    time_step!("memory_packing", {
        wilt::passes::memory_packing::apply_mut(&mut m)
    });
    let mid = time_step!("serialize", { m.serialize() });

    let after_ud = time_step!("unused_data", {
        let mut m = WasmModule::parse(&mid).unwrap();
        wilt::passes::unused_data::apply(&mut m)
    });
    let after_ue = time_step!("unused_elem", {
        let mut m = WasmModule::parse(&after_ud).unwrap();
        wilt::passes::unused_elem::apply(&mut m)
    });
    let after_reorder = time_step!("reorder", {
        let mut m = WasmModule::parse(&after_ue).unwrap();
        wilt::passes::reorder::apply(&mut m)
    });
    let _after_layout = time_step!("layout_for_compression", {
        let mut m = WasmModule::parse(&after_reorder).unwrap();
        wilt::passes::layout_for_compression::apply(&mut m)
    });
}

#[test]
#[ignore]
fn full_optimise() {
    let bytes = std::fs::read("/tmp/big.wasm").unwrap();
    let t0 = Instant::now();
    let out = wilt::optimise(&bytes);
    println!(
        "full optimise: {} ms, in={} out={}",
        t0.elapsed().as_millis(),
        bytes.len(),
        out.len()
    );
}

#[test]
#[ignore]
fn validate_check() {
    use wasmparser::Validator;
    let bytes = std::fs::read("/tmp/big.wasm").unwrap();
    let t0 = Instant::now();
    let ok = Validator::new().validate_all(&bytes).is_ok();
    println!("input validate: {} ms ok={}", t0.elapsed().as_millis(), ok);
    let out = wilt::optimise(&bytes);
    let t0 = Instant::now();
    let ok2 = Validator::new().validate_all(&out).is_ok();
    println!(
        "output validate: {} ms ok={}",
        t0.elapsed().as_millis(),
        ok2
    );
}
