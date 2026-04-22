//! Pinned regression tests.
//!
//! Each case assembles a `.wat` fixture, runs either a targeted pass or
//! the full `wilt::optimise` pipeline, and asserts the output still
//! validates. The fuzz and binaryen corpus cover the same ground
//! stochastically — these fix specific past bugs in place.
//!
//! Fixtures live in `tests/fixtures/regressions/` — one `.wat` per bug
//! with a header comment explaining what it exercises.

use wasmparser::Validator;
use wilt::module::WasmModule;
use wilt::mut_module::MutModule;
use wilt::passes;

fn assemble(path: &str) -> Vec<u8> {
    let full = format!(
        "{}/tests/fixtures/regressions/{}",
        env!("CARGO_MANIFEST_DIR"),
        path,
    );
    let src = std::fs::read_to_string(&full).expect("read .wat");
    wat::parse_str(&src).expect("assemble .wat")
}

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new()
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ───── type_gc: blocktype type-index refs must be remapped ─────

#[test]
fn regression_type_gc_rewrites_block_type_ref() {
    let input = assemble("type_gc_block_type_ref.wat");
    validate(&input).expect("input valid");
    let module = WasmModule::parse(&input).unwrap();
    let out = passes::type_gc::apply(&module);
    validate(&out).expect("type_gc output must validate");
    assert!(
        out.len() < input.len(),
        "type_gc should have removed a type"
    );
}

// ───── type_gc: function-import type indices must be remapped ─────

#[test]
fn regression_type_gc_rewrites_import_type() {
    let input = assemble("type_gc_import_type.wat");
    validate(&input).expect("input valid");
    let module = WasmModule::parse(&input).unwrap();
    let out = passes::type_gc::apply(&module);
    validate(&out).expect("type_gc output must validate");
    assert!(
        out.len() < input.len(),
        "type_gc should have removed the unused type"
    );
}

// ───── DCE must not leave stale call indices in SIMD bodies ─────

#[test]
fn regression_dce_bails_on_simd_body() {
    let input = assemble("dce_skips_simd_body.wat");
    validate(&input).expect("input valid");
    let mut module = WasmModule::parse(&input).unwrap();
    let out = passes::dce::apply(&mut module);
    validate(&out)
        .expect("DCE output must validate — pass must bail rather than leave stale calls");
}

// ───── remove_unused_brs: stack-imbalance case must survive ─────

#[test]
fn regression_remove_br_keeps_when_stack_imbalanced() {
    let input = assemble("remove_br_stack_imbalance.wat");
    validate(&input).expect("input valid");
    let mut m = MutModule::new(&input).unwrap();
    passes::remove_unused_brs::apply_mut(&mut m);
    let out = m.serialize();
    validate(&out).expect("remove_unused_brs must leave stack-imbalanced br alone");
}

// ───── simplify_locals must not infinite-loop on unrelated local ops ─────

#[test]
fn regression_simplify_locals_terminates() {
    let input = assemble("simplify_locals_loop.wat");
    validate(&input).expect("input valid");
    // Bound the run in a separate thread — a regression here would
    // hang indefinitely otherwise.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut m = MutModule::new(&input).unwrap();
        passes::simplify_locals::apply_mut(&mut m);
        let out = m.serialize();
        tx.send(out).ok();
    });
    let out = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("simplify_locals should terminate quickly");
    validate(&out).expect("output valid");
}

// ───── DAE must account for blocktype refs (and parse bodies) ─────

#[test]
fn regression_dae_sees_block_type_refs() {
    let input = assemble("dae_block_type_ref.wat");
    validate(&input).expect("input valid");
    let mut m = MutModule::new(&input).unwrap();
    passes::dae::apply_mut(&mut m);
    let out = m.serialize();
    validate(&out).expect("DAE must spot the loop's blocktype reference to $vt and decline");
}

// ───── full pipeline never corrupts any of these ─────

#[test]
fn regression_full_pipeline_all_fixtures() {
    for name in [
        "type_gc_block_type_ref.wat",
        "type_gc_import_type.wat",
        "dce_skips_simd_body.wat",
        "remove_br_stack_imbalance.wat",
        "simplify_locals_loop.wat",
        "dae_block_type_ref.wat",
    ] {
        let input = assemble(name);
        validate(&input).unwrap_or_else(|e| panic!("input {} invalid: {}", name, e));
        let out = wilt::optimise(&input);
        validate(&out).unwrap_or_else(|e| panic!("{} optimise output invalid: {}", name, e));
    }
}
