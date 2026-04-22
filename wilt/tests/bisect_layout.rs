use wasmparser::Validator;
use wilt::module::WasmModule;

fn validates(b: &[u8]) -> Result<(), String> {
    Validator::new()
        .validate_all(b)
        .map_err(|e| e.to_string())
        .map(|_| ())
}

#[test]
#[ignore]
fn debug_string_lifting() {
    let path = "/Users/gilescope/git/gilescope/wild/external_test_suites/binaryen/test/lit/passes/string-lifting.wast";
    let src = std::fs::read_to_string(path).unwrap();
    let bytes = wat::parse_str(&src).unwrap();
    println!("input {} bytes — {:?}", bytes.len(), validates(&bytes));

    // Run optimise and check.
    let after_full = wilt::optimise(&bytes);
    println!(
        "after_full {} bytes — {:?}",
        after_full.len(),
        validates(&after_full)
    );
    std::fs::write("/tmp/wilt_layout_out.wasm", &after_full).ok();

    // Layout in isolation.
    let mut wm = WasmModule::parse(&bytes).unwrap();
    let after_layout = wilt::passes::layout_for_compression::apply(&mut wm);
    println!(
        "after_layout (bare input) {} bytes — {:?}",
        after_layout.len(),
        validates(&after_layout)
    );
    std::fs::write("/tmp/wilt_layout_alone.wasm", &after_layout).ok();

    // Diff the input vs layout output bytes.
    let mut diffs = Vec::new();
    for i in 0..bytes.len().min(after_layout.len()) {
        if bytes[i] != after_layout[i] {
            diffs.push((i, bytes[i], after_layout[i]));
            if diffs.len() > 30 {
                break;
            }
        }
    }
    println!("first {} byte diffs: {:?}", diffs.len(), diffs);
}
