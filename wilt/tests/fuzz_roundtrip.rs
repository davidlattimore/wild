//! Property test: for any structurally-valid wasm module produced by
//! wasm-smith, `wilt::optimise` must (a) not panic and (b) produce a
//! module that still validates.

use arbitrary::Unstructured;
use proptest::prelude::*;
use wasm_smith::{Config, Module};
use wasmparser::Validator;

fn validates(bytes: &[u8]) -> bool {
    Validator::new().validate_all(bytes).is_ok()
}

/// Constrain wasm-smith to the feature subset wilt claims to handle:
/// MVP + multi-value + SIMD + bulk-memory + mutable-globals.
/// Anything outside this set (GC, typed function refs, exceptions,
/// threads, memory64, tail-call) would exercise valtype encodings
/// wilt's decoder intentionally bails on.
fn smith_config() -> Config {
    Config {
        gc_enabled: false,
        reference_types_enabled: false,
        exceptions_enabled: false,
        threads_enabled: false,
        memory64_enabled: false,
        tail_call_enabled: false,
        custom_page_sizes_enabled: false,
        wide_arithmetic_enabled: false,
        extended_const_enabled: false,
        relaxed_simd_enabled: false,
        shared_everything_threads_enabled: false,
        simd_enabled: true,
        multi_value_enabled: true,
        bulk_memory_enabled: true,
        ..Config::default()
    }
}

fn smith_module(seed: &[u8]) -> Option<Vec<u8>> {
    let mut u = Unstructured::new(seed);
    Module::new(smith_config(), &mut u).ok().map(|m| m.to_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 64,
        .. ProptestConfig::default()
    })]

    #[test]
    fn optimise_preserves_validity(seed in prop::collection::vec(any::<u8>(), 64..4096)) {
        let Some(input) = smith_module(&seed) else { return Ok(()); };
        prop_assume!(validates(&input));
        let output = wilt::optimise(&input);
        if !validates(&output) {
            let err = Validator::new().validate_all(&output).err()
                .map(|e| e.to_string()).unwrap_or_default();
            std::fs::write("/tmp/wilt_fuzz_in.wasm", &input).ok();
            std::fs::write("/tmp/wilt_fuzz_out.wasm", &output).ok();
            prop_assert!(false,
                "wilt produced invalid module ({} -> {} bytes): {}",
                input.len(), output.len(), err);
        }
    }
}
