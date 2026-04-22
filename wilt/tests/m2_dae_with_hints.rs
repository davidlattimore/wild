//! M2 contract test: hint-aware DAE strictly dominates standalone DAE.
//!
//! Standalone wilt assumes the open world — `$helper` looks externally
//! callable (its caller is exported, but `$helper` itself isn't, so it
//! actually IS DAE-able by today's rules; this fixture is structured so
//! the standalone pass also processes it). The contract M2 promises is:
//! when hints are supplied, the result is identical-or-better — never
//! worse — than the standalone result. The test below pins that
//! invariant.

use wasmparser::Validator;
use wilt::linker_hints::testing::FixedHints;

fn assemble(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/regressions/{}",
        env!("CARGO_MANIFEST_DIR"),
        name,
    );
    wat::parse_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn validates(b: &[u8]) -> bool {
    Validator::new().validate_all(b).is_ok()
}

#[test]
fn hints_never_regress_size() {
    let input = assemble("dae_v2_internal_function.wat");
    assert!(validates(&input));

    let plain = wilt::optimise(&input);
    assert!(validates(&plain), "standalone output must validate");

    // Mark $helper (defined func 0 = abs idx 0 since no func imports)
    // as fully internal.
    let mut hints = FixedHints::default();
    hints.internal.insert(0);
    let with = wilt::optimise_with_hints(&input, &hints);
    assert!(validates(&with), "hint-aware output must validate");

    // Contract: hints must never produce a larger module than standalone.
    assert!(
        with.len() <= plain.len(),
        "hint-aware DAE regressed size: standalone {} vs hints {}",
        plain.len(),
        with.len(),
    );
}

#[test]
fn m6_inliner_v2_single_callsite() {
    // With hints declaring $helper internal AND it has exactly one
    // caller, wilt should inline the body. Without hints, wilt should
    // not (no closed-world guarantee → could grow). Either way the
    // output validates.
    let input = assemble("inliner_v2_single_callsite.wat");
    assert!(validates(&input));

    let plain = wilt::optimise(&input);
    assert!(validates(&plain));

    let mut hints = FixedHints::default();
    // Func 0 is $helper (no imports). Mark internal.
    hints.internal.insert(0);
    let with = wilt::optimise_with_hints(&input, &hints);
    assert!(validates(&with));

    // Hint-aware path must not be larger.
    assert!(
        with.len() <= plain.len(),
        "hint-aware inliner regressed size: standalone {} vs hints {}",
        plain.len(),
        with.len(),
    );
}

#[test]
fn m7_devirt_singleton_table() {
    let input = assemble("devirt_singleton_table.wat");
    assert!(validates(&input));

    let plain = wilt::optimise(&input);
    assert!(validates(&plain));

    // Hint: table 0 has just one target — function index 1 ($target,
    // since $target is defined func 1 with the elem slot 0).
    // Note: $target is index 0 (defined funcs come after imports — none
    // here — so $target=0, $caller=1). The element points at $target=0.
    let mut hints = FixedHints::default();
    hints.tables.insert(0, vec![0]);
    // Mark $target reachable — devirt doesn't need is_internal but
    // downstream passes (DCE) might keep $target as ref.func target.
    hints.ref_funcs.push(0);
    let with = wilt::optimise_with_hints(&input, &hints);
    assert!(validates(&with));
    assert!(
        with.len() <= plain.len(),
        "devirt regressed size: standalone {} vs hints {}",
        plain.len(),
        with.len(),
    );
}

#[test]
fn full_corpus_hints_output_validates() {
    // Every regression fixture: optimise with empty FixedHints (which
    // means "every function is external — assume nothing", strictly more
    // conservative than the standalone quartet). Pin: output always
    // validates regardless of how thin the hints are.
    let dir = format!("{}/tests/fixtures/regressions", env!("CARGO_MANIFEST_DIR"));
    let hints = FixedHints::default();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wat") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let Ok(input) = wat::parse_str(&src) else {
            continue;
        };
        if !validates(&input) {
            continue;
        }
        let with = wilt::optimise_with_hints(&input, &hints);
        assert!(
            validates(&with),
            "hint-aware output failed validation for {}",
            path.display(),
        );
    }
}
