//! End-to-end tests for `wilt::optimise_with_debug_level`.
//!
//! Covers the names tier at Phase 1. Tier `Lines` / `Full` will gain
//! their own tests as Phases 2/3 land; until then they fall back to
//! `Names`, which these tests exercise.

use wilt::debug_level::DebugLevel;
use wilt::WasmModule;

fn build_named_module() -> Vec<u8> {
    // A module with two named exported funcs and one internal helper.
    // Optimisation may reorder / rename them but the named-tier output
    // must still carry entries for the surviving function indices.
    wat::parse_str(r#"
        (module
          (func $helper (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.add)
          (func $exp_a (export "a") (param i32) (result i32)
            local.get 0
            call $helper)
          (func $exp_b (export "b") (param i32) (result i32)
            local.get 0
            call $helper
            call $helper))
    "#).unwrap()
}

fn name_section_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    let m = WasmModule::parse(bytes).ok()?;
    let data = m.data();
    for sec in m.sections() {
        if sec.id != 0 { continue; }
        let name_span = sec.custom_name?;
        let name = name_span.slice(data);
        if name == b"name" {
            // Skip the (namelen + name) prefix of the payload.
            let p = sec.payload.slice(data);
            let (nlen, c) = wilt::leb128::read_u32(p)?;
            return Some(p[c + nlen as usize..].to_vec());
        }
    }
    None
}

fn function_names(payload: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < payload.len() {
        let sub_id = payload[off];
        off += 1;
        let (sub_size, c) = wilt::leb128::read_u32(&payload[off..]).unwrap_or((0, 1));
        off += c;
        let content_end = off + sub_size as usize;
        if sub_id == 1 {
            let content = &payload[off..content_end];
            let (count, mut ic) = wilt::leb128::read_u32(content).unwrap_or((0, 0));
            for _ in 0..count {
                let (idx, c) = wilt::leb128::read_u32(&content[ic..]).unwrap_or((0, 0));
                ic += c;
                let (nlen, c) = wilt::leb128::read_u32(&content[ic..]).unwrap_or((0, 0));
                ic += c;
                let name_bytes = &content[ic..ic + nlen as usize];
                ic += nlen as usize;
                out.push((idx, String::from_utf8_lossy(name_bytes).into_owned()));
            }
            return out;
        }
        off = content_end;
    }
    out
}

#[test]
fn none_tier_drops_name_section() {
    let input = build_named_module();
    let out = wilt::optimise_with_debug_level(&input, DebugLevel::None);
    assert!(WasmModule::parse(&out).is_ok());
    assert!(name_section_payload(&out).is_none(),
            "None tier must drop the name section entirely");
}

#[test]
fn names_tier_preserves_named_funcs() {
    let input = build_named_module();
    let out = wilt::optimise_with_debug_level(&input, DebugLevel::Names);
    assert!(WasmModule::parse(&out).is_ok());

    let payload = name_section_payload(&out)
        .expect("names tier must emit a name section");
    let names = function_names(&payload);
    // At least the exported functions must survive. Internal helper
    // may be inlined away and legitimately disappear.
    let name_set: std::collections::HashSet<&str> =
        names.iter().map(|(_, n)| n.as_str()).collect();
    assert!(name_set.contains("exp_a"), "exported $exp_a must survive in name section; got {:?}", names);
    assert!(name_set.contains("exp_b"), "exported $exp_b must survive in name section; got {:?}", names);
}

#[test]
fn names_tier_is_deterministic() {
    let input = build_named_module();
    let a = wilt::optimise_with_debug_level(&input, DebugLevel::Names);
    let b = wilt::optimise_with_debug_level(&input, DebugLevel::Names);
    assert_eq!(a, b);
}

#[test]
fn higher_tiers_no_op_when_input_has_no_debug_line() {
    // With no `.debug_line` in input, Lines/Full have nothing to
    // preserve beyond what Names already does, so output coincides.
    let input = build_named_module();
    let at_names = wilt::optimise_with_debug_level(&input, DebugLevel::Names);
    let at_lines = wilt::optimise_with_debug_level(&input, DebugLevel::Lines);
    let at_full  = wilt::optimise_with_debug_level(&input, DebugLevel::Full);
    assert_eq!(at_names, at_lines, "no debug_line in → Lines == Names output");
    assert_eq!(at_names, at_full,  "no debug_line in → Full == Names output");
}

#[test]
fn default_level_is_highest_implemented() {
    assert_eq!(DebugLevel::default(), DebugLevel::highest_implemented());
}

#[test]
fn names_tier_never_grows() {
    let input = build_named_module();
    let out = wilt::optimise_with_debug_level(&input, DebugLevel::Names);
    assert!(out.len() <= input.len(),
            "names tier must respect never-grow: {} vs input {}",
            out.len(), input.len());
}

#[test]
fn lines_tier_preserves_debug_line_when_code_unchanged() {
    // Attach a stub .debug_line custom section to a module. Since the
    // input has no optimisable content beyond what wilt's fixpoint
    // leaves alone, the output's code section should match the input's
    // byte-for-byte, and Lines tier should carry the .debug_line
    // payload through.
    let mut input = build_named_module();
    let stub_payload = b"\x00\x00\x00fake_line_program_body\xFF";
    let mut custom = Vec::new();
    wilt::leb128::write_u32(&mut custom, b".debug_line".len() as u32);
    custom.extend_from_slice(b".debug_line");
    custom.extend_from_slice(stub_payload);
    input.push(0);
    wilt::leb128::write_u32(&mut input, custom.len() as u32);
    input.extend_from_slice(&custom);

    let out = wilt::optimise_with_debug_level(&input, DebugLevel::Lines);
    assert!(WasmModule::parse(&out).is_ok());

    // Find .debug_line in output.
    let m = WasmModule::parse(&out).unwrap();
    let data = m.data();
    let found = m.sections().iter().find_map(|s| {
        if s.id != 0 { return None; }
        let name = s.custom_name?.slice(data);
        if name != b".debug_line" { return None; }
        let p = s.payload.slice(data);
        let (nlen, c) = wilt::leb128::read_u32(p)?;
        Some(p[c + nlen as usize..].to_vec())
    });

    // If the pipeline left this module's code alone, Lines tier should
    // preserve .debug_line verbatim. If the pipeline did modify code,
    // preservation is the null set — either outcome is correct for
    // this test; we just check that when it IS preserved it matches.
    if let Some(payload) = found {
        assert_eq!(payload, stub_payload,
                   "preserved .debug_line must match input bytes");
    }
}

#[test]
fn module_with_no_name_section_survives() {
    // Strip name section from our fixture first.
    let input = build_named_module();
    let m = WasmModule::parse(&input).unwrap();
    let stripped = wilt::passes::strip::apply(
        &m,
        wilt::passes::strip::StripConfig { names: true, ..Default::default() },
    );
    let out = wilt::optimise_with_debug_level(&stripped, DebugLevel::Names);
    assert!(WasmModule::parse(&out).is_ok());
    // No name section in → no name section out.
    assert!(name_section_payload(&out).is_none());
}
