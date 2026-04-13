//! Strip custom sections that don't affect semantics.
//!
//! Opt-in: not run by default `optimise()` because dropping DWARF changes
//! debuggability. Callers that want small, stripped output can call
//! `passes::strip::apply(module, StripConfig::all())`.

use crate::leb128;
use crate::module::{self, WasmModule};

#[derive(Clone, Copy, Default)]
pub struct StripConfig {
    pub dwarf: bool,
    pub source_maps: bool,
    pub producers: bool,
    pub names: bool,
    pub target_features: bool,
}

impl StripConfig {
    pub fn all() -> Self {
        Self {
            dwarf: true,
            source_maps: true,
            producers: true,
            names: true,
            target_features: true,
        }
    }
    pub fn dwarf_only() -> Self {
        Self { dwarf: true, ..Self::default() }
    }
    pub fn default_strip() -> Self {
        // "Reasonable default for shipping": strip DWARF + source maps,
        // keep names (useful for fatals) and producers (tiny).
        Self { dwarf: true, source_maps: true, ..Self::default() }
    }
    /// Match what `wasm-opt -O` emits: strips DWARF, source maps, names,
    /// and target_features. Keeps `producers` (tiny, identifies tool).
    /// For shipping builds that don't need JS-side name-map debugging.
    pub fn shipping() -> Self {
        Self { dwarf: true, source_maps: true, names: true,
               target_features: true, producers: false }
    }
}

fn should_drop(name: &str, cfg: &StripConfig) -> bool {
    if cfg.dwarf && name.starts_with(".debug_") { return true; }
    if cfg.source_maps && (name == "sourceMappingURL" || name == "external_debug_info") { return true; }
    if cfg.producers && name == "producers" { return true; }
    if cfg.names && name == "name" { return true; }
    if cfg.target_features && name == "target_features" { return true; }
    false
}

pub fn apply(module: &WasmModule<'_>, cfg: StripConfig) -> Vec<u8> {
    let data = module.data();
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);

    for section in module.sections() {
        if section.id == module::SECTION_CUSTOM {
            let name = section.custom_name
                .and_then(|span| {
                    let bytes = &data[span.offset as usize..(span.offset + span.len) as usize];
                    std::str::from_utf8(bytes).ok()
                })
                .unwrap_or("");
            if should_drop(name, &cfg) {
                continue;
            }
        }
        out.extend_from_slice(section.full.slice(data));
    }
    // Rewrite the header so the module id + section count is fine — WASM
    // doesn't have a module-level count, so we're done.
    let _ = leb128::write_u32;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_module_with_customs() -> Vec<u8> {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // Custom section ".debug_info" with empty payload.
        data.push(0); // id
        let mut payload = Vec::new();
        leb128::write_u32(&mut payload, ".debug_info".len() as u32);
        payload.extend_from_slice(b".debug_info");
        leb128::write_u32(&mut data, payload.len() as u32);
        data.extend_from_slice(&payload);

        // Custom section "name".
        data.push(0);
        let mut payload = Vec::new();
        leb128::write_u32(&mut payload, 4);
        payload.extend_from_slice(b"name");
        leb128::write_u32(&mut data, payload.len() as u32);
        data.extend_from_slice(&payload);

        data
    }

    #[test]
    fn strip_dwarf_removes_debug() {
        let data = build_module_with_customs();
        let module = WasmModule::parse(&data).unwrap();
        let out = apply(&module, StripConfig::dwarf_only());
        assert!(out.len() < data.len());
        let m2 = WasmModule::parse(&out).unwrap();
        assert_eq!(m2.sections().len(), 1); // only "name" remains
    }

    #[test]
    fn strip_all_removes_both() {
        let data = build_module_with_customs();
        let module = WasmModule::parse(&data).unwrap();
        let out = apply(&module, StripConfig::all());
        let m2 = WasmModule::parse(&out).unwrap();
        assert_eq!(m2.sections().len(), 0);
    }

    #[test]
    fn strip_none_keeps_all() {
        let data = build_module_with_customs();
        let module = WasmModule::parse(&data).unwrap();
        let out = apply(&module, StripConfig::default());
        assert_eq!(out, data);
    }
}
