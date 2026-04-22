/// Output emitter — copies unchanged sections from the original,
/// splices in modifications where needed.
use crate::module::WasmModule;

/// Emit a WASM module unchanged (roundtrip).
/// This is the baseline: the output should be byte-identical to the input.
pub fn emit_unchanged(module: &WasmModule<'_>) -> Vec<u8> {
    // For a pure roundtrip, just copy the entire buffer.
    // In the future, optimised emit will selectively copy/replace.
    module.data().to_vec()
}

/// Emit a WASM module, replacing specific sections.
/// `replacements` maps section index → new payload bytes.
/// Sections not in the map are copied verbatim from the original.
pub fn emit_with_replacements(
    module: &WasmModule<'_>,
    replacements: &std::collections::HashMap<usize, Vec<u8>>,
) -> Vec<u8> {
    let data = module.data();
    let mut out = Vec::with_capacity(data.len());

    // Header.
    out.extend_from_slice(&data[..8]);

    // Sections.
    for (idx, section) in module.sections().iter().enumerate() {
        if let Some(new_payload) = replacements.get(&idx) {
            // Write section with replacement payload.
            out.push(section.id);
            crate::leb128::write_u32(&mut out, new_payload.len() as u32);
            out.extend_from_slice(new_payload);
        } else {
            // Copy section verbatim from original — zero-copy in spirit,
            // memcpy in practice (output is a new Vec).
            let section_bytes = section.full.slice(data);
            out.extend_from_slice(section_bytes);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let data = b"\0asm\x01\x00\x00\x00";
        let module = WasmModule::parse(data).unwrap();
        assert_eq!(emit_unchanged(&module), data);
    }

    #[test]
    fn roundtrip_with_sections() {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        // Type section
        data.push(1); // id
        data.push(4); // size
        data.extend_from_slice(&[1, 0x60, 0, 0]);
        // Function section
        data.push(3); // id
        data.push(2); // size
        data.extend_from_slice(&[1, 0]);

        let module = WasmModule::parse(&data).unwrap();
        assert_eq!(emit_unchanged(&module), data);
    }
}
