//! Copy-on-write wrapper over a WasmModule. Unchanged sections and
//! function bodies stay as slices into the input mmap; passes only
//! allocate when they modify something. One serialize at the end stitches
//! everything into the final output.
//!
//! Invariant: section boundaries are stable across passes. Passes change
//! payload contents, not section identity. `remove_section` marks an entry
//! as dead (serialize skips it).

use std::collections::HashMap;

use crate::leb128;
use crate::module::{self, FunctionBody, Section, WasmModule};

/// Reusable scratch buffer. A single instance per pipeline; passes clear
/// and reuse it instead of allocating fresh Vecs per body.
#[derive(Default)]
pub struct Scratch {
    pub buf: Vec<u8>,
}

impl Scratch {
    pub fn take(&mut self) -> Vec<u8> {
        let mut v = std::mem::take(&mut self.buf);
        v.clear();
        v
    }
    pub fn give_back(&mut self, mut v: Vec<u8>) {
        v.clear();
        if v.capacity() > self.buf.capacity() {
            self.buf = v;
        }
    }
}

/// Facts computed once per fixpoint iteration; shared by all passes.
#[derive(Default, Clone)]
pub struct ModuleFacts {
    pub num_func_imports: u32,
    pub exported_func_indices: Vec<u32>,
    pub start_func: Option<u32>,
}

pub struct MutModule<'a> {
    input: &'a [u8],
    /// Section boundaries derived from `input` at construction.
    sections: Vec<Section>,
    /// One slot per section: None = use input slice; Some = override payload.
    section_overrides: Vec<Option<Vec<u8>>>,
    /// Marks a section as removed from output.
    section_removed: Vec<bool>,
    /// Parsed function bodies (indexes into input, same as WasmModule).
    bodies: Vec<FunctionBody>,
    /// One slot per defined function body; None = still in input.
    /// Lazily grown on first `set_body`.
    body_overrides: Vec<Option<Vec<u8>>>,
    pub facts: ModuleFacts,
    pub scratch: Scratch,
}

impl<'a> MutModule<'a> {
    pub fn new(input: &'a [u8]) -> Result<Self, &'static str> {
        let m = WasmModule::parse(input)?;
        let sections: Vec<Section> = m.sections().to_vec();
        let mut tmp = WasmModule::parse(input)?;
        tmp.ensure_function_bodies_parsed();
        let bodies: Vec<FunctionBody> = tmp.function_bodies().to_vec();

        let facts = compute_facts(input, &sections, &bodies);

        let section_overrides = vec![None; sections.len()];
        let section_removed = vec![false; sections.len()];
        let body_overrides = vec![None; bodies.len()];

        Ok(Self {
            input, sections, section_overrides, section_removed,
            bodies, body_overrides, facts, scratch: Scratch::default(),
        })
    }

    pub fn input(&self) -> &'a [u8] { self.input }
    pub fn sections(&self) -> &[Section] { &self.sections }
    pub fn num_bodies(&self) -> usize { self.bodies.len() }
    pub fn body_spans(&self) -> &[FunctionBody] { &self.bodies }

    /// Find the index of the first section with the given id.
    pub fn find_section(&self, id: u8) -> Option<usize> {
        self.sections.iter().position(|s| s.id == id)
    }

    /// The current bytes for a section's payload — override if present,
    /// otherwise a slice of the input mmap.
    pub fn section_payload(&self, sec_idx: usize) -> &[u8] {
        if let Some(Some(buf)) = self.section_overrides.get(sec_idx) {
            return buf;
        }
        let sec = &self.sections[sec_idx];
        sec.payload.slice(self.input)
    }

    pub fn set_section_payload(&mut self, sec_idx: usize, payload: Vec<u8>) {
        self.section_overrides[sec_idx] = Some(payload);
        self.section_removed[sec_idx] = false;
    }

    pub fn remove_section(&mut self, sec_idx: usize) {
        self.section_removed[sec_idx] = true;
    }

    /// Body bytes (without the body-size LEB prefix) for the given defined
    /// function index.
    pub fn body_bytes(&self, local_idx: usize) -> &[u8] {
        if let Some(buf) = self.body_overrides.get(local_idx).and_then(|x| x.as_ref()) {
            return buf;
        }
        self.bodies[local_idx].body.slice(self.input)
    }

    pub fn set_body(&mut self, local_idx: usize, bytes: Vec<u8>) {
        self.body_overrides[local_idx] = Some(bytes);
    }

    /// A cheap hash of which sections / bodies have been overridden. Used
    /// to detect fixpoint without reserialising.
    pub fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (i, o) in self.section_overrides.iter().enumerate() {
            if self.section_removed[i] {
                ("rm", i).hash(&mut h);
            }
            if let Some(v) = o {
                ("sec", i, v.len(), v.first(), v.last()).hash(&mut h);
            }
        }
        for (i, o) in self.body_overrides.iter().enumerate() {
            if let Some(v) = o {
                ("body", i, v.len(), v.first(), v.last()).hash(&mut h);
            }
        }
        h.finish()
    }

    /// Produce the final serialised module. Consumes self so the caller can't
    /// accidentally re-emit.
    pub fn serialize(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.input.len());
        out.extend_from_slice(&self.input[..8]); // header

        // If any function body has been overridden, we must emit a new code
        // section payload from the stitched body vec. Build that here.
        let code_payload: Option<Vec<u8>> = if self.body_overrides.iter().any(|o| o.is_some()) {
            Some(build_code_section(&self.bodies, &self.body_overrides, self.input))
        } else {
            None
        };

        for (idx, section) in self.sections.iter().enumerate() {
            if self.section_removed[idx] { continue; }

            if section.id == module::SECTION_CODE {
                if let Some(buf) = &code_payload {
                    out.push(section.id);
                    leb128::write_u32(&mut out, buf.len() as u32);
                    out.extend_from_slice(buf);
                    continue;
                }
            }
            if let Some(buf) = &self.section_overrides[idx] {
                out.push(section.id);
                leb128::write_u32(&mut out, buf.len() as u32);
                out.extend_from_slice(buf);
            } else {
                out.extend_from_slice(section.full.slice(self.input));
            }
        }
        out
    }
}

fn build_code_section(bodies: &[FunctionBody], overrides: &[Option<Vec<u8>>], input: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    leb128::write_u32(&mut payload, bodies.len() as u32);
    for (i, body) in bodies.iter().enumerate() {
        let bytes: &[u8] = match overrides.get(i).and_then(|o| o.as_ref()) {
            Some(v) => v,
            None => body.body.slice(input),
        };
        leb128::write_u32(&mut payload, bytes.len() as u32);
        payload.extend_from_slice(bytes);
    }
    payload
}

fn compute_facts(input: &[u8], sections: &[Section], _bodies: &[FunctionBody]) -> ModuleFacts {
    let mut f = ModuleFacts::default();
    // num_func_imports
    if let Some(sec) = sections.iter().find(|s| s.id == module::SECTION_IMPORT) {
        let p = sec.payload.slice(input);
        if let Some((count, mut off)) = leb128::read_u32(p) {
            for _ in 0..count {
                let Some((l, c)) = leb128::read_u32(&p[off..]) else { break };
                off += c + l as usize; if off > p.len() { break; }
                let Some((l, c)) = leb128::read_u32(&p[off..]) else { break };
                off += c + l as usize; if off >= p.len() { break; }
                let kind = p[off]; off += 1;
                match kind {
                    0x00 => {
                        if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; f.num_func_imports += 1; } else { break; }
                    }
                    0x01 => {
                        if off >= p.len() { break; }
                        off += 1;
                        if off >= p.len() { break; }
                        let flags = p[off]; off += 1;
                        if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { break; }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { break; }
                        }
                    }
                    0x02 => {
                        if off >= p.len() { break; }
                        let flags = p[off]; off += 1;
                        if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { break; }
                        if flags & 1 != 0 {
                            if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { break; }
                        }
                    }
                    0x03 => { off += 2; }
                    0x04 => {
                        off += 1;
                        if let Some((_, c)) = leb128::read_u32(&p[off..]) { off += c; } else { break; }
                    }
                    _ => break,
                }
            }
        }
    }

    // exported function indices
    if let Some(sec) = sections.iter().find(|s| s.id == module::SECTION_EXPORT) {
        let p = sec.payload.slice(input);
        if let Some((count, mut off)) = leb128::read_u32(p) {
            for _ in 0..count {
                let Some((nl, c)) = leb128::read_u32(&p[off..]) else { break };
                off += c + nl as usize;
                if off >= p.len() { break; }
                let kind = p[off]; off += 1;
                let Some((idx, c)) = leb128::read_u32(&p[off..]) else { break };
                off += c;
                if kind == 0x00 { f.exported_func_indices.push(idx); }
            }
        }
    }

    // start function
    if let Some(sec) = sections.iter().find(|s| s.id == module::SECTION_START) {
        let p = sec.payload.slice(input);
        if let Some((idx, _)) = leb128::read_u32(p) { f.start_func = Some(idx); }
    }

    f
}

// Suppress unused-import lint for HashMap (will be used by later passes).
#[allow(dead_code)]
fn _compile_check(_: HashMap<u32, u32>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample_module() -> Vec<u8> {
        let mut data = b"\0asm\x01\x00\x00\x00".to_vec();
        data.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]); // type () -> ()
        data.extend_from_slice(&[3, 2, 1, 0]);           // func section: 1 func
        data.extend_from_slice(&[7, 5, 1, 1, b'f', 0x00, 0]); // export
        data.extend_from_slice(&[10, 4, 1, 2, 0, 0x0B]); // code
        data
    }

    #[test]
    fn roundtrip_unchanged() {
        let data = build_sample_module();
        let m = MutModule::new(&data).unwrap();
        let out = m.serialize();
        assert_eq!(out, data);
    }

    #[test]
    fn override_body_and_serialize() {
        let data = build_sample_module();
        let mut m = MutModule::new(&data).unwrap();
        // Replace body with one containing a nop so the output differs.
        m.set_body(0, vec![0, 0x01, 0x0B]);
        let out = m.serialize();
        WasmModule::parse(&out).unwrap();
        assert_ne!(out, data);
    }

    #[test]
    fn facts_populated() {
        let data = build_sample_module();
        let m = MutModule::new(&data).unwrap();
        assert_eq!(m.facts.num_func_imports, 0);
        assert_eq!(m.facts.exported_func_indices, vec![0]);
        assert_eq!(m.facts.start_func, None);
    }
}
