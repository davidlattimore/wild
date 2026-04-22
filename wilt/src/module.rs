/// Zero-copy WASM module representation.
///
/// `WasmModule` borrows from the input buffer and only records
/// section boundaries — no per-instruction allocation.
use crate::leb128;

/// WASM section IDs (spec ordering).
pub const SECTION_CUSTOM: u8 = 0;
pub const SECTION_TYPE: u8 = 1;
pub const SECTION_IMPORT: u8 = 2;
pub const SECTION_FUNCTION: u8 = 3;
pub const SECTION_TABLE: u8 = 4;
pub const SECTION_MEMORY: u8 = 5;
pub const SECTION_GLOBAL: u8 = 6;
pub const SECTION_EXPORT: u8 = 7;
pub const SECTION_START: u8 = 8;
pub const SECTION_ELEMENT: u8 = 9;
pub const SECTION_CODE: u8 = 10;
pub const SECTION_DATA: u8 = 11;
pub const SECTION_DATACOUNT: u8 = 12;

/// A byte range into the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub offset: u32,
    pub len: u32,
}

impl Span {
    /// Get the byte slice from the parent buffer.
    pub fn slice<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.offset as usize..(self.offset + self.len) as usize]
    }
}

/// A section in the WASM module.
#[derive(Debug, Clone)]
pub struct Section {
    pub id: u8,
    /// Span of the payload (after the id + size LEB).
    pub payload: Span,
    /// Span of the entire section (including id + size LEB).
    pub full: Span,
    /// For custom sections: the name (offset + length within payload).
    pub custom_name: Option<Span>,
}

/// A function body within the code section.
#[derive(Debug, Clone, Copy)]
pub struct FunctionBody {
    /// Span of the entire body including the body-size LEB.
    pub full: Span,
    /// Span of just the body bytes (after the body-size LEB).
    pub body: Span,
}

/// A parsed WASM module that borrows from the input buffer.
/// Zero-copy: only stores offsets, never copies section data.
pub struct WasmModule<'a> {
    data: &'a [u8],
    sections: Vec<Section>,
    /// Lazily parsed function bodies.
    function_bodies: Option<Vec<FunctionBody>>,
}

impl<'a> WasmModule<'a> {
    /// Parse a WASM module from a byte buffer.
    /// Only scans section boundaries — O(sections), not O(instructions).
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("too short for WASM header");
        }
        if &data[..4] != b"\0asm" {
            return Err("bad WASM magic");
        }
        if data[4..8] != [1, 0, 0, 0] {
            return Err("unsupported WASM version");
        }

        let mut sections = Vec::new();
        let mut pos = 8;

        while pos < data.len() {
            let section_start = pos;
            let id = data[pos];
            pos += 1;

            let (size, consumed) = leb128::read_u32(&data[pos..]).ok_or("bad section size")?;
            pos += consumed;

            let payload_offset = pos as u32;
            let payload_len = size;

            if pos + size as usize > data.len() {
                return Err("section extends past end of file");
            }

            let mut custom_name = None;
            if id == SECTION_CUSTOM {
                // Parse custom section name.
                if let Some((name_len, name_consumed)) =
                    leb128::read_u32(&data[pos..pos + size as usize])
                {
                    custom_name = Some(Span {
                        offset: (pos + name_consumed) as u32,
                        len: name_len,
                    });
                }
            }

            sections.push(Section {
                id,
                payload: Span {
                    offset: payload_offset,
                    len: payload_len,
                },
                full: Span {
                    offset: section_start as u32,
                    len: (pos + size as usize - section_start) as u32,
                },
                custom_name,
            });

            pos += size as usize;
        }

        if pos != data.len() {
            return Err("trailing bytes after last section");
        }

        Ok(WasmModule {
            data,
            sections,
            function_bodies: None,
        })
    }

    /// The raw input bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// All sections.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Find the first section with the given ID.
    pub fn section(&self, id: u8) -> Option<&Section> {
        self.sections.iter().find(|s| s.id == id)
    }

    /// Ensure function bodies are parsed (triggers lazy parse).
    pub fn ensure_function_bodies_parsed(&mut self) {
        if self.function_bodies.is_none() {
            self.function_bodies = Some(self.parse_function_bodies());
        }
    }

    /// Get function bodies (must call ensure_function_bodies_parsed first).
    pub fn function_bodies(&self) -> &[FunctionBody] {
        self.function_bodies.as_ref().map_or(&[], |v| v.as_slice())
    }

    /// Number of function bodies.
    pub fn num_function_bodies(&self) -> usize {
        self.function_bodies.as_ref().map_or(0, |v| v.len())
    }

    fn parse_function_bodies(&self) -> Vec<FunctionBody> {
        let Some(code) = self.section(SECTION_CODE) else {
            return Vec::new();
        };

        let payload = code.payload.slice(self.data);
        let Some((count, mut off)) = leb128::read_u32(payload) else {
            return Vec::new();
        };

        let mut bodies = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let full_start = code.payload.offset + off as u32;
            let Some((body_size, size_consumed)) = leb128::read_u32(&payload[off..]) else {
                break;
            };
            off += size_consumed;
            let body_start = code.payload.offset + off as u32;

            bodies.push(FunctionBody {
                full: Span {
                    offset: full_start,
                    len: (size_consumed + body_size as usize) as u32,
                },
                body: Span {
                    offset: body_start,
                    len: body_size,
                },
            });

            off += body_size as usize;
        }
        bodies
    }

    /// Get exported function indices (GC roots).
    pub fn exported_function_indices(&self) -> Vec<u32> {
        let Some(export) = self.section(SECTION_EXPORT) else {
            return Vec::new();
        };
        let payload = export.payload.slice(self.data);
        let Some((count, mut off)) = leb128::read_u32(payload) else {
            return Vec::new();
        };
        let mut indices = Vec::new();
        for _ in 0..count {
            // name
            let Some((name_len, c)) = leb128::read_u32(&payload[off..]) else {
                break;
            };
            off += c + name_len as usize;
            // kind
            if off >= payload.len() {
                break;
            }
            let kind = payload[off];
            off += 1;
            // index
            let Some((index, c)) = leb128::read_u32(&payload[off..]) else {
                break;
            };
            off += c;
            if kind == 0x00 {
                // function export
                indices.push(index);
            }
        }
        indices
    }

    /// Get the start function index (if any).
    pub fn start_function(&self) -> Option<u32> {
        let start = self.section(SECTION_START)?;
        let payload = start.payload.slice(self.data);
        leb128::read_u32(payload).map(|(idx, _)| idx)
    }

    /// Get function count from the function section.
    pub fn function_count(&self) -> u32 {
        let Some(func) = self.section(SECTION_FUNCTION) else {
            return 0;
        };
        let payload = func.payload.slice(self.data);
        leb128::read_u32(payload)
            .map(|(count, _)| count)
            .unwrap_or(0)
    }

    /// Total size of the module in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Number of sections.
    pub fn num_sections(&self) -> usize {
        self.sections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid WASM module (just the header).
    const EMPTY_MODULE: &[u8] = b"\0asm\x01\x00\x00\x00";

    #[test]
    fn parse_empty_module() {
        let module = WasmModule::parse(EMPTY_MODULE).unwrap();
        assert_eq!(module.num_sections(), 0);
        assert_eq!(module.size(), 8);
    }

    #[test]
    fn parse_with_type_section() {
        // Type section: 1 type, func () -> ()
        let mut data = EMPTY_MODULE.to_vec();
        data.push(SECTION_TYPE); // section id
        data.push(4); // payload size
        data.extend_from_slice(&[1, 0x60, 0, 0]); // 1 func type, 0 params, 0 results

        let module = WasmModule::parse(&data).unwrap();
        assert_eq!(module.num_sections(), 1);
        let sec = module.section(SECTION_TYPE).unwrap();
        assert_eq!(sec.id, SECTION_TYPE);
        assert_eq!(sec.payload.len, 4);
    }

    #[test]
    fn bad_magic() {
        let data = b"\0elf\x01\x00\x00\x00";
        assert!(WasmModule::parse(data).is_err());
    }

    #[test]
    fn truncated() {
        assert!(WasmModule::parse(b"\0asm").is_err());
    }
}
