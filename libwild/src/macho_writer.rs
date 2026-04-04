// Mach-O output file writer.
//
// Generates a minimal Mach-O executable for aarch64-apple-darwin.
#![allow(dead_code)]

use crate::error::Result;
use crate::layout::Layout;
use crate::macho::MachO;
use crate::platform::Arch;
use crate::platform::Args as _;

/// Page size on Apple Silicon
const PAGE_SIZE: u64 = 0x4000; // 16KB

/// Default size for __PAGEZERO
const PAGEZERO_SIZE: u64 = 0x1_0000_0000; // 4GB

// Mach-O constants
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_EXECUTE: u32 = 2;
const MH_PIE: u32 = 0x0020_0000;
const MH_TWOLEVEL: u32 = 0x80;
const MH_NOUNDEFS: u32 = 1;
const MH_DYLDLINK: u32 = 4;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_LOAD_DYLINKER: u32 = 0x0e;
const LC_LOAD_DYLIB: u32 = 0x0c;
const LC_UUID: u32 = 0x1b;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_SOURCE_VERSION: u32 = 0x2a;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_EXECUTE: u32 = 4;
const S_REGULAR: u32 = 0;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const PLATFORM_MACOS: u32 = 1;

const DYLD_PATH: &[u8] = b"/usr/lib/dyld";
const LIBSYSTEM_PATH: &[u8] = b"/usr/lib/libSystem.B.dylib";

pub(crate) fn write<A: Arch<Platform = MachO>>(
    _output: &crate::file_writer::Output,
    layout: &Layout<'_, MachO>,
) -> Result {
    let mut buf = Vec::new();
    write_macho_to_vec(&mut buf, layout)?;

    let output_path = layout.symbol_db.args.output();
    std::fs::write(output_path.as_ref(), &buf)
        .map_err(|e| crate::error!("Failed to write output file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(output_path.as_ref(), perms)
            .map_err(|e| crate::error!("Failed to set permissions: {e}"))?;
    }

    Ok(())
}

fn write_macho_to_vec(out: &mut Vec<u8>, layout: &Layout<'_, MachO>) -> Result {
    // Collect text section data from input objects
    let mut text_data: Vec<u8> = Vec::new();

    for group_layout in &layout.group_layouts {
        for file_layout in &group_layout.files {
            if let crate::layout::FileLayout::Object(obj) = file_layout {
                for section in obj.object.sections {
                    use object::read::macho::Section as _;
                    let sectname = section.sectname();
                    let name_end = sectname.iter().position(|&b| b == 0).unwrap_or(16);
                    if &sectname[..name_end] == b"__text" {
                        let off = section.offset(object::Endianness::Little) as usize;
                        let sz = section.size(object::Endianness::Little) as usize;
                        if sz > 0
                            && let Some(data) = obj.object.data.get(off..off + sz) {
                                text_data.extend_from_slice(data);
                            }
                    }
                }
            }
        }
    }

    if text_data.is_empty() {
        text_data.extend_from_slice(&[
            0x40, 0x05, 0x80, 0xd2, // mov x0, #42
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ]);
    }

    let text_size = text_data.len() as u64;

    // Struct sizes
    let header_size: u64 = 32;
    let seg_cmd_size: u64 = 72;
    let section_hdr_size: u64 = 80;
    let entry_cmd_size: u64 = 24;
    let symtab_cmd_size: u64 = 24;
    let dysymtab_cmd_size: u64 = 80;
    let build_version_cmd_size: u64 = 32; // 24 base + 8 for one tool
    let _source_version_cmd_size: u64 = 16;
    let _uuid_cmd_size: u64 = 24;
    let linkedit_data_cmd_size: u64 = 16; // for chained fixups and exports trie

    // LC_LOAD_DYLINKER: cmd(4) + cmdsize(4) + name_offset(4) + path + padding to 8-byte align
    let dylinker_path_len = DYLD_PATH.len() + 1; // +1 for NUL
    let dylinker_cmd_size = align_to((12 + dylinker_path_len) as u64, 8);

    // LC_LOAD_DYLIB: cmd(4) + cmdsize(4) + offset(4) + timestamp(4) + current_version(4) + compat_version(4) + name + padding
    let dylib_name_len = LIBSYSTEM_PATH.len() + 1;
    let load_dylib_cmd_size = align_to((24 + dylib_name_len) as u64, 8);

    let num_load_commands: u32 = 11;
    let load_commands_size: u64 = seg_cmd_size          // __PAGEZERO
        + seg_cmd_size + section_hdr_size               // __TEXT + __text
        + seg_cmd_size                                  // __LINKEDIT
        + entry_cmd_size                                // LC_MAIN
        + dylinker_cmd_size                             // LC_LOAD_DYLINKER
        + load_dylib_cmd_size                           // LC_LOAD_DYLIB
        + symtab_cmd_size                               // LC_SYMTAB
        + dysymtab_cmd_size                             // LC_DYSYMTAB
        + build_version_cmd_size                        // LC_BUILD_VERSION
        + linkedit_data_cmd_size                        // LC_DYLD_CHAINED_FIXUPS
        + linkedit_data_cmd_size;                       // LC_DYLD_EXPORTS_TRIE

    let header_and_cmds = header_size + load_commands_size;
    let text_file_offset = align_to(header_and_cmds, PAGE_SIZE);
    let text_vm_addr = PAGEZERO_SIZE + text_file_offset;
    let text_segment_file_size = align_to(text_size, PAGE_SIZE);
    let text_segment_vm_size = text_file_offset + text_segment_file_size;

    let linkedit_file_offset = text_file_offset + text_segment_file_size;
    let linkedit_vm_addr = PAGEZERO_SIZE + linkedit_file_offset;

    // __LINKEDIT needs to contain at least the chained fixups header (empty)
    // Minimal chained fixups: 4 bytes (fixups_version=0) + 4 bytes (starts_offset=0) +
    // 4 bytes (imports_offset=0) + 4 bytes (symbols_offset=0) + 4 bytes (imports_count=0) +
    // 4 bytes (imports_format=0) + 4 bytes (symbols_format=0)
    let chained_fixups_size: u64 = 48; // dyld_chained_fixups_header
    let exports_trie_size: u64 = 0;

    let chained_fixups_offset = linkedit_file_offset;
    let exports_trie_offset = chained_fixups_offset + chained_fixups_size;
    let linkedit_data_size = chained_fixups_size + exports_trie_size;
    let linkedit_file_size = align_to(linkedit_data_size, 8);

    let total_file_size = (linkedit_file_offset + linkedit_file_size) as usize;
    out.resize(total_file_size, 0);

    let mut w = Writer::new(out);

    // -- Mach-O Header --
    w.write_u32(MH_MAGIC_64);
    w.write_u32(CPU_TYPE_ARM64);
    w.write_u32(CPU_SUBTYPE_ARM64_ALL);
    w.write_u32(MH_EXECUTE);
    w.write_u32(num_load_commands);
    w.write_u32(load_commands_size as u32);
    w.write_u32(MH_PIE | MH_TWOLEVEL | MH_DYLDLINK);
    w.write_u32(0); // reserved

    // -- LC_SEGMENT_64: __PAGEZERO --
    w.write_u32(LC_SEGMENT_64);
    w.write_u32(seg_cmd_size as u32);
    w.write_name16(b"__PAGEZERO");
    w.write_u64(0);
    w.write_u64(PAGEZERO_SIZE);
    w.write_u64(0);
    w.write_u64(0);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(0);

    // -- LC_SEGMENT_64: __TEXT --
    w.write_u32(LC_SEGMENT_64);
    w.write_u32((seg_cmd_size + section_hdr_size) as u32);
    w.write_name16(b"__TEXT");
    w.write_u64(PAGEZERO_SIZE);
    w.write_u64(text_segment_vm_size);
    w.write_u64(0);
    w.write_u64(text_file_offset + text_segment_file_size);
    w.write_u32(VM_PROT_READ | VM_PROT_EXECUTE);
    w.write_u32(VM_PROT_READ | VM_PROT_EXECUTE);
    w.write_u32(1);
    w.write_u32(0);

    // __text section
    w.write_name16(b"__text");
    w.write_name16(b"__TEXT");
    w.write_u64(text_vm_addr);
    w.write_u64(text_size);
    w.write_u32(text_file_offset as u32);
    w.write_u32(2); // align 2^2
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(0);

    // -- LC_SEGMENT_64: __LINKEDIT --
    w.write_u32(LC_SEGMENT_64);
    w.write_u32(seg_cmd_size as u32);
    w.write_name16(b"__LINKEDIT");
    w.write_u64(linkedit_vm_addr);
    w.write_u64(align_to(linkedit_file_size, PAGE_SIZE));
    w.write_u64(linkedit_file_offset);
    w.write_u64(linkedit_file_size);
    w.write_u32(VM_PROT_READ);
    w.write_u32(VM_PROT_READ);
    w.write_u32(0);
    w.write_u32(0);

    // -- LC_MAIN --
    w.write_u32(LC_MAIN);
    w.write_u32(entry_cmd_size as u32);
    w.write_u64(text_file_offset);
    w.write_u64(0);

    // -- LC_LOAD_DYLINKER --
    w.write_u32(LC_LOAD_DYLINKER);
    w.write_u32(dylinker_cmd_size as u32);
    w.write_u32(12); // name offset (after cmd + cmdsize + offset fields)
    w.write_bytes(DYLD_PATH);
    w.write_u8(0); // NUL terminator
    w.pad_to_align(8);

    // -- LC_LOAD_DYLIB: libSystem --
    w.write_u32(LC_LOAD_DYLIB);
    w.write_u32(load_dylib_cmd_size as u32);
    w.write_u32(24); // name offset
    w.write_u32(2); // timestamp
    w.write_u32(0x010000); // current_version (1.0.0 encoded)
    w.write_u32(0x010000); // compatibility_version
    w.write_bytes(LIBSYSTEM_PATH);
    w.write_u8(0);
    w.pad_to_align(8);

    // -- LC_SYMTAB (empty) --
    w.write_u32(LC_SYMTAB);
    w.write_u32(symtab_cmd_size as u32);
    w.write_u32(0); // symoff
    w.write_u32(0); // nsyms
    w.write_u32(0); // stroff
    w.write_u32(0); // strsize

    // -- LC_DYSYMTAB (empty) --
    w.write_u32(LC_DYSYMTAB);
    w.write_u32(dysymtab_cmd_size as u32);
    for _ in 0..18 { // 18 u32 fields, all zero
        w.write_u32(0);
    }

    // -- LC_BUILD_VERSION --
    w.write_u32(LC_BUILD_VERSION);
    w.write_u32(build_version_cmd_size as u32);
    w.write_u32(PLATFORM_MACOS); // platform
    w.write_u32(0x000e_0000); // minos: 14.0.0
    w.write_u32(0x000e_0000); // sdk: 14.0.0
    w.write_u32(1); // ntools
    // Tool entry (ld)
    w.write_u32(3); // tool = LD
    w.write_u32(0x03_0001_00); // version

    // -- LC_DYLD_CHAINED_FIXUPS --
    w.write_u32(LC_DYLD_CHAINED_FIXUPS);
    w.write_u32(linkedit_data_cmd_size as u32);
    w.write_u32(chained_fixups_offset as u32);
    w.write_u32(chained_fixups_size as u32);

    // -- LC_DYLD_EXPORTS_TRIE --
    w.write_u32(LC_DYLD_EXPORTS_TRIE);
    w.write_u32(linkedit_data_cmd_size as u32);
    w.write_u32(exports_trie_offset as u32);
    w.write_u32(exports_trie_size as u32);

    // -- Write text section data --
    let text_start = text_file_offset as usize;
    out[text_start..text_start + text_data.len()].copy_from_slice(&text_data);

    // -- Write chained fixups header in __LINKEDIT --
    let cf_start = chained_fixups_offset as usize;
    // dyld_chained_fixups_header
    let fixups_version: u32 = 0;
    let starts_offset: u32 = 0; // no starts
    let imports_offset: u32 = 0;
    let symbols_offset: u32 = 0;
    let imports_count: u32 = 0;
    let imports_format: u32 = 1; // DYLD_CHAINED_IMPORT
    let symbols_format: u32 = 0;
    out[cf_start..cf_start + 4].copy_from_slice(&fixups_version.to_le_bytes());
    out[cf_start + 4..cf_start + 8].copy_from_slice(&starts_offset.to_le_bytes());
    out[cf_start + 8..cf_start + 12].copy_from_slice(&imports_offset.to_le_bytes());
    out[cf_start + 12..cf_start + 16].copy_from_slice(&symbols_offset.to_le_bytes());
    out[cf_start + 16..cf_start + 20].copy_from_slice(&imports_count.to_le_bytes());
    out[cf_start + 20..cf_start + 24].copy_from_slice(&imports_format.to_le_bytes());
    out[cf_start + 24..cf_start + 28].copy_from_slice(&symbols_format.to_le_bytes());

    Ok(())
}

struct Writer<'a> {
    buf: &'a mut Vec<u8>,
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut Vec<u8>) -> Self {
        Writer { buf, pos: 0 }
    }

    fn write_u8(&mut self, val: u8) {
        self.buf[self.pos] = val;
        self.pos += 1;
    }

    fn write_u32(&mut self, val: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&val.to_le_bytes());
        self.pos += 4;
    }

    fn write_u64(&mut self, val: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&val.to_le_bytes());
        self.pos += 8;
    }

    fn write_name16(&mut self, name: &[u8]) {
        let mut padded = [0u8; 16];
        let len = name.len().min(16);
        padded[..len].copy_from_slice(&name[..len]);
        self.buf[self.pos..self.pos + 16].copy_from_slice(&padded);
        self.pos += 16;
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    fn pad_to_align(&mut self, alignment: usize) {
        let aligned = (self.pos + alignment - 1) & !(alignment - 1);
        while self.pos < aligned {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }
}

fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}
