#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Standalone tests for --only-keep-debug ELF output properties.

use object::LittleEndian as LE;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::elf::ElfFile64;
use object::read::elf::ProgramHeader as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn wild_path() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_wild"))
}

fn build_obj(tmp: &Path) -> PathBuf {
    let src = tmp.join("test.c");
    let obj = tmp.join("test.o");
    std::fs::write(
        &src,
        r#"
int global = 42;
void _start(void) {
    __asm__("movq $60, %rax\n\txorq %rdi, %rdi\n\tsyscall");
}
"#,
    )
    .unwrap();
    let status = Command::new("gcc")
        .args(["-c", "-g", "-O0", "-nostdlib"])
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("gcc not available");
    assert!(status.success(), "gcc compile failed");
    obj
}

fn link(obj: &Path, out: &Path, extra_args: &[&str]) {
    let status = Command::new(wild_path())
        .arg("-nostdlib")
        .args(extra_args)
        .arg(obj)
        .arg("-o")
        .arg(out)
        .status()
        .expect("wild not found");
    assert!(
        status.success(),
        "wild link failed with args {extra_args:?}"
    );
}

/// Returns true if a section has file-backed content (not NOBITS and non-zero size).
fn section_has_file_content(
    section: &object::read::elf::ElfSection64<'_, '_, LE>,
    endian: LE,
) -> bool {
    let sh = section.elf_section_header();
    let ty = sh.sh_type.get(endian);
    let size = sh.sh_size.get(endian);
    ty != object::elf::SHT_NOBITS && ty != object::elf::SHT_NULL && size > 0
}

/// ELF section and segment invariants for --only-keep-debug output.
///
/// Checks:
///   - SHF_ALLOC non-NOTE sections are SHT_NOBITS
///   - Non-NOBITS sections don't overlap in file
///   - PT_LOAD p_filesz is semantically correct based on segment content
///   - Debug sections (.debug_info, .debug_line, .debug_abbrev, .debug_str) are preserved
///   - Symbol table (.symtab, .strtab) is preserved
#[test]
fn elf_section_and_segment_properties() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out = tmp.path().join("out.dbg");
    link(&obj, &out, &["--only-keep-debug"]);

    let bytes = std::fs::read(&out).unwrap();
    let elf: ElfFile64<LE> = ElfFile64::parse(bytes.as_slice()).unwrap();
    let endian = elf.endian();

    // Every SHF_ALLOC non-NOTE section must be SHT_NOBITS.
    for section in elf.sections() {
        let sh = section.elf_section_header();
        let ty = sh.sh_type.get(endian);
        let is_alloc = matches!(section.flags(),
            object::SectionFlags::Elf { sh_flags, .. } if sh_flags.0 & object::elf::SHF_ALLOC.0 != 0);
        let is_note = ty == object::elf::SHT_NOTE;
        if is_alloc && !is_note {
            assert_eq!(
                ty,
                object::elf::SHT_NOBITS,
                "section {:?} SHF_ALLOC non-NOTE has sh_type={ty:#x}, want SHT_NOBITS",
                section.name()
            );
        }
    }

    // No two non-NOBITS sections should overlap in file offsets.
    let mut regions: Vec<(u64, u64, String)> = elf
        .sections()
        .filter_map(|s| {
            let sh = s.elf_section_header();
            let ty = sh.sh_type.get(endian);
            let size = sh.sh_size.get(endian);
            let offset = sh.sh_offset.get(endian);
            if ty != object::elf::SHT_NOBITS && size > 0 {
                Some((offset, offset + size, s.name().unwrap_or("?").to_owned()))
            } else {
                None
            }
        })
        .collect();
    regions.sort_by_key(|r| r.0);
    for w in regions.windows(2) {
        let (_, end_a, name_a) = &w[0];
        let (start_b, _, name_b) = &w[1];
        assert!(
            end_a <= start_b,
            "sections {name_a} and {name_b} overlap ({end_a:#x} > {start_b:#x})"
        );
    }

    // Semantic PT_LOAD p_filesz check: for each PT_LOAD segment, determine whether
    // it contains any file-backed sections. If it does, p_filesz must be non-zero.
    // If all its sections are NOBITS (zeroed alloc), p_filesz must be zero.
    // This avoids encoding positional assumptions about which PT_LOAD is "first".
    for phdr in elf.elf_program_headers() {
        if phdr.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let seg_vaddr = phdr.p_vaddr(endian);
        let seg_memsz = phdr.p_memsz(endian);
        let seg_end = seg_vaddr + seg_memsz;

        // Find sections whose sh_addr falls within this segment's virtual range.
        let has_file_content = elf.sections().any(|sec| {
            let sh = sec.elf_section_header();
            let addr = sh.sh_addr.get(endian);
            let size = sh.sh_size.get(endian);
            // Section overlaps the segment's virtual address range.
            addr >= seg_vaddr
                && addr < seg_end
                && size > 0
                && section_has_file_content(&sec, endian)
        });

        if has_file_content {
            assert!(
                phdr.p_filesz(endian) > 0,
                "PT_LOAD [{seg_vaddr:#x}..{seg_end:#x}] contains file-backed sections \
                 but has p_filesz=0"
            );
        } else {
            assert_eq!(
                phdr.p_filesz(endian),
                0,
                "PT_LOAD [{seg_vaddr:#x}..{seg_end:#x}] has only NOBITS sections \
                 but p_filesz={:#x}",
                phdr.p_filesz(endian)
            );
        }
    }

    // Debug sections must be preserved and non-empty.
    for name in [".debug_info", ".debug_line", ".debug_abbrev", ".debug_str"] {
        let section = elf.section_by_name(name).unwrap_or_else(|| {
            panic!("{name} section must be present in --only-keep-debug output")
        });
        assert!(section.size() > 0, "{name} must have non-zero size");
    }

    // Symbol table must be preserved.
    let symtab = elf
        .section_by_name(".symtab")
        .expect(".symtab must be present");
    assert!(symtab.size() > 0, ".symtab must have non-zero size");
    let strtab = elf
        .section_by_name(".strtab")
        .expect(".strtab must be present");
    assert!(strtab.size() > 0, ".strtab must have non-zero size");
}

/// Two-pass address and symbol preservation.
///
/// Links the same object normally and with --only-keep-debug, then asserts:
///   - Every section in the normal build exists in the debug build with matching sh_addr
///   - Every named symbol in the normal build exists in the debug build with matching st_value
///   - The debug-only ELF is smaller than the normal ELF
#[test]
fn two_pass_address_preservation() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out_n = tmp.path().join("out.normal");
    let out_d = tmp.path().join("out.dbg");
    link(&obj, &out_n, &[]);
    link(&obj, &out_d, &["--only-keep-debug"]);

    let bytes_n = std::fs::read(&out_n).unwrap();
    let bytes_d = std::fs::read(&out_d).unwrap();

    // The debug-only ELF should be materially smaller — code/data are gone.
    assert!(
        bytes_d.len() < bytes_n.len(),
        "debug-only ELF ({} bytes) should be smaller than normal ELF ({} bytes)",
        bytes_d.len(),
        bytes_n.len()
    );

    let elf_n: ElfFile64<LE> = ElfFile64::parse(bytes_n.as_slice()).unwrap();
    let elf_d: ElfFile64<LE> = ElfFile64::parse(bytes_d.as_slice()).unwrap();
    let endian = LE;

    // Every section in the normal build must exist in the debug build with the same sh_addr.
    for sec in elf_n.sections() {
        let name = match sec.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        let sec_d = elf_d.section_by_name(name).unwrap_or_else(|| {
            panic!(
                "section {name} present in normal build is missing from --only-keep-debug output"
            )
        });
        let addr_n = sec.elf_section_header().sh_addr.get(endian);
        let addr_d = sec_d.elf_section_header().sh_addr.get(endian);
        assert_eq!(
            addr_n, addr_d,
            "section {name}: sh_addr normal={addr_n:#x} dbg={addr_d:#x}"
        );
    }

    // Every named symbol in the normal build must exist in the debug build
    // with matching st_value.
    for sym in elf_n.symbols() {
        let name = match sym.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        let sym_d = elf_d
            .symbols()
            .find(|s| s.name() == Ok(name))
            .unwrap_or_else(|| {
                panic!(
                    "symbol {name} present in normal build is missing from --only-keep-debug output"
                )
            });
        assert_eq!(
            sym.address(),
            sym_d.address(),
            "symbol {name}: st_value normal={:#x} dbg={:#x}",
            sym.address(),
            sym_d.address()
        );
    }
}

/// Verify that explicit --build-id=0x... produces identical .note.gnu.build-id
/// in both normal and --only-keep-debug builds.
#[test]
fn build_id_explicit_matching() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out_n = tmp.path().join("out.normal");
    let out_d = tmp.path().join("out.dbg");
    let build_id_arg = "--build-id=0xdeadbeef12345678";

    link(&obj, &out_n, &[build_id_arg]);
    link(&obj, &out_d, &["--only-keep-debug", build_id_arg]);

    let bytes_n = std::fs::read(&out_n).unwrap();
    let bytes_d = std::fs::read(&out_d).unwrap();
    let elf_n: ElfFile64<LE> = ElfFile64::parse(bytes_n.as_slice()).unwrap();
    let elf_d: ElfFile64<LE> = ElfFile64::parse(bytes_d.as_slice()).unwrap();

    let note_n = elf_n
        .section_by_name(".note.gnu.build-id")
        .expect("normal build must have .note.gnu.build-id");
    let note_d = elf_d
        .section_by_name(".note.gnu.build-id")
        .expect("debug build must have .note.gnu.build-id");

    let data_n = note_n.data().unwrap();
    let data_d = note_d.data().unwrap();

    assert_eq!(
        data_n.len(),
        data_d.len(),
        "build-id note size mismatch: normal={} debug={}",
        data_n.len(),
        data_d.len()
    );
    assert_eq!(
        data_n, data_d,
        "build-id content must match between normal and debug builds"
    );
}

/// Verify that --compress-debug-sections=zlib combined with --only-keep-debug
/// produces a valid ELF with compressed debug info and zeroed alloc sections.
///
/// This tests the interaction between the two post-layout passes:
///   compress debug → only-keep-debug → recalculate layout
#[test]
fn compressed_debug_with_only_keep_debug() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out = tmp.path().join("out.dbg");
    link(
        &obj,
        &out,
        &["--only-keep-debug", "--compress-debug-sections=zlib"],
    );

    let bytes = std::fs::read(&out).unwrap();
    let elf: ElfFile64<LE> = ElfFile64::parse(bytes.as_slice()).unwrap();
    let endian = elf.endian();

    // Alloc sections must still be NOBITS.
    for section in elf.sections() {
        let sh = section.elf_section_header();
        let ty = sh.sh_type.get(endian);
        let is_alloc = matches!(section.flags(),
            object::SectionFlags::Elf { sh_flags, .. } if sh_flags.0 & object::elf::SHF_ALLOC.0 != 0);
        let is_note = ty == object::elf::SHT_NOTE;
        if is_alloc && !is_note {
            assert_eq!(
                ty,
                object::elf::SHT_NOBITS,
                "section {:?} should be NOBITS with compression + only-keep-debug",
                section.name()
            );
        }
    }

    // Debug sections must exist and have non-zero file size (they may be compressed).
    for name in [".debug_info", ".debug_line", ".debug_abbrev", ".debug_str"] {
        let section = elf.section_by_name(name).unwrap_or_else(|| {
            panic!("{name} must be present with --compress-debug-sections + --only-keep-debug")
        });
        assert!(
            section.size() > 0,
            "{name} must have non-zero size even when compressed"
        );
    }

    // PT_LOAD segments with only NOBITS content must have p_filesz == 0.
    for phdr in elf.elf_program_headers() {
        if phdr.p_type(endian) != object::elf::PT_LOAD {
            continue;
        }
        let seg_vaddr = phdr.p_vaddr(endian);
        let seg_memsz = phdr.p_memsz(endian);
        let seg_end = seg_vaddr + seg_memsz;

        let has_file_content = elf.sections().any(|sec| {
            let sh = sec.elf_section_header();
            let addr = sh.sh_addr.get(endian);
            let size = sh.sh_size.get(endian);
            addr >= seg_vaddr
                && addr < seg_end
                && size > 0
                && section_has_file_content(&sec, endian)
        });

        if !has_file_content {
            assert_eq!(
                phdr.p_filesz(endian),
                0,
                "PT_LOAD [{seg_vaddr:#x}..{seg_end:#x}] with only NOBITS sections \
                 should have p_filesz=0 (with compression)"
            );
        }
    }
}
