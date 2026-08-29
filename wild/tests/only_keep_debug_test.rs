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
    assert!(status.success(), "wild link failed with args {extra_args:?}");
}

fn load_elf(path: &Path) -> (Vec<u8>, ElfFile64<'static, LE>) {
    let bytes = Box::leak(std::fs::read(path).unwrap().into_boxed_slice());
    let elf = ElfFile64::parse(bytes as &[u8]).unwrap();
    (Vec::new(), elf) // bytes owned by leaked box; elf borrows it
}

/// Properties 3, 5, 7
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn elf_section_and_segment_properties() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out = tmp.path().join("out.dbg");
    link(&obj, &out, &["--only-keep-debug"]);

    let bytes = std::fs::read(&out).unwrap();
    let elf: ElfFile64<LE> = ElfFile64::parse(bytes.as_slice()).unwrap();
    let endian = elf.endian();

    // Property 3: every SHF_ALLOC non-NOTE section must be SHT_NOBITS
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

    // Property 5: no two non-NOBITS sections overlap in file
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

    // Property 7: every PT_LOAD segment has p_filesz == 0
    for phdr in elf.elf_program_headers() {
        if phdr.p_type(endian) == object::elf::PT_LOAD {
            assert_eq!(
                phdr.p_filesz(endian),
                0,
                "PT_LOAD segment has p_filesz={:#x}, want 0",
                phdr.p_filesz(endian)
            );
        }
    }
}

/// Properties 1 + 2: two-pass address preservation
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn two_pass_address_preservation() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = build_obj(tmp.path());
    let out_n = tmp.path().join("out.normal");
    let out_d = tmp.path().join("out.dbg");
    link(&obj, &out_n, &[]);
    link(&obj, &out_d, &["--only-keep-debug"]);

    let bytes_n = std::fs::read(&out_n).unwrap();
    let bytes_d = std::fs::read(&out_d).unwrap();
    let elf_n: ElfFile64<LE> = ElfFile64::parse(bytes_n.as_slice()).unwrap();
    let elf_d: ElfFile64<LE> = ElfFile64::parse(bytes_d.as_slice()).unwrap();
    let endian = LE;

    // Property 1: sh_addr matches by section name
    for sec in elf_n.sections() {
        let name = match sec.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        if let Some(sec_d) = elf_d.section_by_name(name) {
            let addr_n = sec.elf_section_header().sh_addr.get(endian);
            let addr_d = sec_d.elf_section_header().sh_addr.get(endian);
            assert_eq!(
                addr_n, addr_d,
                "section {name}: sh_addr normal={addr_n:#x} dbg={addr_d:#x}"
            );
        }
    }

    // Property 2: st_value matches by symbol name
    for sym in elf_n.symbols() {
        let name = match sym.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        if let Some(sym_d) = elf_d.symbols().find(|s| s.name() == Ok(name)) {
            assert_eq!(
                sym.address(),
                sym_d.address(),
                "symbol {name}: st_value normal={:#x} dbg={:#x}",
                sym.address(),
                sym_d.address()
            );
        }
    }
}
