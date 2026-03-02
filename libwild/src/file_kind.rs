//! Code for identifying what sort of file we're dealing with based on the bytes of the file.

use crate::bail;
use crate::elf;
use crate::error::Result;
use object::LittleEndian;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum FileKind {
    ElfObject,
    ElfDynamic,
    Archive,
    ThinArchive,
    Text,
    LlvmIr,
    GccIr,
}

impl FileKind {
    pub(crate) fn identify_bytes(bytes: &[u8]) -> Result<FileKind> {
        if bytes.starts_with(&object::archive::MAGIC) {
            Ok(FileKind::Archive)
        } else if bytes.starts_with(&object::archive::THIN_MAGIC) {
            Ok(FileKind::ThinArchive)
        } else if bytes.starts_with(&object::elf::ELFMAG) {
            const HEADER_LEN: usize = size_of::<elf::FileHeader>();
            if bytes.len() < HEADER_LEN {
                bail!("Invalid ELF file");
            }
            let header: &elf::FileHeader = object::from_bytes(&bytes[..HEADER_LEN]).unwrap().0;
            if header.e_ident.class != object::elf::ELFCLASS64 {
                bail!("Only 64 bit ELF is currently supported");
            }
            if header.e_ident.data != object::elf::ELFDATA2LSB {
                bail!("Only little endian is currently supported");
            }

            match header.e_type.get(LittleEndian) {
                object::elf::ET_REL => {
                    if is_gcc_bitcode(bytes, header).unwrap_or(false) {
                        Ok(FileKind::GccIr)
                    } else {
                        Ok(FileKind::ElfObject)
                    }
                }
                object::elf::ET_DYN => Ok(FileKind::ElfDynamic),
                t => bail!("Unsupported ELF kind {t}"),
            }
        } else if bytes.is_ascii() {
            Ok(FileKind::Text)
        } else if bytes.starts_with(b"BC") {
            Ok(FileKind::LlvmIr)
        } else {
            bail!("Couldn't identify file type");
        }
    }

    pub(crate) fn is_compiler_ir(self) -> bool {
        matches!(self, FileKind::LlvmIr | FileKind::GccIr)
    }
}

/// Returns whether the supplied file contents is GCC IR. Scanning the entire section table would be
/// expensive. Instead, we assume that we'll find a GCC LTO section within the first few sections,
/// so just scan part of the section header strings table. It's unfortunate that GCC didn't tag
/// these objects in some fast-to-check way.
fn is_gcc_bitcode(data: &[u8], header: &crate::elf::FileHeader) -> Option<bool> {
    // If we don't have plugin support, then we skip checking if the file contains GCC IR. If it is,
    // then we'll figure that out later on and report an error. We do this because this code has a
    // measurable performance impact.
    if !cfg!(feature = "plugins") {
        return Some(false);
    }
    let e = LittleEndian;
    let section_headers = header.section_headers(e, data).ok()?;
    let sh_str_index = header.shstrndx(e, data).ok()?;
    let strings_section_header = section_headers.get(sh_str_index as usize)?;
    let start_offset = strings_section_header.sh_offset(e) as usize;
    let len = strings_section_header.sh_size(e) as usize;
    // In observed GCC IR files, the LTO section names start at offset 44 and end at 454. We want to
    // scan roughly the middle of this range.
    const START: usize = 100;
    // The longest GCC LTO section name is 47 bytes. We scan a bit more in case the first LTO
    // section started later than START.
    const MAX_SCAN: usize = 200;
    let strings = data.get(start_offset + START..start_offset + (START + MAX_SCAN).min(len))?;
    Some(memchr::memmem::find(strings, b"\0.gnu.lto_.").is_some())
}

impl std::fmt::Display for FileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FileKind::ElfObject => "ELF object",
            FileKind::ElfDynamic => "ELF dynamic",
            FileKind::Archive => "archive",
            FileKind::ThinArchive => "thin archive",
            FileKind::Text => "text",
            FileKind::LlvmIr => "LLVM-IR",
            FileKind::GccIr => "GCC-IR",
        };
        std::fmt::Display::fmt(s, f)
    }
}
