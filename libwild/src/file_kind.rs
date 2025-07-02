//! Code for identifying what sort of file we're dealing with based on the bytes of the file.

use crate::bail;
use crate::elf;
use crate::error::Result;
use object::LittleEndian;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum FileKind {
    ElfObject,
    ElfDynamic,
    Archive,
    ThinArchive,
    Text,
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
                object::elf::ET_REL => Ok(FileKind::ElfObject),
                object::elf::ET_DYN => Ok(FileKind::ElfDynamic),
                t => bail!("Unsupported ELF kind {t}"),
            }
        } else if bytes.is_ascii() {
            Ok(FileKind::Text)
        } else if bytes.starts_with(b"BC") {
            bail!("LLVM IR (LTO mode) is not supported yet");
        } else {
            bail!("Couldn't identify file type");
        }
    }
}
