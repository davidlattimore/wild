use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use anyhow::bail;
use anyhow::Result;

pub(crate) struct AArch64;

impl crate::arch::Arch for AArch64 {
    type Relaxation = ();

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_AARCH64
    }

    // The table of the relocations is documented here:
    // https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        let (kind, size) = match r_type {
            object::elf::R_AARCH64_CALL26 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 28 },
            ),
            object::elf::R_AARCH64_PREL32 => {
                (RelocationKind::Relative, RelocationSize::ByteSize(4))
            }
            _ => bail!("Unsupported relocation type {}", r_type),
        };
        Ok(RelocationKindInfo { kind, size })
    }
}

impl crate::arch::Relaxation for () {
    #[allow(unused_variables)]
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_flags: crate::resolution::ValueFlags,
        output_kind: crate::args::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
    ) -> Option<Self>
    where
        Self: std::marker::Sized,
    {
        None
    }

    #[allow(unused_variables)]
    fn apply(
        &self,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut u64,
        next_modifier: &mut crate::relaxation::RelocationModifier,
    ) {
    }

    fn rel_info(&self) -> crate::elf::RelocationKindInfo {
        RelocationKindInfo {
            kind: RelocationKind::None,
            size: RelocationSize::ByteSize(0),
        }
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        todo!()
    }
}
