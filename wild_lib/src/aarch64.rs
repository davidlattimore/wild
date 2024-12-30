use crate::elf::DynamicRelocationKind;
use crate::elf::PageMask;
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
        let (kind, size, mask) = match r_type {
            // 5.7.4   Static miscellaneous relocations
            object::elf::R_AARCH64_NONE => {
                (RelocationKind::None, RelocationSize::ByteSize(0), None)
            }

            // 5.7.5   Static Data relocations
            // Data relocations
            object::elf::R_AARCH64_ABS64 => {
                (RelocationKind::Absolute, RelocationSize::ByteSize(8), None)
            }
            object::elf::R_AARCH64_ABS32 => {
                (RelocationKind::Absolute, RelocationSize::ByteSize(4), None)
            }
            object::elf::R_AARCH64_ABS16 => {
                (RelocationKind::Absolute, RelocationSize::ByteSize(2), None)
            }
            object::elf::R_AARCH64_PREL64 => {
                (RelocationKind::Relative, RelocationSize::ByteSize(8), None)
            }
            object::elf::R_AARCH64_PREL32 => {
                (RelocationKind::Relative, RelocationSize::ByteSize(4), None)
            }
            object::elf::R_AARCH64_PREL16 => {
                (RelocationKind::Relative, RelocationSize::ByteSize(2), None)
            }
            // TODO: missing in upstream header file (as well as in Object crate):
            // object::elf::R_AARCH64_PLT32

            // 5.7.6   Static AArch64 relocations
            // Group relocations to create a 16-, 32-, 48-, or 64-bit unsigned data value or address inline
            object::elf::R_AARCH64_MOVW_UABS_G0 | object::elf::R_AARCH64_MOVW_UABS_G0_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 0, end: 16 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G1 | object::elf::R_AARCH64_MOVW_UABS_G1_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 16, end: 32 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G2 | object::elf::R_AARCH64_MOVW_UABS_G2_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 32, end: 48 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G3 => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 48, end: 64 },
                None,
            ),

            // Group relocations to create a 16, 32, 48, or 64 bit signed data or offset value inline
            object::elf::R_AARCH64_MOVW_SABS_G0 => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 0, end: 16 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_SABS_G1 => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 16, end: 32 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_SABS_G2 => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 32, end: 48 },
                None,
            ),

            // Relocations to generate 19, 21 and 33 bit PC-relative addresses
            object::elf::R_AARCH64_LD_PREL_LO19 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 21 },
                None,
            ),
            object::elf::R_AARCH64_ADR_PREL_LO21 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 0, end: 21 },
                None,
            ),
            object::elf::R_AARCH64_ADR_PREL_PG_HI21
            | object::elf::R_AARCH64_ADR_PREL_PG_HI21_NC => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 12, end: 33 },
                Some(PageMask::SymbolPlusAddendAndPosition),
            ),
            object::elf::R_AARCH64_ADD_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 0, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LDST8_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 0, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LDST16_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 1, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LDST32_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 2, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LDST64_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 3, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LDST128_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitRange { start: 4, end: 12 },
                None,
            ),

            // Relocations for control-flow instructions - all offsets are a multiple of 4
            object::elf::R_AARCH64_TSTBR14 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 16 },
                None,
            ),
            object::elf::R_AARCH64_CONDBR19 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 21 },
                None,
            ),
            object::elf::R_AARCH64_JUMP26 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 28 },
                None,
            ),
            object::elf::R_AARCH64_CALL26 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 2, end: 28 },
                None,
            ),

            // Group relocations to create a 16, 32, 48, or 64 bit PC-relative offset inline
            object::elf::R_AARCH64_MOVW_PREL_G0 | object::elf::R_AARCH64_MOVW_PREL_G0_NC => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 0, end: 16 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G1 | object::elf::R_AARCH64_MOVW_PREL_G1_NC => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 16, end: 32 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G2 | object::elf::R_AARCH64_MOVW_PREL_G2_NC => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 32, end: 48 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G3 => (
                RelocationKind::Relative,
                RelocationSize::BitRange { start: 48, end: 64 },
                None,
            ),

            // Group relocations to create a 16, 32, 48, or 64 bit GOT-relative offsets inline
            object::elf::R_AARCH64_MOVW_GOTOFF_G0 | object::elf::R_AARCH64_MOVW_GOTOFF_G0_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 0, end: 16 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G1 | object::elf::R_AARCH64_MOVW_GOTOFF_G1_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 16, end: 32 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G2 | object::elf::R_AARCH64_MOVW_GOTOFF_G2_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 32, end: 48 },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G3 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 48, end: 64 },
                None,
            ),

            // GOT-relative data relocations
            object::elf::R_AARCH64_GOTREL64 => (
                RelocationKind::SymRelGotBase,
                RelocationSize::ByteSize(4),
                None,
            ),
            object::elf::R_AARCH64_GOTREL32 => (
                RelocationKind::SymRelGotBase,
                RelocationSize::ByteSize(8),
                None,
            ),
            // TODO: missing in upstream header file (as well as in Object crate)
            // object::elf::R_AARCH64_GOTPCREL32
            object::elf::R_AARCH64_GOT_LD_PREL19 => (
                RelocationKind::GotRelative,
                RelocationSize::BitRange { start: 2, end: 21 },
                None,
            ),
            object::elf::R_AARCH64_LD64_GOTOFF_LO15 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 3, end: 15 },
                None,
            ),
            object::elf::R_AARCH64_ADR_GOT_PAGE => (
                RelocationKind::GotRelative,
                RelocationSize::BitRange { start: 12, end: 33 },
                Some(PageMask::GotEntryAndPosition),
            ),
            object::elf::R_AARCH64_LD64_GOT_LO12_NC => (
                RelocationKind::Got,
                RelocationSize::BitRange { start: 3, end: 12 },
                None,
            ),
            object::elf::R_AARCH64_LD64_GOTPAGE_LO15 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitRange { start: 3, end: 15 },
                Some(PageMask::GotBase),
            ),
            _ => bail!("Unsupported relocation type {}", r_type),
        };
        Ok(RelocationKindInfo { kind, size, mask })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        match relocation {
            DynamicRelocationKind::Copy => object::elf::R_AARCH64_COPY,
            DynamicRelocationKind::Irelative => object::elf::R_AARCH64_IRELATIVE,
            DynamicRelocationKind::DtpMod => object::elf::R_AARCH64_TLS_DTPMOD,
            // TODO
            DynamicRelocationKind::DtpOff => object::elf::R_AARCH64_NONE,
            DynamicRelocationKind::TpOff => object::elf::R_AARCH64_NONE,
            DynamicRelocationKind::Relative => object::elf::R_AARCH64_RELATIVE,
            DynamicRelocationKind::DynamicSymbol => object::elf::R_AARCH64_GLOB_DAT,
        }
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
            mask: None,
        }
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        todo!()
    }
}
