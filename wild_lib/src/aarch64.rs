use crate::elf::extract_bits;
use crate::elf::BitRange;
use crate::elf::DynamicRelocationKind;
use crate::elf::PageMask;
use crate::elf::RelocationInsn;
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
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G1 | object::elf::R_AARCH64_MOVW_UABS_G1_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G2 | object::elf::R_AARCH64_MOVW_UABS_G2_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_UABS_G3 => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 48, end: 64 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            // Group relocations to create a 16, 32, 48, or 64 bit signed data or offset value inline
            object::elf::R_AARCH64_MOVW_SABS_G0 => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_SABS_G1 => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_SABS_G2 => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            // Relocations to generate 19, 21 and 33 bit PC-relative addresses
            object::elf::R_AARCH64_LD_PREL_LO19 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 21 },
                    insn: RelocationInsn::Ldr,
                },
                None,
            ),
            object::elf::R_AARCH64_ADR_PREL_LO21 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 21 },
                    insn: RelocationInsn::Adr,
                },
                None,
            ),
            object::elf::R_AARCH64_ADR_PREL_PG_HI21
            | object::elf::R_AARCH64_ADR_PREL_PG_HI21_NC => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 12, end: 33 },
                    insn: RelocationInsn::Adr,
                },
                Some(PageMask::SymbolPlusAddendAndPosition),
            ),
            object::elf::R_AARCH64_ADD_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 12 },
                    insn: RelocationInsn::Add,
                },
                None,
            ),
            object::elf::R_AARCH64_LDST8_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LDST16_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 1, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LDST32_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LDST64_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 3, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LDST128_ABS_LO12_NC => (
                RelocationKind::Absolute,
                RelocationSize::BitMasking {
                    range: BitRange { start: 4, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),

            // Relocations for control-flow instructions - all offsets are a multiple of 4
            object::elf::R_AARCH64_TSTBR14 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 16 },
                    insn: RelocationInsn::TstBr,
                },
                None,
            ),
            object::elf::R_AARCH64_CONDBR19 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 21 },
                    insn: RelocationInsn::Bcond,
                },
                None,
            ),
            object::elf::R_AARCH64_JUMP26 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 28 },
                    insn: RelocationInsn::JumpCall,
                },
                None,
            ),
            object::elf::R_AARCH64_CALL26 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 28 },
                    insn: RelocationInsn::JumpCall,
                },
                None,
            ),

            // Group relocations to create a 16, 32, 48, or 64 bit PC-relative offset inline
            object::elf::R_AARCH64_MOVW_PREL_G0 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G0_NC => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G1 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G1_NC => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G2 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G2_NC => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_PREL_G3 => (
                RelocationKind::Relative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 48, end: 64 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),

            // Group relocations to create a 16, 32, 48, or 64 bit GOT-relative offsets inline
            object::elf::R_AARCH64_MOVW_GOTOFF_G0 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G0_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 0, end: 16 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G1 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G1_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 16, end: 32 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G2 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movnz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G2_NC => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 32, end: 48 },
                    insn: RelocationInsn::Movkz,
                },
                None,
            ),
            object::elf::R_AARCH64_MOVW_GOTOFF_G3 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 48, end: 64 },
                    insn: RelocationInsn::Movnz,
                },
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
                RelocationSize::BitMasking {
                    range: BitRange { start: 2, end: 21 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LD64_GOTOFF_LO15 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 3, end: 15 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_ADR_GOT_PAGE => (
                RelocationKind::GotRelative,
                RelocationSize::BitMasking {
                    range: BitRange { start: 12, end: 33 },
                    insn: RelocationInsn::Adr,
                },
                Some(PageMask::GotEntryAndPosition),
            ),
            object::elf::R_AARCH64_LD64_GOT_LO12_NC => (
                RelocationKind::Got,
                RelocationSize::BitMasking {
                    range: BitRange { start: 3, end: 12 },
                    insn: RelocationInsn::LdSt,
                },
                None,
            ),
            object::elf::R_AARCH64_LD64_GOTPAGE_LO15 => (
                RelocationKind::GotRelGotBase,
                RelocationSize::BitMasking {
                    range: BitRange { start: 3, end: 15 },
                    insn: RelocationInsn::LdSt,
                },
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

impl RelocationInsn {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // Each instruction links to a chapter in the Arm Architecture Reference Manual for A-profile architecture
    // manual: https://developer.arm.com/documentation/ddi0487/latest/
    pub(crate) fn write_to_value(self, extracted_value: u64, original_value: u64, dest: &mut [u8]) {
        let mut mask;
        match self {
            // C6.2.13
            RelocationInsn::Adr => {
                mask = ((extract_bits(extracted_value, 0, 2) as u32) << 29)
                    | ((extract_bits(extracted_value, 2, 32) as u32) << 5);
            }
            // C6.2.252, C6.2.254
            RelocationInsn::Movkz => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.253, C6.2.254
            RelocationInsn::Movnz => {
                let negative = (original_value as i64) < 0;
                let mut value = extracted_value as i64;
                mask = 0u32;
                if negative {
                    value = !value;
                } else {
                    // Set opcode for MOVZ instruction
                    mask |= 1 << 30;
                }
                mask |= extract_bits(value as u64, 0, 16) as u32;
            }
            // C6.2.192
            RelocationInsn::Ldr => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.5
            RelocationInsn::Add => {
                mask = (extracted_value as u32) << 10;
            }
            // C7.2.208, C6.2.383
            RelocationInsn::LdSt => {
                mask = (extracted_value as u32) << 10;
            }
            // C6.2.438
            RelocationInsn::TstBr => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.34
            RelocationInsn::Bcond => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.33
            RelocationInsn::JumpCall => {
                mask = extracted_value as u32;
            }
        }
        // Read the original value and combine it with the prepared mask.
        let mask_bytes = &mask.to_le_bytes();
        for (i, v) in mask_bytes.iter().enumerate() {
            dest[i] = *v;
        }
    }
}
