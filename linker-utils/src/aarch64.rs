use crate::elf::extract_bits;
use crate::elf::PageMask;
use crate::elf::RelocationInstruction;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::relaxation::RelocationModifier;

#[derive(Debug, Clone, Copy)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,

    /// Replace with nop
    ReplaceWithNop,

    /// Replace with movz x0 lsl #16
    MovzX0Lsl16,

    /// Replace with movk x0
    MovkX0,

    /// Replace with movz xn lsl #16
    MovzXnLsl16,

    /// Replace with movk xn
    MovkXn,
}

impl RelaxationKind {
    pub fn apply(self, section_bytes: &mut [u8], offset_in_section: &mut u64, _addend: &mut i64) {
        let offset = *offset_in_section as usize;
        match self {
            RelaxationKind::NoOp => {}
            RelaxationKind::ReplaceWithNop => {
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    0x1f, 0x20, 0x03, 0xd5, // nop
                ]);
            }
            RelaxationKind::MovzX0Lsl16 => {
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    0x0, 0x0, 0xa0, 0xd2, // movz x0, ${offset}, lsl #16
                ]);
            }
            RelaxationKind::MovkX0 => {
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    0x0, 0x0, 0x80, 0xf2, // movk x0, ${offset}
                ]);
            }
            RelaxationKind::MovzXnLsl16 => {
                let reg = extract_bits(
                    u64::from(u32::from_le_bytes(
                        *section_bytes[offset..offset + 4]
                            .first_chunk::<4>()
                            .unwrap(),
                    )),
                    0,
                    5,
                ) as u8;
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    reg, 0x0, 0xa0, 0xd2, // movz x{reg}, ${offset}, lsl #16
                ]);
            }
            RelaxationKind::MovkXn => {
                let raw = u64::from(u32::from_le_bytes(
                    *section_bytes[offset..offset + 4]
                        .first_chunk::<4>()
                        .unwrap(),
                ));
                let dst_reg = extract_bits(raw, 0, 5) as u8;
                let src_reg = extract_bits(raw, 5, 10) as u8;
                debug_assert_eq!(
                    src_reg, dst_reg,
                    "Source and destination registers must be equal"
                );
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    dst_reg, 0x0, 0x80, 0xf2, // movk x{dst}, ${offset}
                ]);
            }
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }
}

#[must_use]
pub fn relocation_type_from_raw(r_type: u32) -> Option<RelocationKindInfo> {
    let (kind, size, mask) = match r_type {
        // 5.7.4   Static miscellaneous relocations
        object::elf::R_AARCH64_NONE => (RelocationKind::None, RelocationSize::ByteSize(0), None),

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
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_UABS_G1 | object::elf::R_AARCH64_MOVW_UABS_G1_NC => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_UABS_G2 | object::elf::R_AARCH64_MOVW_UABS_G2_NC => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_UABS_G3 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(48, 64, RelocationInstruction::Movkz),
            None,
        ),
        // Group relocations to create a 16, 32, 48, or 64 bit signed data or offset value inline
        object::elf::R_AARCH64_MOVW_SABS_G0 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_SABS_G1 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_SABS_G2 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movnz),
            None,
        ),
        // Relocations to generate 19, 21 and 33 bit PC-relative addresses
        object::elf::R_AARCH64_LD_PREL_LO19 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(2, 21, RelocationInstruction::Ldr),
            None,
        ),
        object::elf::R_AARCH64_ADR_PREL_LO21 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(0, 21, RelocationInstruction::Adr),
            None,
        ),
        object::elf::R_AARCH64_ADR_PREL_PG_HI21 | object::elf::R_AARCH64_ADR_PREL_PG_HI21_NC => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::SymbolPlusAddendAndPosition),
        ),
        object::elf::R_AARCH64_ADD_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_LDST8_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LDST16_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(1, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LDST32_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(2, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LDST64_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LDST128_ABS_LO12_NC => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask(4, 12, RelocationInstruction::LdSt),
            None,
        ),

        // Relocations for control-flow instructions - all offsets are a multiple of 4
        object::elf::R_AARCH64_TSTBR14 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(2, 16, RelocationInstruction::TstBr),
            None,
        ),
        object::elf::R_AARCH64_CONDBR19 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(2, 21, RelocationInstruction::Bcond),
            None,
        ),
        object::elf::R_AARCH64_JUMP26 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(2, 28, RelocationInstruction::JumpCall),
            None,
        ),
        object::elf::R_AARCH64_CALL26 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(2, 28, RelocationInstruction::JumpCall),
            None,
        ),

        // Group relocations to create a 16, 32, 48, or 64 bit PC-relative offset inline
        object::elf::R_AARCH64_MOVW_PREL_G0 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G0_NC => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G1 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G1_NC => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G2 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G2_NC => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_PREL_G3 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask(48, 64, RelocationInstruction::Movnz),
            None,
        ),

        // Group relocations to create a 16, 32, 48, or 64 bit GOT-relative offsets inline
        object::elf::R_AARCH64_MOVW_GOTOFF_G0 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G0_NC => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G1 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G1_NC => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G2 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G2_NC => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_MOVW_GOTOFF_G3 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(48, 64, RelocationInstruction::Movnz),
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
            RelocationSize::bit_mask(2, 21, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LD64_GOTOFF_LO15 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(3, 15, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_ADR_GOT_PAGE => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::GotEntryAndPosition),
        ),
        object::elf::R_AARCH64_LD64_GOT_LO12_NC => (
            RelocationKind::Got,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_LD64_GOTPAGE_LO15 => (
            RelocationKind::GotRelGotBase,
            RelocationSize::bit_mask(3, 15, RelocationInstruction::LdSt),
            Some(PageMask::GotBase),
        ),

        // 5.7.11.1   General Dynamic thread-local storage model
        object::elf::R_AARCH64_TLSGD_ADR_PREL21 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask(0, 21, RelocationInstruction::Adr),
            None,
        ),
        object::elf::R_AARCH64_TLSGD_ADR_PAGE21 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::GotEntryAndPosition),
        ),
        object::elf::R_AARCH64_TLSGD_ADD_LO12_NC => (
            RelocationKind::TlsGdGot,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSGD_MOVW_G1 => (
            RelocationKind::TlsGdGotBase,
            RelocationSize::bit_mask(16, 33, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSGD_MOVW_G0_NC => (
            RelocationKind::TlsGdGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),

        // 5.7.11.2   Local Dynamic thread-local storage model
        object::elf::R_AARCH64_TLSLD_ADR_PREL21 => (
            RelocationKind::TlsLd,
            RelocationSize::bit_mask(0, 21, RelocationInstruction::Adr),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_ADR_PAGE21 => (
            RelocationKind::TlsLd,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::GotEntryAndPosition),
        ),
        object::elf::R_AARCH64_TLSLD_ADD_LO12_NC => (
            RelocationKind::TlsLdGot,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_G1 => (
            RelocationKind::TlsLdGotBase,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_G0_NC => (
            RelocationKind::TlsLdGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LD_PREL19 => (
            RelocationKind::TlsLd,
            RelocationSize::bit_mask(0, 21, RelocationInstruction::Ldr),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_DTPREL_G2 => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_DTPREL_G1 => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_DTPREL_G0 => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_ADD_DTPREL_HI12 => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(12, 24, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_ADD_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LDST8_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LDST16_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(1, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LDST32_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(2, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LDST64_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLD_LDST128_DTPREL_LO12
        | object::elf::R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC => (
            RelocationKind::DtpOff,
            RelocationSize::bit_mask(4, 12, RelocationInstruction::LdSt),
            None,
        ),

        // 5.7.11.3   Initial Exec thread-local storage model
        object::elf::R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 => (
            RelocationKind::GotTpOffGotBase,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC => (
            RelocationKind::GotTpOffGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 => (
            RelocationKind::GotTpOff,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::GotEntryAndPosition),
        ),
        object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdrRegister),
            None,
        ),
        object::elf::R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 => (
            RelocationKind::GotTpOff,
            RelocationSize::bit_mask(2, 21, RelocationInstruction::Ldr),
            None,
        ),

        // 5.7.11.4   Local Exec thread-local storage model
        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G2 => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(32, 48, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1 => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0 => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_ADD_TPREL_HI12 => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(12, 24, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_ADD_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_ADD_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_LDST8_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_LDST16_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(1, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_LDST32_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(2, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_LDST64_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdSt),
            None,
        ),
        object::elf::R_AARCH64_TLSLE_LDST128_TPREL_LO12
        | object::elf::R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC => (
            RelocationKind::TpOffAArch64,
            RelocationSize::bit_mask(4, 12, RelocationInstruction::LdSt),
            None,
        ),

        // 5.7.11.5 Thread-local storage descriptors
        object::elf::R_AARCH64_TLSDESC_LD_PREL19 => (
            RelocationKind::TlsDesc,
            RelocationSize::bit_mask(2, 21, RelocationInstruction::Ldr),
            None,
        ),
        object::elf::R_AARCH64_TLSDESC_ADR_PREL21 => (
            RelocationKind::TlsDesc,
            RelocationSize::bit_mask(0, 21, RelocationInstruction::Adr),
            None,
        ),
        object::elf::R_AARCH64_TLSDESC_ADR_PAGE21 => (
            RelocationKind::TlsDesc,
            RelocationSize::bit_mask(12, 33, RelocationInstruction::Adr),
            Some(PageMask::GotEntryAndPosition),
        ),
        object::elf::R_AARCH64_TLSDESC_LD64_LO12 => (
            RelocationKind::TlsDescGot,
            RelocationSize::bit_mask(3, 12, RelocationInstruction::LdrRegister),
            None,
        ),
        object::elf::R_AARCH64_TLSDESC_ADD_LO12 => (
            RelocationKind::TlsDescGot,
            RelocationSize::bit_mask(0, 12, RelocationInstruction::Add),
            None,
        ),
        object::elf::R_AARCH64_TLSDESC_OFF_G1 => (
            RelocationKind::TlsDescGotBase,
            RelocationSize::bit_mask(16, 32, RelocationInstruction::Movnz),
            None,
        ),
        object::elf::R_AARCH64_TLSDESC_OFF_G0_NC => (
            RelocationKind::TlsDescGotBase,
            RelocationSize::bit_mask(0, 16, RelocationInstruction::Movkz),
            None,
        ),

        // Misc relocations
        object::elf::R_AARCH64_TLSDESC_CALL => (
            RelocationKind::TlsDescCall,
            RelocationSize::ByteSize(0),
            None,
        ),

        _ => return None,
    };

    Some(RelocationKindInfo { kind, size, mask })
}

impl RelocationInstruction {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // Each instruction links to a chapter in the Arm Architecture Reference Manual for A-profile architecture
    // manual: https://developer.arm.com/documentation/ddi0487/latest/
    pub fn write_to_value(self, extracted_value: u64, negative: bool, dest: &mut [u8]) {
        let mut mask;
        match self {
            // C6.2.13
            RelocationInstruction::Adr => {
                mask = ((extract_bits(extracted_value, 0, 2) as u32) << 29)
                    | ((extract_bits(extracted_value, 2, 32) as u32) << 5);
            }
            // C6.2.252, C6.2.254
            RelocationInstruction::Movkz => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.253, C6.2.254
            RelocationInstruction::Movnz => {
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
            RelocationInstruction::Ldr => {
                mask = (extracted_value as u32) << 5;
            }
            RelocationInstruction::LdrRegister => {
                mask = (extracted_value as u32) << 10;
            }
            // C6.2.5
            RelocationInstruction::Add => {
                mask = (extracted_value as u32) << 10;
            }
            // C7.2.208, C6.2.383
            RelocationInstruction::LdSt => {
                mask = (extracted_value as u32) << 10;
            }
            // C6.2.438
            RelocationInstruction::TstBr => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.34
            RelocationInstruction::Bcond => {
                mask = (extracted_value as u32) << 5;
            }
            // C6.2.33
            RelocationInstruction::JumpCall => {
                mask = extracted_value as u32;
            }
        }
        // Read the original value and combine it with the prepared mask.
        let mask_bytes = &mask.to_le_bytes();
        for (i, v) in mask_bytes.iter().enumerate() {
            dest[i] |= *v;
        }
    }
}
