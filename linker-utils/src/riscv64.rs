use crate::elf::AllowedRange;
use crate::elf::RISCVInstruction;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::extract_bit;
use crate::elf::extract_bits;
use crate::utils::or_from_slice;

#[must_use]
pub const fn relocation_type_from_raw(r_type: u32) -> Option<RelocationKindInfo> {
    // The relocation listing following the order defined in the standard:
    // https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
    let (kind, size, mask, range, alignment) = match r_type {
        object::elf::R_RISCV_NONE => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_32 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_64 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_BRANCH => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 12, RISCVInstruction::BType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_JAL => return None, // TODO: support
        object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 64, RISCVInstruction::AuipcJalr),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_GOT_HI20 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::High20),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TLS_GOT_HI20 => return None, // TODO: support
        object::elf::R_RISCV_TLS_GD_HI20 => return None,  // TODO: support
        object::elf::R_RISCV_PCREL_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::High20),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_PCREL_LO12_I | object::elf::R_RISCV_PCREL_LO12_S => (
            RelocationKind::RelativeRISCVLow12,
            RelocationSize::bit_mask_riscv(0, 12, RISCVInstruction::Low12),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_HI20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::High20),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_LO12_I | object::elf::R_RISCV_LO12_S => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 12, RISCVInstruction::Low12),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TPREL_ADD => return None, // TODO: support
        object::elf::R_RISCV_ADD8 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_ADD16 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_ADD32 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_ADD64 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB8 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB16 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB32 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB64 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_GOT32_PCREL => return None, // TODO: support
        object::elf::R_RISCV_ALIGN => return None,       // TODO: support
        object::elf::R_RISCV_RVC_BRANCH => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 9, RISCVInstruction::CBType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_RVC_JUMP => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 12, RISCVInstruction::CJType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_RELAX => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB6 => (
            RelocationKind::AbsoluteSubtractionWord6,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET6 => (
            RelocationKind::AbsoluteWord6,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET8 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET16 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET32 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_32_PCREL => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_PLT32 => return None, // TODO: support
        object::elf::R_RISCV_SET_ULEB128 => return None, // TODO: support
        object::elf::R_RISCV_SUB_ULEB128 => return None, // TODO: support
        object::elf::R_RISCV_TLSDESC_HI20 => return None, // TODO: support
        object::elf::R_RISCV_TLSDESC_LOAD_LO12 => return None, // TODO: support
        object::elf::R_RISCV_TLSDESC_ADD_LO12 => return None, // TODO: support
        object::elf::R_RISCV_TLSDESC_CALL => return None, // TODO: support
        _ => return None,
    };

    Some(RelocationKindInfo {
        kind,
        size,
        mask,
        range,
        alignment,
    })
}

// A final address calculation is represented as addition of HI20 and LO12, where
// we must prevent add 0x800 in order to not make HI20 a huge negative if the final
// value is a small negative value.
// For instance, -10i32 (0xfffffff6) should become 0x0 (HI20) and 0xff6 (LO12).
const RISCV_HI20_ADDEND: u64 = 0x800;

impl RISCVInstruction {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // A handy pages where one can easily find instruction encoding:
    // https://msyksphinz-self.github.io/riscv-isadoc/html/index.html.
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        let mask = match self {
            RISCVInstruction::High20 => {
                (extract_bits(extracted_value.wrapping_add(RISCV_HI20_ADDEND), 12, 32) as u32) << 12
            }
            RISCVInstruction::Low12 => (extracted_value as u32) << 20,
            RISCVInstruction::AuipcJalr => {
                let lower = (extract_bits(extracted_value, 0, 12) as u32) << 20;
                let upper = (extract_bits(extracted_value.wrapping_add(RISCV_HI20_ADDEND), 12, 32)
                    as u32)
                    << 12;
                or_from_slice(dest, &upper.to_le_bytes());
                or_from_slice(&mut dest[4..], &lower.to_le_bytes());
                return;
            }
            RISCVInstruction::BType => {
                let mut mask = extract_bits(extracted_value, 11, 12) << 7;
                mask |= extract_bits(extracted_value, 1, 5) << 8;
                mask |= extract_bits(extracted_value, 5, 11) << 25;
                mask |= extract_bit(extracted_value, 12) << 31;
                mask as u32
            }
            RISCVInstruction::CBType => {
                let mut mask = extract_bit(extracted_value, 5) << 2;
                mask |= extract_bits(extracted_value, 1, 3) << 3;
                mask |= extract_bits(extracted_value, 6, 8) << 5;
                mask |= extract_bits(extracted_value, 3, 5) << 10;
                mask |= extract_bit(extracted_value, 8) << 12;
                mask as u32
            }
            RISCVInstruction::CJType => {
                let mut mask = extract_bit(extracted_value, 5) << 2;
                mask |= extract_bits(extracted_value, 1, 4) << 3;
                mask |= extract_bit(extracted_value, 7) << 6;
                mask |= extract_bit(extracted_value, 6) << 7;
                mask |= extract_bit(extracted_value, 10) << 8;
                mask |= extract_bits(extracted_value, 8, 10) << 9;
                mask |= extract_bit(extracted_value, 4) << 11;
                mask |= extract_bit(extracted_value, 11) << 12;
                mask as u32
            }
        };
        // Read the original value and combine it with the prepared mask.
        or_from_slice(dest, &mask.to_le_bytes());
    }

    /// The inverse of `write_to_value`. Returns `(extracted_value, negative)`. Supplied `bytes`
    /// must be at least 4 bytes, otherwise we panic.
    #[must_use]
    pub fn read_value(self, _bytes: &[u8]) -> (u64, bool) {
        todo!()
    }
}
