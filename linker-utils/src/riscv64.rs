use crate::elf::AllowedRange;
use crate::elf::RISCVInstruction;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::extract_bit;
use crate::elf::extract_bits;
use crate::relaxation::RelocationModifier;
use crate::utils::and_from_slice;
use crate::utils::or_from_slice;
use leb128;
use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,

    /// Replace with nop
    ReplaceWithNop,
}

impl RelaxationKind {
    pub fn apply(self, section_bytes: &mut [u8], offset_in_section: &mut u64, _addend: &mut i64) {
        let offset = *offset_in_section as usize;
        match self {
            RelaxationKind::NoOp => {}
            RelaxationKind::ReplaceWithNop => {
                section_bytes[offset..offset + 4].copy_from_slice(&[
                    0x01, 0x0, // nop
                    0x01, 0x0, // nop
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
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::BType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_JAL => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::JType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT => (
            RelocationKind::PltRelative,
            RelocationSize::bit_mask_riscv(0, 64, RISCVInstruction::UIType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_GOT_HI20 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TLS_GOT_HI20 => (
            RelocationKind::GotTpOff,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TLS_GD_HI20 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_PCREL_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_PCREL_LO12_I => (
            RelocationKind::RelativeRISCVLow12,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::IType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_PCREL_LO12_S => (
            RelocationKind::RelativeRISCVLow12,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::SType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_HI20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_LO12_I => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::IType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_LO12_S => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::SType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TPREL_HI20 => (
            RelocationKind::TpOffRiscV,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::UType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TPREL_LO12_I => (
            RelocationKind::TpOffRiscV,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::IType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TPREL_LO12_S => (
            RelocationKind::TpOffRiscV,
            RelocationSize::bit_mask_riscv(0, 32, RISCVInstruction::SType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_TPREL_ADD => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
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
        object::elf::R_RISCV_GOT32_PCREL => (
            RelocationKind::GotRelative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        // TODO: right now, no relaxation is implemented and so we can skip the relocation
        object::elf::R_RISCV_ALIGN => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_RVC_BRANCH => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 16, RISCVInstruction::CBType),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_RVC_JUMP => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 16, RISCVInstruction::CJType),
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
            RelocationKind::AbsoluteSetWord6,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET8 => (
            RelocationKind::AbsoluteSet,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET16 => (
            RelocationKind::AbsoluteSet,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SET32 => (
            RelocationKind::AbsoluteSet,
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
        object::elf::R_RISCV_PLT32 => (
            RelocationKind::PltRelative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        // We process the subtraction in the SUB_ULEB128 relocation,
        // thus we skip the first relocation in the pair.
        object::elf::R_RISCV_SET_ULEB128 => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_SUB_ULEB128 => (
            RelocationKind::PairSubtraction,
            RelocationSize::bit_mask_riscv(0, 64, RISCVInstruction::ULEB128),
            None,
            AllowedRange::no_check(),
            1,
        ),
        // TODO: support TLSDESC once glibc supports the feature: #712
        object::elf::R_RISCV_TLSDESC_HI20 => return None,
        object::elf::R_RISCV_TLSDESC_LOAD_LO12 => return None,
        object::elf::R_RISCV_TLSDESC_ADD_LO12 => return None,
        object::elf::R_RISCV_TLSDESC_CALL => return None,
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

const UTYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_0000_0000_1111_1111_1111;
const ITYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_1111_1111_1111_1111_1111;
const STYPE_IMMEDIATE_MASK: u32 = 0b0000_0001_1111_1111_1111_0000_0111_1111;
const BTYPE_IMMEDIATE_MASK: u32 = 0b0000_0001_1111_1111_1111_0000_0111_1111;
const JTYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_0000_0000_1111_1111_1111;

const CBTYPE_IMMEDIATE_MASK: u16 = 0b1110_0011_1000_0011;
const CJTYPE_IMMEDIATE_MASK: u16 = 0b1110_0000_0000_0011;

impl RISCVInstruction {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // A handy page where one can easily find instruction encoding:
    // https://msyksphinz-self.github.io/riscv-isadoc/html/index.html.

    // During the build of the static libc.a, there are various places where the immediate operand
    // of an instruction is already filled up. Thus, we zero the bits before a relocation value is applied.
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        match self {
            RISCVInstruction::UIType => {
                RISCVInstruction::UType.write_to_value(extracted_value, _negative, &mut dest[..4]);
                RISCVInstruction::IType.write_to_value(extracted_value, _negative, &mut dest[4..]);
            }
            RISCVInstruction::UType => {
                // A final address calculation is represented as addition of HI20 and LO12, where
                // we must prevent add 0x800 in order to not make HI20 a huge negative if the final
                // value is a small negative value.
                // For instance, -10i32 (0xfffffff6) should become 0x0 (HI20) and 0xff6 (LO12).
                let mask = (extract_bits(extracted_value.wrapping_add(0x800), 12, 32) as u32) << 12;
                and_from_slice(dest, UTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RISCVInstruction::IType => {
                let mask = extracted_value << 20;
                and_from_slice(dest, ITYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RISCVInstruction::SType => {
                let mut mask = extract_bits(extracted_value, 0, 5) << 7;
                mask |= extract_bits(extracted_value, 5, 12) << 25;
                and_from_slice(dest, STYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RISCVInstruction::BType => {
                let mut mask = extract_bit(extracted_value, 11) << 7;
                mask |= extract_bits(extracted_value, 1, 5) << 8;
                mask |= extract_bits(extracted_value, 5, 11) << 25;
                mask |= extract_bit(extracted_value, 12) << 31;
                and_from_slice(dest, BTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RISCVInstruction::JType => {
                let mut mask = extract_bits(extracted_value, 12, 20) << 12;
                mask |= extract_bit(extracted_value, 11) << 20;
                mask |= extract_bits(extracted_value, 1, 11) << 21;
                mask |= extract_bit(extracted_value, 20) << 31;
                and_from_slice(dest, JTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RISCVInstruction::CBType => {
                let mut mask = extract_bit(extracted_value, 5) << 2;
                mask |= extract_bits(extracted_value, 1, 3) << 3;
                mask |= extract_bits(extracted_value, 6, 8) << 5;
                // rs1' register takes 3 bits here
                mask |= extract_bits(extracted_value, 3, 5) << 10;
                mask |= extract_bit(extracted_value, 8) << 12;
                // The compressed instruction only takes 2 bytes.
                and_from_slice(dest, CBTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &mask.to_le_bytes()[..2]);
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
                // The compressed instruction only takes 2 bytes.
                and_from_slice(dest, CJTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &mask.to_le_bytes()[..2]);
            }
            RISCVInstruction::ULEB128 => {
                // u64 always fits in 10 bytes in the ULEB format: 64 / 7 = 9.14
                let mut writer = Cursor::new(vec![0u8; 10]);
                let n = leb128::write::unsigned(&mut writer, extracted_value)
                    .expect("Must fit into the buffer");
                dest[..n].copy_from_slice(&writer.into_inner()[..n]);
            }
        };
    }

    /// The inverse of `write_to_value`. Returns `(extracted_value, negative)`. Supplied `bytes`
    /// must be at least 4 bytes, otherwise we panic.
    #[must_use]
    pub fn read_value(self, _bytes: &[u8]) -> (u64, bool) {
        todo!()
    }
}

#[test]
fn test_riscv_insn_immediate_mask() {
    for (mask, insn) in &[
        (UTYPE_IMMEDIATE_MASK, RISCVInstruction::UType),
        (ITYPE_IMMEDIATE_MASK, RISCVInstruction::IType),
        (STYPE_IMMEDIATE_MASK, RISCVInstruction::SType),
        (BTYPE_IMMEDIATE_MASK, RISCVInstruction::BType),
        (JTYPE_IMMEDIATE_MASK, RISCVInstruction::JType),
    ] {
        let mut dest = [0u8; 4];
        let value = if matches!(insn, RISCVInstruction::UType) {
            u64::MAX.wrapping_sub(0x800)
        } else {
            u64::MAX
        };
        insn.write_to_value(value, false, &mut dest);
        assert_eq!(!mask, u32::from_le_bytes(dest));
    }
}

#[test]
fn test_riscv_insn_rvcimmediate_mask() {
    for (mask, insn) in &[
        (CBTYPE_IMMEDIATE_MASK, RISCVInstruction::CBType),
        (CJTYPE_IMMEDIATE_MASK, RISCVInstruction::CJType),
    ] {
        let mut dest = [0u8; 2];
        insn.write_to_value(u64::from(u16::MAX), false, &mut dest);
        assert_eq!(!mask, u16::from_le_bytes(dest));
    }
}
