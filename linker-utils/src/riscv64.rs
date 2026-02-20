use crate::bit_misc::BitExtraction;
use crate::elf::AllowedRange;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::RiscVInstruction;
use crate::relaxation::RelocationModifier;
use crate::utils::and_from_slice;
use crate::utils::or_from_slice;
use crate::utils::u32_from_slice;

/// JAL instruction range: signed 21-bit immediate, 2-byte aligned.
pub const JAL_RANGE: std::ops::RangeInclusive<i64> = -(1i64 << 20)..=((1i64 << 20) - 1);

#[inline]
#[must_use]
pub fn distance_fits_jal(distance: i64) -> bool {
    JAL_RANGE.contains(&distance)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,

    /// Replace with nop
    ReplaceWithNop,

    /// Rewrite auipc+jalr to jal.
    CallToJal,

    /// Rewrite 4-byte `lui rd, imm` to 2-byte `c.lui rd, nzimm`.
    Hi20ToCLui,
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
            RelaxationKind::CallToJal => {
                let auipc_word = u32_from_slice(&section_bytes[offset..]);
                let rd = (auipc_word >> 7) & 0x1f;
                let jal_base = 0x6fu32 | (rd << 7);
                section_bytes[offset..offset + 4].copy_from_slice(&jal_base.to_le_bytes());
            }
            RelaxationKind::Hi20ToCLui => {
                let lui_lo = u16::from_le_bytes([section_bytes[offset], section_bytes[offset + 1]]);
                let rd = (lui_lo >> 7) & 0x1f;
                let clui_base: u16 = 0x6001 | (rd << 7);
                section_bytes[offset..offset + 2].copy_from_slice(&clui_base.to_le_bytes());
            }
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        match self {
            RelaxationKind::CallToJal => RelocationModifier::SkipNextRelocation,
            _ => RelocationModifier::Normal,
        }
    }

    /// Returns true if the HI20 value (i.e. `(value + 0x800) >> 12`) fits in the
    /// c.lui 6-bit signed non-zero immediate range: [-32, -1] ∪ [1, 31].
    #[must_use]
    pub fn hi20_fits_clui(value: u64) -> bool {
        let hi20 = value.wrapping_add(0x800) >> 12;
        let hi20_signed = hi20 as i64;
        // The 6-bit signed immediate excludes 0, and wraps around for large values.
        // Check that the sign-extended 6-bit value equals the full hi20.
        let as_6bit = ((hi20_signed as i8) << 2) >> 2; // sign-extend from 6 bits
        i64::from(as_6bit) == hi20_signed && hi20_signed != 0
    }

    /// Returns true if the rd register is valid for c.lui.
    #[must_use]
    pub fn rd_valid_for_clui(rd: u32) -> bool {
        rd != 0 && rd != 2
    }

    /// Returns the `RelocationKindInfo` to use when a HI20 relocation has been relaxed to c.lui.
    #[must_use]
    pub fn clui_rel_info() -> RelocationKindInfo {
        RelocationKindInfo {
            kind: RelocationKind::Absolute,
            size: RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::CluiType),
            mask: None,
            range: AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            alignment: 1,
            bias: 0,
        }
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
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
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
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::BType),
            None,
            AllowedRange::new(-(2i64.pow(12)), 2i64.pow(13) - 2),
            1,
        ),
        object::elf::R_RISCV_JAL => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::JType),
            None,
            AllowedRange::new(-(2i64.pow(20)), 2i64.pow(20) - 2),
            1,
        ),
        object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT => (
            RelocationKind::PltRelative,
            RelocationSize::bit_mask_riscv(0, 64, RiscVInstruction::UiType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_GOT_HI20 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_TLS_GOT_HI20 => (
            RelocationKind::GotTpOff,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_TLS_GD_HI20 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_PCREL_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_PCREL_LO12_I => (
            RelocationKind::RelativeRiscVLow12,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::IType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_PCREL_LO12_S => (
            RelocationKind::RelativeRiscVLow12,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::SType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_HI20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_LO12_I => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::IType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_LO12_S => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::SType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_TPREL_HI20 => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::UType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_TPREL_LO12_I => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::IType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_TPREL_LO12_S => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_riscv(0, 32, RiscVInstruction::SType),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
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
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_ALIGN => (
            RelocationKind::Alignment,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_RVC_BRANCH => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 16, RiscVInstruction::CbType),
            None,
            AllowedRange::new(-(2i64.pow(8)), 2i64.pow(9) - 2),
            1,
        ),
        object::elf::R_RISCV_RVC_JUMP => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 16, RiscVInstruction::CjType),
            None,
            AllowedRange::new(-(2i64.pow(11)), 2i64.pow(12) - 2),
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
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_RISCV_PLT32 => (
            RelocationKind::PltRelative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
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
            RelocationKind::PairSubtractionULEB128(object::elf::R_RISCV_SET_ULEB128),
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
        ),
        // TODO: #712: support TLSDESC once glibc supports the feature
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
        bias: 0,
    })
}

const UTYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_0000_0000_1111_1111_1111;
const ITYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_1111_1111_1111_1111_1111;
const STYPE_IMMEDIATE_MASK: u32 = 0b0000_0001_1111_1111_1111_0000_0111_1111;
const BTYPE_IMMEDIATE_MASK: u32 = 0b0000_0001_1111_1111_1111_0000_0111_1111;
const JTYPE_IMMEDIATE_MASK: u32 = 0b0000_0000_0000_0000_0000_1111_1111_1111;

const CBTYPE_IMMEDIATE_MASK: u16 = 0b1110_0011_1000_0011;
const CJTYPE_IMMEDIATE_MASK: u16 = 0b1110_0000_0000_0011;
// c.lui: [15:13]=funct3 [12]=nzimm[5] [11:7]=rd [6:2]=nzimm[4:0] [1:0]=op
const CLUITYPE_IMMEDIATE_MASK: u16 = 0b1110_1111_1000_0011;

impl RiscVInstruction {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // A handy page where one can easily find instruction encoding:
    // https://msyksphinz-self.github.io/riscv-isadoc/html/index.html.

    // During the build of the static libc.a, there are various places where the immediate operand
    // of an instruction is already filled up. Thus, we zero the bits before a relocation value is
    // applied.
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        match self {
            RiscVInstruction::UiType => {
                RiscVInstruction::UType.write_to_value(extracted_value, _negative, &mut dest[..4]);
                RiscVInstruction::IType.write_to_value(extracted_value, _negative, &mut dest[4..]);
            }
            RiscVInstruction::UType => {
                // A final address calculation is represented as addition of HI20 and LO12, where
                // we must prevent add 0x800 in order to not make HI20 a huge negative if the final
                // value is a small negative value.
                // For instance, -10i32 (0xfffffff6) should become 0x0 (HI20) and 0xff6 (LO12).
                let mask = (extracted_value
                    .wrapping_add(0x800)
                    .extract_bit_range(12..32) as u32)
                    << 12;
                and_from_slice(dest, UTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &mask.to_le_bytes());
            }
            RiscVInstruction::IType => {
                let mask = extracted_value << 20;
                and_from_slice(dest, ITYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RiscVInstruction::SType => {
                let mut mask = extracted_value.extract_bit_range(0..5) << 7;
                mask |= extracted_value.extract_bit_range(5..12) << 25;
                and_from_slice(dest, STYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RiscVInstruction::BType => {
                let mut mask = extracted_value.extract_bit(11) << 7;
                mask |= extracted_value.extract_bit_range(1..5) << 8;
                mask |= extracted_value.extract_bit_range(5..11) << 25;
                mask |= extracted_value.extract_bit(12) << 31;
                and_from_slice(dest, BTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RiscVInstruction::JType => {
                let mut mask = extracted_value.extract_bit_range(12..20) << 12;
                mask |= extracted_value.extract_bit(11) << 20;
                mask |= extracted_value.extract_bit_range(1..11) << 21;
                mask |= extracted_value.extract_bit(20) << 31;
                and_from_slice(dest, JTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            RiscVInstruction::CbType => {
                let mut mask = extracted_value.extract_bit(5) << 2;
                mask |= extracted_value.extract_bit_range(1..3) << 3;
                mask |= extracted_value.extract_bit_range(6..8) << 5;
                // rs1' register takes 3 bits here
                mask |= extracted_value.extract_bit_range(3..5) << 10;
                mask |= extracted_value.extract_bit(8) << 12;
                // The compressed instruction only takes 2 bytes.
                and_from_slice(dest, CBTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &mask.to_le_bytes()[..2]);
            }
            RiscVInstruction::CjType => {
                let mut mask = extracted_value.extract_bit(5) << 2;
                mask |= extracted_value.extract_bit_range(1..4) << 3;
                mask |= extracted_value.extract_bit(7) << 6;
                mask |= extracted_value.extract_bit(6) << 7;
                mask |= extracted_value.extract_bit(10) << 8;
                mask |= extracted_value.extract_bit_range(8..10) << 9;
                mask |= extracted_value.extract_bit(4) << 11;
                mask |= extracted_value.extract_bit(11) << 12;
                // The compressed instruction only takes 2 bytes.
                and_from_slice(dest, CJTYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &mask.to_le_bytes()[..2]);
            }
            RiscVInstruction::CluiType => {
                let hi20 = extracted_value.wrapping_add(0x800) >> 12;
                let mut mask = (hi20 & 0x1f) << 2; // nzimm[4:0]
                mask |= ((hi20 >> 5) & 1) << 12; // nzimm[5]
                and_from_slice(dest, CLUITYPE_IMMEDIATE_MASK.to_le_bytes().as_slice());
                or_from_slice(dest, &(mask as u16).to_le_bytes());
            }
        };
    }

    /// The inverse of `write_to_value`. Returns `(extracted_value, negative)`. Supplied `bytes`
    /// must be at least 4 bytes, otherwise we panic.
    #[must_use]
    pub fn read_value(self, bytes: &[u8]) -> (u64, bool) {
        match self {
            RiscVInstruction::UiType => {
                let (hi, _) = RiscVInstruction::UType.read_value(&bytes[..4]);
                let (lo, _) = RiscVInstruction::IType.read_value(&bytes[4..]);
                (hi << 12 | lo, false)
            }
            RiscVInstruction::UType => {
                let value = u32_from_slice(bytes);
                let imm = (value >> 12) & 0xfffff;
                let adjusted = ((imm as i32) << 12) >> 12;
                ((adjusted as u64).wrapping_sub(0x800), false)
            }
            RiscVInstruction::IType => {
                let value = u32_from_slice(bytes);
                let imm = (value >> 20) & 0xfff;
                let sign_extended = ((imm as i32) << 20) >> 20;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::SType => {
                let value = u32_from_slice(bytes);
                let imm_low = (value >> 7) & 0x1f;
                let imm_high = (value >> 25) & 0x7f;
                let imm = (imm_high << 5) | imm_low;
                let sign_extended = ((imm as i32) << 20) >> 20;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::BType => {
                let value = u32_from_slice(bytes);
                let imm11 = (value >> 7) & 0x1;
                let imm1_4 = (value >> 8) & 0xf;
                let imm5_10 = (value >> 25) & 0x3f;
                let imm12 = (value >> 31) & 0x1;

                let imm = (imm12 << 12) | (imm11 << 11) | (imm5_10 << 5) | (imm1_4 << 1);
                let sign_extended = ((imm as i32) << 19) >> 19;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::JType => {
                let value = u32_from_slice(bytes);
                let imm12_19 = (value >> 12) & 0xff;
                let imm11 = (value >> 20) & 0x1;
                let imm1_10 = (value >> 21) & 0x3ff;
                let imm20 = (value >> 31) & 0x1;

                let imm = (imm20 << 20) | (imm12_19 << 12) | (imm11 << 11) | (imm1_10 << 1);
                let sign_extended = ((imm as i32) << 11) >> 11;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::CbType => {
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                let imm5 = (value >> 2) & 0x1;
                let imm1_2 = (value >> 3) & 0x3;
                let imm6_7 = (value >> 5) & 0x3;
                let imm3_4 = (value >> 10) & 0x3;
                let imm8 = (value >> 12) & 0x1;

                let imm = (imm8 << 8) | (imm6_7 << 6) | (imm5 << 5) | (imm3_4 << 3) | (imm1_2 << 1);
                let sign_extended = (i32::from(imm) << 23) >> 23;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::CjType => {
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                let imm5 = (value >> 2) & 0x1;
                let imm1_3 = (value >> 3) & 0x7;
                let imm7 = (value >> 6) & 0x1;
                let imm6 = (value >> 7) & 0x1;
                let imm10 = (value >> 8) & 0x1;
                let imm8_9 = (value >> 9) & 0x3;
                let imm4 = (value >> 11) & 0x1;
                let imm11 = (value >> 12) & 0x1;

                let imm = (imm11 << 11)
                    | (imm10 << 10)
                    | (imm8_9 << 8)
                    | (imm7 << 7)
                    | (imm6 << 6)
                    | (imm5 << 5)
                    | (imm4 << 4)
                    | (imm1_3 << 1);
                let sign_extended = (i32::from(imm) << 20) >> 20;
                (sign_extended as u64, sign_extended < 0)
            }
            RiscVInstruction::CluiType => {
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                let nzimm4_0 = (value >> 2) & 0x1f;
                let nzimm5 = (value >> 12) & 0x1;
                let nzimm = (nzimm5 << 5) | nzimm4_0;
                let hi20 = ((i32::from(nzimm) << 26) >> 26) as u64;
                let extracted = (hi20 << 12).wrapping_sub(0x800);
                (extracted, (hi20 as i64) < 0)
            }
        }
    }
}

#[test]
fn test_riscv_insn_immediate_mask() {
    for (mask, insn) in &[
        (UTYPE_IMMEDIATE_MASK, RiscVInstruction::UType),
        (ITYPE_IMMEDIATE_MASK, RiscVInstruction::IType),
        (STYPE_IMMEDIATE_MASK, RiscVInstruction::SType),
        (BTYPE_IMMEDIATE_MASK, RiscVInstruction::BType),
        (JTYPE_IMMEDIATE_MASK, RiscVInstruction::JType),
    ] {
        let mut dest = [0u8; 4];
        let value = if matches!(insn, RiscVInstruction::UType) {
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
        (CBTYPE_IMMEDIATE_MASK, RiscVInstruction::CbType),
        (CJTYPE_IMMEDIATE_MASK, RiscVInstruction::CjType),
    ] {
        let mut dest = [0u8; 2];
        insn.write_to_value(u64::from(u16::MAX), false, &mut dest);
        assert_eq!(!mask, u16::from_le_bytes(dest));
    }
}
