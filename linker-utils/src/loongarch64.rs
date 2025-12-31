use crate::elf::AllowedRange;
use crate::elf::LoongArch64Instruction;
use crate::elf::PAGE_MASK_4KB;
use crate::elf::PageMask;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::SIZE_2GB;
use crate::elf::SIZE_2KB;
use crate::elf::SIZE_4GB;
use crate::elf::SIZE_4KB;
use crate::relaxation::RelocationModifier;
use crate::utils::or_from_slice;

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
                    0x03, 0x40, 0x0, 0x0, // nop
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
    // https://github.com/loongson/la-abi-specs/blob/release/laelf.adoc#relocation-types
    let (kind, size, mask, range, alignment, bias) = match r_type {
        object::elf::R_LARCH_NONE => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // Addition and subtraction relocations.
        object::elf::R_LARCH_32 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
            0,
        ),
        object::elf::R_LARCH_64 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD6 => (
            RelocationKind::AbsoluteAdditionWord6,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD8 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD16 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD24 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(3),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD32 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ADD64 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB6 => (
            RelocationKind::AbsoluteSubtractionWord6,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB8 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(1),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB16 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB24 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(3),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB32 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB64 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // We process the subtraction in the SUB_ULEB128 relocation,
        // thus we skip the first relocation in the pair.
        object::elf::R_LARCH_ADD_ULEB128 => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_SUB_ULEB128 => (
            RelocationKind::PairSubtractionULEB128(object::elf::R_LARCH_ADD_ULEB128),
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // General relocations
        object::elf::R_LARCH_ABS_HI20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ABS_LO12 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ABS64_HI12 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ABS64_LO20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_PCALA_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_PCALA_LO12 => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_PCALA64_HI12 => (
            RelocationKind::RelativeLoongArchHigh,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_PCALA64_LO20 => (
            RelocationKind::RelativeLoongArchHigh,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_32_PCREL => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_PCREL20_S2 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 22, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_64_PCREL => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_PCADD_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_PCADD_LO12 => (
            RelocationKind::RelativeRiscVLow12,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // GOT-relative relocations
        object::elf::R_LARCH_GOT_PC_HI20 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::GotEntryAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_GOT_PC_LO12 => (
            RelocationKind::Got,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_GOT64_PC_HI12 => (
            RelocationKind::GotRelativeLoongArch64,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_GOT64_PC_LO20 => (
            RelocationKind::GotRelativeLoongArch64,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // CFG-related relocations.
        object::elf::R_LARCH_B16 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 18, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_B21 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 23, LoongArch64Instruction::Branch21or26),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_B26 => (
            RelocationKind::PltRelative,
            RelocationSize::bit_mask_loongarch64(2, 28, LoongArch64Instruction::Branch21or26),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_CALL36 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 38, LoongArch64Instruction::Call36),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_CALL30 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 19, LoongArch64Instruction::Call30),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // TLS-related relocations (traditional).
        object::elf::R_LARCH_TLS_LE_HI20 => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_LE_LO12 => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_LE64_LO20 => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_LE64_HI12 => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_LE_HI20_R => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_TLS_LE_LO12_R => (
            RelocationKind::TpOff,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE_PC_HI20 => (
            RelocationKind::GotTpOff,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::GotEntryAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_TLS_IE_PC_LO12 => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE64_PC_LO20 => (
            RelocationKind::GotTpOffLoongArch64,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE64_PC_HI12 => (
            RelocationKind::GotTpOffLoongArch64,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE_HI20 => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE_LO12 => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE64_HI12 => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_IE64_LO20 => (
            RelocationKind::GotTpOffGot,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // It's a known limitation the ABI does not properly support TLS LD:
        // https://github.com/loongson/la-abi-specs/issues/19
        object::elf::R_LARCH_TLS_LD_PC_HI20 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::GotEntryAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_TLS_LD_HI20 => (
            RelocationKind::TlsGdGot,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_GD_PC_HI20 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::GotEntryAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_TLS_GD_HI20 => (
            RelocationKind::TlsGdGot,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // TLS-related relocations (TLS descriptors).
        object::elf::R_LARCH_TLS_DESC_PC_HI20 => (
            RelocationKind::TlsDesc,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::GotEntryAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
            SIZE_2KB,
        ),
        object::elf::R_LARCH_TLS_DESC_PC_LO12 => (
            RelocationKind::TlsDescGot,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_DESC64_PC_HI12 => (
            RelocationKind::TlsDescLoongArch64,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_DESC64_PC_LO20 => (
            RelocationKind::TlsDescLoongArch64,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            // Mark is applied directly in the relocation!
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_DESC_LD => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_TLS_DESC_CALL => (
            RelocationKind::TlsDescCall,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        // Misc relocations.
        object::elf::R_LARCH_RELAX | object::elf::R_LARCH_TLS_LE_ADD_R => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        object::elf::R_LARCH_ALIGN => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
            0,
        ),
        _ => return None,
    };

    Some(RelocationKindInfo {
        kind,
        size,
        mask,
        range,
        alignment,
        bias,
    })
}

impl LoongArch64Instruction {
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        match self {
            LoongArch64Instruction::Shift5 => {
                let mask = extracted_value << 5;
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            LoongArch64Instruction::Shift10 => {
                let mask = extracted_value << 10;
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            LoongArch64Instruction::Branch21or26 => {
                let low_part = (extracted_value & 0xffff) << 10;
                let high_part = extracted_value >> 16;
                or_from_slice(dest, &((low_part | high_part) as u32).to_le_bytes());
            }
            LoongArch64Instruction::Call30 => {
                let low_part = (extracted_value & 0x1ff) << (32 + 10);
                let high_part = (extracted_value & !0x1ff) << 5;
                or_from_slice(dest, &(low_part | high_part).to_le_bytes());
            }
            LoongArch64Instruction::Call36 => {
                let low_part = (extracted_value & 0xffff) << (32 + 10);
                let high_part = ((extracted_value + 0x8000) >> 16) << 5;
                or_from_slice(dest, &(low_part | high_part).to_le_bytes());
            }
        };
    }

    #[must_use]
    pub fn read_value(self, _bytes: &[u8]) -> (u64, bool) {
        todo!()
    }
}

// Documentation definition:
// (*(uint32_t *) PC) [24 ... 5] = (((S+A+0x8000'0000 + (((S+A) & 0x800) ?
// (0x1000-0x1'0000'0000) : 0)) & ~0xfff) - (PC-8 & ~0xfff)) [51 ... 32]
#[must_use]
pub fn highest_relocation_with_bias(symbol_with_addend: u64, pc: u64) -> u64 {
    ((symbol_with_addend.wrapping_add(SIZE_2GB).wrapping_add(
        if symbol_with_addend & SIZE_2KB != 0 {
            SIZE_4KB.wrapping_sub(SIZE_4GB)
        } else {
            0
        },
    )) & !PAGE_MASK_4KB)
        .wrapping_sub((pc.wrapping_sub(8)) & !PAGE_MASK_4KB)
}
