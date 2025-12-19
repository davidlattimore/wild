use crate::elf::AllowedRange;
use crate::elf::LoongArch64Instruction;
use crate::elf::PAGE_MASK_4KB;
use crate::elf::PageMask;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::relaxation::RelocationModifier;
use crate::utils::or_from_slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,
}

impl RelaxationKind {
    pub fn apply(self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {
        match self {
            RelaxationKind::NoOp => {}
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }
}

#[must_use]
pub const fn relocation_type_from_raw(r_type: u32) -> Option<RelocationKindInfo> {
    // TODO: add link
    let (kind, size, mask, range, alignment) = match r_type {
        object::elf::R_LARCH_NONE => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_32 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::new(-(2i64.pow(31)), 2i64.pow(32)),
            1,
        ),
        object::elf::R_LARCH_64 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),

        // TODO: reorder
        object::elf::R_LARCH_PCALA_HI20 => (
            RelocationKind::Relative2KBiased,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_PCALA_LO12 => (
            RelocationKind::AbsoluteAArch64,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_PCALA64_HI12 => (
            RelocationKind::RelativeLoongArchHigh,
            RelocationSize::bit_mask_loongarch64(52, 64, LoongArch64Instruction::Shift10),
            Some(PageMask::Position(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_PCALA64_LO20 => (
            RelocationKind::RelativeLoongArchHigh,
            RelocationSize::bit_mask_loongarch64(32, 52, LoongArch64Instruction::Shift5),
            Some(PageMask::Position(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_B16 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 18, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_GOT_PC_HI20 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_loongarch64(12, 32, LoongArch64Instruction::Shift5),
            Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_GOT_PC_LO12 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_loongarch64(0, 12, LoongArch64Instruction::Shift10),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_B21 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 23, LoongArch64Instruction::Branch21or26),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_B26 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_loongarch64(2, 28, LoongArch64Instruction::Branch21or26),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_ADD16 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_ADD32 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_ADD64 => (
            RelocationKind::AbsoluteAddition,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_SUB16 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(2),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_SUB32 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_SUB64 => (
            RelocationKind::AbsoluteSubtraction,
            RelocationSize::ByteSize(8),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_32_PCREL => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(4),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_LARCH_RELAX => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),

        // TODO
        object::elf::R_LARCH_ALIGN => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),

        // TODO
        object::elf::R_LARCH_ADD6 | object::elf::R_LARCH_SUB6 => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),

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
            LoongArch64Instruction::Shift32 => {
                let mask = extracted_value;
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            LoongArch64Instruction::Shift52 => {
                let mask = extracted_value << 20;
                or_from_slice(dest, &(mask as u32).to_le_bytes());
            }
            LoongArch64Instruction::Branch21or26 => {
                let low_part = extracted_value >> 16;
                let high_part = (extracted_value & 0xffff) << 10;
                or_from_slice(dest, &((low_part | high_part) as u32).to_le_bytes());
            }
        };
    }

    #[must_use]
    pub fn read_value(self, _bytes: &[u8]) -> (u64, bool) {
        todo!()
    }
}
