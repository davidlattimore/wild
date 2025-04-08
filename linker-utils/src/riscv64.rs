use crate::elf::AllowedRange;
use crate::elf::RISCVInstruction;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::extract_bits;
use crate::utils::or_from_slice;

#[must_use]
pub const fn relocation_type_from_raw(r_type: u32) -> Option<RelocationKindInfo> {
    let (kind, size, mask, range, alignment) = match r_type {
        object::elf::R_RISCV_NONE | object::elf::R_RISCV_RELAX => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_CALL_PLT => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(0, 64, RISCVInstruction::AuipcJalr),
            None,
            AllowedRange::no_check(),
            1,
        ),
        object::elf::R_RISCV_HI20 => (
            RelocationKind::Absolute,
            RelocationSize::bit_mask_riscv(12, 32, RISCVInstruction::High20),
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
        object::elf::R_RISCV_PCREL_HI20 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_riscv(12, 32, RISCVInstruction::High20),
            None,
            AllowedRange::no_check(),
            1,
        ),
        // TODO: R_RISCV_PCREL_LO12_I is tricky one as it needs to find the position of R_RISCV_PCREL_HI20!
        object::elf::R_RISCV_32_PCREL => (
            RelocationKind::Relative,
            RelocationSize::ByteSize(4),
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
        object::elf::R_RISCV_SUB6 => (
            RelocationKind::AbsoluteSubtractionWord6,
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

impl RISCVInstruction {
    // Encode computed relocation value and store it based on the encoding of an instruction.
    // A handy pages where one can easily find instruction encoding:
    // https://msyksphinz-self.github.io/riscv-isadoc/html/index.html.
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        let mask = match self {
            RISCVInstruction::High20 => (extracted_value as u32) << 12,
            RISCVInstruction::Low12 => (extracted_value as u32) << 20,
            RISCVInstruction::AuipcJalr => {
                let lower = (extract_bits(extracted_value, 0, 12) as u32) << 20;
                let upper = (extract_bits(extracted_value, 12, 32) as u32) << 12;
                or_from_slice(dest, &upper.to_le_bytes());
                or_from_slice(&mut dest[4..], &lower.to_le_bytes());
                return;
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
