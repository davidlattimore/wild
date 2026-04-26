// TODO
#![allow(unused_variables)]

use crate::bail;
use crate::macho::MachO;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::AllowedRange;
use linker_utils::elf::PAGE_MASK_4GB;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::Sign;

pub(crate) struct MachOAArch64;

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        todo!()
    }

    fn rel_info(&self) -> linker_utils::elf::RelocationKindInfo {
        todo!()
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        todo!()
    }

    fn next_modifier(&self) -> linker_utils::relaxation::RelocationModifier {
        todo!()
    }

    fn is_mandatory(&self) -> bool {
        todo!()
    }
}

impl crate::platform::Arch for MachOAArch64 {
    type Relaxation = Relaxation;

    type Platform = MachO;

    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {
        todo!()
    }

    fn get_dynamic_relocation_type(relocation: linker_utils::elf::DynamicRelocationKind) -> u32 {
        todo!()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        todo!()
    }

    fn relocation_from_raw(
        rel: object::macho::RelocationInfo,
    ) -> crate::error::Result<RelocationKindInfo> {
        let rel_size_in_bytes = 1 << rel.r_type;
        let rel_kind = if rel.r_pcrel {
            RelocationKind::Relative
        } else {
            RelocationKind::Absolute
        };
        let rel_size = RelocationSize::ByteSize(rel_size_in_bytes);

        let (size, mask, range, alignment) = match rel.r_type {
            object::macho::ARM64_RELOC_UNSIGNED => (rel_size, None, AllowedRange::no_check(), 1),
            object::macho::ARM64_RELOC_BRANCH26 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationSize::bit_mask_aarch64(2, 28, AArch64Instruction::JumpCall),
                    None,
                    AllowedRange::from_bit_size(28, Sign::Signed),
                    4,
                )
            }
            object::macho::ARM64_RELOC_PAGE21 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4GB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::Add),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            _ => bail!("Unknown relocation: {}", rel.r_type),
        };
        Ok(RelocationKindInfo {
            alignment,
            bias: 0,
            kind: rel_kind,
            mask: None,
            range,
            size: rel_size,
        })
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        todo!()
    }

    fn tp_offset_start(layout: &crate::layout::Layout<Self::Platform>) -> u64 {
        todo!()
    }

    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass> {
        todo!()
    }

    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> crate::error::Result<u32> {
        todo!()
    }

    fn high_part_relocations() -> &'static [u32] {
        todo!()
    }

    fn get_source_info<'data>(
        object: &<Self::Platform as crate::platform::Platform>::File<'data>,
        relocations: &<Self::Platform as crate::platform::Platform>::RelocationSections,
        section: &<Self::Platform as crate::platform::Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> crate::error::Result<crate::platform::SourceInfo> {
        todo!()
    }

    fn new_relaxation(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: <Self::Platform as crate::platform::Platform>::SectionFlags,
        non_zero_address: bool,
        relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation> {
        todo!()
    }
}
