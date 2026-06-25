// TODO
#![allow(unused_variables)]

use crate::bail;
use crate::ensure;
use crate::macho::MachO;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::AllowedRange;
use linker_utils::elf::PAGE_MASK_4KB;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::elf::SIZE_4KB;
use linker_utils::elf::Sign;
use std::borrow::Cow;

pub(crate) struct MachOAArch64;

// ADRP+ADD+BR symbol stub template.
const STUB_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // ADRP x16, page(got)
    0x10, 0x02, 0x40, 0xf9, // LDR  x16, [x16, #off]
    0x00, 0x02, 0x1f, 0xd6, // BR   x16
];

const _ASSERTS: () = {
    assert!(STUB_TEMPLATE.len() as u64 == crate::macho::PLT_ENTRY_SIZE);
};

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
    fn start_memory_address(_output_kind: crate::output_kind::OutputKind) -> u64 {
        crate::macho::MACHO_START_MEM_ADDRESS
    }
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
        // TODO: For simplicity, we assume now the PLT entry precedes the GOT entry, so we can
        // make the offset calculation in the unsigned type.
        debug_assert!(plt_address < got_address);

        plt_entry.copy_from_slice(STUB_TEMPLATE);
        let plt_page_address = plt_address & !PAGE_MASK_4KB;
        let offset = got_address.wrapping_sub(plt_page_address);
        ensure!(
            offset < (1 << 32),
            "Mach-O stub is more than 4GiB away from GOT"
        );
        AArch64Instruction::Adr.write_to_value(offset / SIZE_4KB, false, &mut plt_entry[0..4]);
        AArch64Instruction::MachOLow12.write_to_value(
            offset & PAGE_MASK_4KB,
            false,
            &mut plt_entry[4..8],
        );
        Ok(())
    }

    fn relocation_from_raw(
        rel: object::macho::RelocationInfo,
    ) -> crate::error::Result<RelocationKindInfo> {
        let rel_size_in_bytes = 1 << rel.r_length;
        let rel_size = RelocationSize::ByteSize(rel_size_in_bytes);
        let rel_kind = if rel.r_pcrel {
            RelocationKind::Relative
        } else {
            RelocationKind::Absolute
        };

        let (kind, size, mask, range, alignment) = match rel.r_type {
            object::macho::ARM64_RELOC_UNSIGNED => {
                (rel_kind, rel_size, None, AllowedRange::no_check(), 1)
            }
            object::macho::ARM64_RELOC_BRANCH26 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    rel_kind,
                    RelocationSize::bit_mask_aarch64(2, 28, AArch64Instruction::JumpCall),
                    None,
                    AllowedRange::from_bit_size(28, Sign::Signed),
                    4,
                )
            }
            object::macho::ARM64_RELOC_PAGE21 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    rel_kind,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::AbsoluteLowPart,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
                    None,
                    AllowedRange::no_check(),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGE21 => {
                debug_assert_eq!(rel_kind, RelocationKind::Relative);
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::GotRelative,
                    RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
                    Some(PageMask::SymbolPlusAddendAndPosition(PAGE_MASK_4KB)),
                    AllowedRange::from_bit_size(33, Sign::Signed),
                    1,
                )
            }
            object::macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                debug_assert_eq!(rel_size, RelocationSize::ByteSize(4));
                (
                    RelocationKind::Got,
                    RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::MachOLow12),
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
            kind,
            mask,
            range,
            size,
            thunkable: false,
        })
    }

    fn rel_type_to_string(r_type: u32) -> Cow<'static, str> {
        if let Some(name) = object::macho::NAMES_ARM64_RELOC.name(r_type as u8) {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("Unknown arm64 relocation type 0x{r_type:x}"))
        }
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
        Ok(crate::platform::SourceInfo(None))
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
