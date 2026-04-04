// Mach-O ARM64 architecture support.
#![allow(unused_variables)]

use crate::macho::MachO;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::AllowedRange;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::relaxation::RelocationModifier;
use object::macho;

pub(crate) struct MachOAArch64;

/// Mach-O ARM64 relocation types mapped to our internal representation.
fn macho_aarch64_relocation_from_raw(r_type: u32) -> Option<RelocationKindInfo> {
    let (kind, size, range, alignment) = match r_type as u8 {
        macho::ARM64_RELOC_UNSIGNED => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(8),
            AllowedRange::no_check(),
            1,
        ),
        macho::ARM64_RELOC_BRANCH26 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_aarch64(0, 26, AArch64Instruction::JumpCall),
            AllowedRange::from_bit_size(28, linker_utils::elf::Sign::Signed),
            4,
        ),
        macho::ARM64_RELOC_PAGE21 => (
            RelocationKind::Relative,
            RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
            AllowedRange::from_bit_size(33, linker_utils::elf::Sign::Signed),
            1,
        ),
        macho::ARM64_RELOC_PAGEOFF12 => (
            RelocationKind::AbsoluteLowPart,
            RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::Add),
            AllowedRange::no_check(),
            1,
        ),
        macho::ARM64_RELOC_GOT_LOAD_PAGE21 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
            AllowedRange::from_bit_size(33, linker_utils::elf::Sign::Signed),
            1,
        ),
        macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => (
            RelocationKind::GotRelative,
            RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::LdrRegister),
            AllowedRange::no_check(),
            8,
        ),
        macho::ARM64_RELOC_SUBTRACTOR => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(8),
            AllowedRange::no_check(),
            1,
        ),
        macho::ARM64_RELOC_POINTER_TO_GOT => (
            RelocationKind::GotRelative,
            RelocationSize::ByteSize(4),
            AllowedRange::from_bit_size(32, linker_utils::elf::Sign::Signed),
            1,
        ),
        macho::ARM64_RELOC_TLVP_LOAD_PAGE21 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_aarch64(12, 33, AArch64Instruction::Adr),
            AllowedRange::from_bit_size(33, linker_utils::elf::Sign::Signed),
            1,
        ),
        macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => (
            RelocationKind::TlsGd,
            RelocationSize::bit_mask_aarch64(0, 12, AArch64Instruction::Add),
            AllowedRange::no_check(),
            1,
        ),
        macho::ARM64_RELOC_ADDEND => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            AllowedRange::no_check(),
            1,
        ),
        _ => return None,
    };
    Some(RelocationKindInfo {
        kind,
        size,
        mask: None,
        range,
        alignment,
        bias: 0,
    })
}

fn macho_aarch64_rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
    match r_type as u8 {
        macho::ARM64_RELOC_UNSIGNED => "ARM64_RELOC_UNSIGNED".into(),
        macho::ARM64_RELOC_SUBTRACTOR => "ARM64_RELOC_SUBTRACTOR".into(),
        macho::ARM64_RELOC_BRANCH26 => "ARM64_RELOC_BRANCH26".into(),
        macho::ARM64_RELOC_PAGE21 => "ARM64_RELOC_PAGE21".into(),
        macho::ARM64_RELOC_PAGEOFF12 => "ARM64_RELOC_PAGEOFF12".into(),
        macho::ARM64_RELOC_GOT_LOAD_PAGE21 => "ARM64_RELOC_GOT_LOAD_PAGE21".into(),
        macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => "ARM64_RELOC_GOT_LOAD_PAGEOFF12".into(),
        macho::ARM64_RELOC_POINTER_TO_GOT => "ARM64_RELOC_POINTER_TO_GOT".into(),
        macho::ARM64_RELOC_TLVP_LOAD_PAGE21 => "ARM64_RELOC_TLVP_LOAD_PAGE21".into(),
        macho::ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => "ARM64_RELOC_TLVP_LOAD_PAGEOFF12".into(),
        macho::ARM64_RELOC_ADDEND => "ARM64_RELOC_ADDEND".into(),
        other => format!("unknown Mach-O ARM64 relocation {other}").into(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {
        // No relaxations for Mach-O yet
    }

    fn rel_info(&self) -> RelocationKindInfo {
        RelocationKindInfo {
            kind: RelocationKind::None,
            size: RelocationSize::ByteSize(0),
            mask: None,
            range: AllowedRange::no_check(),
            alignment: 1,
            bias: 0,
        }
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        "MachORelaxation(none)"
    }

    fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }

    fn is_mandatory(&self) -> bool {
        false
    }
}

impl crate::platform::Arch for MachOAArch64 {
    type Relaxation = Relaxation;
    type Platform = MachO;

    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {
        // Mach-O doesn't use ELF-style arch identifiers
    }

    fn get_dynamic_relocation_type(
        _relocation: linker_utils::elf::DynamicRelocationKind,
    ) -> u32 {
        0
    }

    fn write_plt_entry(
        _plt_entry: &mut [u8],
        _got_address: u64,
        _plt_address: u64,
    ) -> crate::error::Result {
        // Mach-O uses stubs instead of PLT entries; handled separately
        Ok(())
    }

    fn relocation_from_raw(r_type: u32) -> crate::error::Result<RelocationKindInfo> {
        macho_aarch64_relocation_from_raw(r_type).ok_or_else(|| {
            crate::error!(
                "Unsupported Mach-O ARM64 relocation type {}",
                macho_aarch64_rel_type_to_string(r_type)
            )
        })
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        macho_aarch64_rel_type_to_string(r_type)
    }

    fn tp_offset_start(_layout: &crate::layout::Layout<Self::Platform>) -> u64 {
        0
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }

    fn merge_eflags(_eflags: impl Iterator<Item = u32>) -> crate::error::Result<u32> {
        Ok(0)
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
    }

    fn get_source_info<'data>(
        _object: &<Self::Platform as crate::platform::Platform>::File<'data>,
        _relocations: &<Self::Platform as crate::platform::Platform>::RelocationSections,
        _section: &<Self::Platform as crate::platform::Platform>::SectionHeader,
        _offset_in_section: u64,
    ) -> crate::error::Result<crate::platform::SourceInfo> {
        Ok(crate::platform::SourceInfo(None))
    }

    fn new_relaxation(
        _relocation_kind: u32,
        _section_bytes: &[u8],
        _offset_in_section: u64,
        _flags: crate::value_flags::ValueFlags,
        _output_kind: crate::output_kind::OutputKind,
        _section_flags: <Self::Platform as crate::platform::Platform>::SectionFlags,
        _non_zero_address: bool,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation> {
        None
    }
}
