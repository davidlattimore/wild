// WASM architecture support.
#![allow(unused_variables)]

use crate::wasm::Wasm;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
use linker_utils::relaxation::RelocationModifier;

pub(crate) struct WasmArch;

#[derive(Debug, Clone)]
pub(crate) struct Relaxation;

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {}

    fn rel_info(&self) -> RelocationKindInfo {
        RelocationKindInfo {
            kind: RelocationKind::None,
            size: RelocationSize::ByteSize(0),
            mask: None,
            range: linker_utils::elf::AllowedRange::no_check(),
            alignment: 1,
            bias: 0,
        }
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        "WasmRelaxation(none)"
    }

    fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }

    fn is_mandatory(&self) -> bool {
        false
    }
}

impl crate::platform::Arch for WasmArch {
    type Relaxation = Relaxation;
    type Platform = Wasm;

    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {}

    fn get_dynamic_relocation_type(_relocation: linker_utils::elf::DynamicRelocationKind) -> u32 {
        0
    }

    fn write_plt_entry(
        _plt_entry: &mut [u8],
        _got_address: u64,
        _plt_address: u64,
    ) -> crate::error::Result {
        Ok(())
    }

    fn relocation_from_raw(r_type: u32) -> crate::error::Result<RelocationKindInfo> {
        crate::bail!("WASM relocation type {r_type} not yet supported")
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        format!("R_WASM_{r_type}").into()
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
