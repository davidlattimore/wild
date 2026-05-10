// TODO
#![allow(unused_variables)]

use crate::wasm::Wasm;

pub(crate) struct WasmWasm32;

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
        // Placeholder so the trait method type-checks.
        "WasmRelaxation"
    }

    fn next_modifier(&self) -> linker_utils::relaxation::RelocationModifier {
        todo!()
    }

    fn is_mandatory(&self) -> bool {
        false
    }
}

impl crate::platform::Arch for WasmWasm32 {
    type Relaxation = Relaxation;

    type Platform = Wasm;

    fn arch_identifier() -> <Self::Platform as crate::platform::Platform>::ArchIdentifier {}

    fn get_dynamic_relocation_type(relocation: linker_utils::elf::DynamicRelocationKind) -> u32 {
        todo!()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        // Wasm has no PLT.
        unreachable!("wasm has no PLT")
    }

    fn relocation_from_raw(
        r_type: <Self::Platform as crate::platform::Platform>::RelocationInfo,
    ) -> crate::error::Result<linker_utils::elf::RelocationKindInfo> {
        // TODO: map Wasm reloc type codes (R_WASM_*) to RelocationKindInfo.
        todo!()
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(format!("R_WASM_{r_type}"))
    }

    fn tp_offset_start(layout: &crate::layout::Layout<Self::Platform>) -> u64 {
        // Wasm has no TLS yet.
        0
    }

    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass> {
        // Wasm has no GNU property notes.
        None
    }

    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> crate::error::Result<u32> {
        // Wasm has no e_flags equivalent.
        Ok(0)
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
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
        // Wasm doesn't currently support any relaxations.
        None
    }
}
