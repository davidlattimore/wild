use crate::bail;
use crate::elf::Elf;
use crate::error;
use crate::error::Result;
use crate::platform::Platform;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::ppc64_rel_type_to_string;
use linker_utils::ppc64::RelaxationKind;
use linker_utils::relaxation::RelocationModifier;

pub(crate) struct ElfPpc64;

impl crate::platform::Arch for ElfPpc64 {
    type Relaxation = Relaxation;
    type Platform = Elf;

    fn arch_identifier() -> <Self::Platform as Platform>::ArchIdentifier {
        object::elf::EM_PPC64
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::ppc64::relocation_type_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        relocation.ppc64_r_type()
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        ppc64_rel_type_to_string(r_type)
    }

    fn write_plt_entry(
        _plt_entry: &mut [u8],
        _got_address: u64,
        _plt_address: u64,
    ) -> crate::error::Result {
        bail!("PLT generation for ppc64 is not yet implemented");
    }

    /// The thread pointer (`r13`) points 0x7000 bytes past the start of the static TLS block.
    fn tp_offset_start(layout: &crate::layout::Layout<Elf>) -> u64 {
        layout.tls_start_address() + 0x7000
    }

    /// DTV entries point 0x8000 bytes past the start of each module's TLS block.
    fn get_dtv_offset() -> u64 {
        0x8000
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }

    fn merge_eflags(
        eflags: impl Iterator<Item = object::elf::FileFlags>,
    ) -> Result<object::elf::FileFlags> {
        Ok(eflags.fold(object::elf::FileFlags(0), |merged, flags| merged | flags))
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
    }

    #[allow(unused_variables)]
    #[inline(always)]
    fn new_relaxation(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
        relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation>
    where
        Self: std::marker::Sized,
    {
        None
    }

    fn get_source_info<'data>(
        object: &<Self::Platform as Platform>::File<'data>,
        relocations: &<Self::Platform as Platform>::RelocationSections,
        section: &<Self::Platform as Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<crate::platform::SourceInfo> {
        crate::dwarf_address_info::get_source_info::<Self>(
            object,
            relocations,
            section,
            offset_in_section,
        )
    }
}

// Relaxations are not yet implemented for ppc64, so `new_relaxation` always returns `None` and
// this type is never constructed.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        self.kind.apply(section_bytes, offset_in_section, addend);
    }

    fn rel_info(&self) -> RelocationKindInfo {
        self.rel_info
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        &self.kind
    }

    fn next_modifier(&self) -> RelocationModifier {
        self.kind.next_modifier()
    }

    fn is_mandatory(&self) -> bool {
        self.mandatory
    }
}
