//! Abstraction over different CPU architectures for ELF.

use crate::OutputKind;
use crate::arch::Architecture;
use crate::error::Result;
use crate::layout::Layout;
use crate::layout::PropertyClass;
use crate::value_flags::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::SectionFlags;
use linker_utils::relaxation::RelocationModifier;
use object::SectionIndex;
use std::borrow::Cow;

pub(crate) trait ElfArch {
    type Relaxation: Relaxation;

    // Architecture identifier
    const KIND: Architecture;

    // Get ELF header magic for the architecture.
    fn elf_header_arch_magic() -> u16;

    // Get dynamic relocation value specific for the architecture.
    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32;

    // Write PLT entry for the architecture.
    fn write_plt_entry(plt_entry: &mut [u8], got_address: u64, plt_address: u64) -> Result;

    // Make architecture-specific parsing of the relocation types.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo>;

    // Get string representation of a relocation specific for the architecture.
    fn rel_type_to_string(r_type: u32) -> Cow<'static, str>;

    // Get DTV OFFSET.
    fn get_dtv_offset() -> u64 {
        0
    }

    // Some architectures use debug info relocation that depend on local symbols.
    fn local_symbols_in_debug_info() -> bool;

    // Get position of the $tp (thread pointer) in the TLS section. Each platform defines
    // a different place based on the following article:
    // https://maskray.me/blog/2021-02-14-all-about-thread-local-storage#tls-variants
    fn tp_offset_start(layout: &Layout) -> u64;

    // Classify a GNU property note.
    fn get_property_class(property_type: u32) -> Option<PropertyClass>;

    // Merge e_flags of the input files and provide an error
    // if the flags are not compatible.
    fn merge_eflags(eflags: &[u32]) -> Result<u32>;

    // A list of high-part relocations that need to be tracked in a relocation cache
    fn high_part_relocations() -> &'static [u32];
}

pub(crate) trait Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: SectionFlags,
        non_zero_address: bool,
    ) -> Option<Self>
    where
        Self: std::marker::Sized;

    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64);

    fn rel_info(&self) -> RelocationKindInfo;

    fn debug_kind(&self) -> impl std::fmt::Debug;

    fn next_modifier(&self) -> RelocationModifier;

    fn is_mandatory(&self) -> bool;
}

#[expect(unused)]
pub(crate) struct RelaxSymbolInfo {
    /// The section in which the symbol is defined.
    pub section_index: SectionIndex,
    /// The symbol's offset within its section.
    pub offset: u64,
    /// Whether the symbol may be interposed at runtime.
    pub is_interposable: bool,
}
