//! Format-agnostic layout types shared across all output formats (ELF, PE).
//! ELF-specific layout code lives in `elf_layout.rs`.

use crate::alignment::Alignment;
use crate::elf_layout::ElfLayout;
use crate::output_section_id::OutputSectionId;
use crate::parsing::InternalSymDefInfo;
use crate::part_id::PartId;
use crate::symbol_db::SymbolId;
use crate::value_flags::ValueFlags;
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::num::NonZeroU64;

/// Trait that all format-specific layout types must implement.
pub(crate) trait LayoutTarget<'data> {
    type ArgsType: 'static;

    fn args(&self) -> &crate::args::Args<Self::ArgsType>;

    fn layout_data(&self) -> linker_layout::Layout;

    fn into_target_layout(self) -> TargetLayout<'data>;
}

/// Format-specific layout data, analogous to `TargetArgs`.
pub(crate) enum TargetLayout<'data> {
    Elf(ElfLayout<'data>),
    Pe(crate::pe_writer::PeLayout<'data>),
}

impl<'data> LayoutTarget<'data> for TargetLayout<'data> {
    type ArgsType = crate::args::TargetArgs;

    fn args(&self) -> &crate::args::Args<Self::ArgsType> {
        // TargetLayout is only used as the default type parameter for Layout.
        // In practice, file_writer::write is always called with a concrete layout type.
        unimplemented!("args() on TargetLayout enum is not supported; use a concrete layout type")
    }

    fn layout_data(&self) -> linker_layout::Layout {
        match self {
            Self::Elf(elf) => elf.layout_data(),
            Self::Pe(pe) => pe.layout_data(),
        }
    }

    fn into_target_layout(self) -> TargetLayout<'data> {
        self
    }
}

// TargetLayout can't impl Debug because ElfLayout contains non-Debug types
impl std::fmt::Debug for TargetLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf(_) => write!(f, "TargetLayout::Elf(..)"),
            Self::Pe(_) => write!(f, "TargetLayout::Pe(..)"),
        }
    }
}

/// Layout result — common fields shared across all output formats (ELF, PE),
/// generic over format-specific data `T` (analogous to `Args<T>`).
///
/// During layout computation, `T` is set to the concrete format type
/// (e.g. `ElfLayout` or `PeLayout`). Use `TargetLayout` for format-erased code.
///
/// Format-specific fields are accessible via `Deref`/`DerefMut` through `target`.
#[derive(Debug)]
pub(crate) struct Layout<'data, T: LayoutTarget<'data> = TargetLayout<'data>> {
    /// Total output file size in bytes.
    pub(crate) file_size: u64,
    /// Virtual address of the entry point (absolute).
    pub(crate) entry_address: u64,
    /// Resolved address for each symbol, indexed by global symbol ID.
    /// 0 means undefined / no address.
    pub(crate) symbol_addresses: Vec<u64>,
    /// Format-specific layout data.
    pub(crate) target: T,
    _phantom: PhantomData<&'data ()>,
}

impl<'data, T: LayoutTarget<'data>> std::ops::Deref for Layout<'data, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.target
    }
}

impl<'data, T: LayoutTarget<'data>> std::ops::DerefMut for Layout<'data, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.target
    }
}

impl<'data, T: LayoutTarget<'data>> Layout<'data, T> {
    pub(crate) fn new(file_size: u64, entry_address: u64, symbol_addresses: Vec<u64>, target: T) -> Self {
        Layout {
            file_size,
            entry_address,
            symbol_addresses,
            target,
            _phantom: PhantomData,
        }
    }

    /// Erase the concrete layout type into the format-agnostic `TargetLayout` enum.
    pub(crate) fn into_erased(self) -> Layout<'data> {
        Layout {
            file_size: self.file_size,
            entry_address: self.entry_address,
            symbol_addresses: self.symbol_addresses,
            target: self.target.into_target_layout(),
            _phantom: PhantomData,
        }
    }
}

/// Address information for a section.
#[derive(derive_more::Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SectionResolution {
    #[debug("0x{address:x}")]
    pub(crate) address: u64,
}

impl SectionResolution {
    /// Returns a resolution for a section that we didn't load, or for which we don't have an
    /// address (e.g. string-merge sections).
    pub(crate) fn none() -> SectionResolution {
        SectionResolution { address: u64::MAX }
    }

    pub(crate) fn address(self) -> Option<u64> {
        if self.address == u64::MAX {
            None
        } else {
            Some(self.address)
        }
    }

    /// Converts to a resolution compatible with what's used for symbols.
    pub(crate) fn full_resolution(self) -> Option<Resolution> {
        let address = self.address()?;
        Some(Resolution {
            raw_value: address,
            dynamic_symbol_index: None,
            got_address: None,
            plt_address: None,
            flags: ValueFlags::empty(),
        })
    }
}

/// Address information for a symbol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    /// The base GOT address for this resolution. For pointers to symbols the GOT entry will
    /// contain a single pointer. For TLS variables there can be up to 3 pointers. If
    /// ValueFlags::GOT_TLS_OFFSET is set, then that will be the first value. If
    /// ValueFlags::GOT_TLS_MODULE is set, then there will be a pair of values (module and
    /// offset within module).
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) flags: ValueFlags,
}

#[derive(Debug)]
pub(crate) struct InternalSymbols<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
    pub(crate) start_symbol_id: SymbolId,
}

#[derive(derive_more::Debug, Clone, Copy)]
pub(crate) struct DynamicSymbolDefinition<'data> {
    pub(crate) symbol_id: SymbolId,
    #[debug("{:?}", String::from_utf8_lossy(name))]
    pub(crate) name: &'data [u8],
    pub(crate) hash: u32,
    pub(crate) version: u16,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
    pub(crate) index: object::SectionIndex,
    pub(crate) part_id: PartId,
    /// Size in the output. This starts as the input section size, then may be reduced by
    /// relaxation-induced byte deletions during `scan_relaxations`.
    pub(crate) size: u64,
    pub(crate) flags: ValueFlags,
    pub(crate) is_writable: bool,
}

impl Section {
    // How much space we take up. This is our size rounded up to the next multiple of our
    // alignment, unless we're in a packed section, in which case it's just our size.
    pub(crate) fn capacity(&self) -> u64 {
        if self.part_id.should_pack() {
            self.size
        } else {
            self.alignment().align_up(self.size)
        }
    }

    pub(crate) fn output_section_id(&self) -> OutputSectionId {
        self.part_id.output_section_id()
    }

    pub(crate) fn output_part_id(&self) -> PartId {
        self.part_id
    }

    /// Returns the alignment for this section.
    pub(crate) fn alignment(&self) -> Alignment {
        self.part_id.alignment()
    }
}

/// The sizes and positions of either a segment or an output section. Note, we use usize for file
/// offsets and sizes, since we mmap our output file, so we're frequently working with in-memory
/// slices. This means that if we were linking on a 32 bit system that we'd be limited to file
/// offsets that were 32 bits. This isn't a loss though, since we couldn't mmap an output file where
/// that would be a problem on a 32 bit system.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputRecordLayout {
    pub(crate) file_size: usize,
    pub(crate) mem_size: u64,
    pub(crate) alignment: Alignment,
    pub(crate) file_offset: usize,
    pub(crate) mem_offset: u64,
}
