//! Shared __eh_frame types and parsing logic.
//!
//! The CIE/FDE format is identical between ELF and Mach-O. This module provides
//! platform-generic types and a parsing function that both can reuse.

use crate::platform::FrameIndex;
use crate::platform::Relocation;
use crate::symbol_db::SymbolId;
use smallvec::SmallVec;
use zerocopy::FromBytes;

/// Prefix of every CIE or FDE entry in __eh_frame.
/// This format is identical between ELF and Mach-O.
#[derive(FromBytes, Clone, Copy)]
#[repr(C)]
pub(crate) struct EhFrameEntryPrefix {
    pub(crate) length: u32,
    pub(crate) cie_id: u32,
}

/// The offset of the pc_begin field in an FDE (after the length + cie_pointer).
pub(crate) const FDE_PC_BEGIN_OFFSET: usize = 8;

/// A stored exception frame (CIE or FDE) with its associated relocations.
///
/// `R` is the concrete relocation type. The relocations are stored as a
/// subsequence of the parent sequence, parameterized by `R::Sequence<'data>`.
#[derive(Default)]
pub(crate) struct ExceptionFrame<'data, R: Relocation> {
    /// The relocations that need to be processed if we load this frame.
    pub(crate) relocations: R::Sequence<'data>,

    /// Number of bytes required to store this frame.
    pub(crate) frame_size: u32,

    /// The index of the previous frame that is for the same section.
    pub(crate) previous_frame_for_section: Option<FrameIndex>,
}

/// Accumulated sizes for eh_frame output.
pub(crate) struct EhFrameSizes {
    pub(crate) num_frames: u64,
    pub(crate) eh_frame_size: u64,
}

/// A "common information entry". Part of __eh_frame data.
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct Cie<'data> {
    pub(crate) bytes: &'data [u8],
    pub(crate) eligible_for_deduplication: bool,
    pub(crate) referenced_symbols: SmallVec<[SymbolId; 1]>,
}

/// A CIE stored with its offset within __eh_frame.
pub(crate) struct CieAtOffset<'data> {
    /// Offset within __eh_frame.
    #[allow(dead_code)]
    pub(crate) offset: u32,
    pub(crate) cie: Cie<'data>,
}

