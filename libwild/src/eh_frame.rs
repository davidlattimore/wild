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

/// A lightweight exception frame descriptor returned by the generic parser.
/// Uses index ranges rather than subsequences to avoid type-system issues.
pub(crate) struct RawExceptionFrame {
    /// Range of relocation indices in the parent sequence.
    pub(crate) rel_range: std::ops::Range<usize>,
    /// Number of bytes for this frame.
    pub(crate) frame_size: u32,
    /// Previous frame for the same section.
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

/// Platform-specific callbacks for __eh_frame parsing.
///
/// `R` is the relocation type yielded by the sequence iterator.
pub(crate) trait EhFrameHandler<'data, R: Relocation> {
    /// Process a relocation found inside a CIE entry.
    /// Returns the resolved symbol ID for dedup tracking, or None if the reloc
    /// has no symbol (which makes the CIE ineligible for deduplication).
    fn process_cie_relocation(&mut self, rel: &R) -> crate::error::Result<Option<SymbolId>>;

    /// Given the pc_begin relocation of an FDE, return the section index of the
    /// target function. Returns None if the FDE should be discarded.
    fn fde_target_section(&self, rel: &R) -> crate::error::Result<Option<object::SectionIndex>>;

    /// Store a parsed CIE.
    fn store_cie(&mut self, offset: u32, cie: Cie<'data>);

    /// Link an FDE to the section it covers. Returns `Some(previous_frame)` if
    /// the section is eligible (building the linked list), or None to skip.
    fn link_fde_to_section(
        &mut self,
        section_index: object::SectionIndex,
    ) -> Option<Option<FrameIndex>>;
}

/// Parse __eh_frame data into CIEs and FDEs using a platform-specific handler.
///
/// Returns raw exception frame descriptors (with relocation index ranges) and
/// the count of trailing bytes. The caller converts `RawExceptionFrame` into
/// platform-specific `ExceptionFrame` by extracting relocation subsequences.
pub(crate) fn parse_eh_frame_entries<'data, R, H>(
    handler: &mut H,
    data: &'data [u8],
    rel_iter: &mut std::iter::Peekable<impl Iterator<Item = (usize, R)>>,
) -> crate::error::Result<(Vec<RawExceptionFrame>, usize)>
where
    R: Relocation,
    H: EhFrameHandler<'data, R>,
{
    use std::mem::size_of;
    use std::mem::size_of_val;

    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();

    let mut offset = 0;
    let mut exception_frames = Vec::new();

    while offset + PREFIX_LEN <= data.len() {
        let prefix =
            EhFrameEntryPrefix::read_from_bytes(&data[offset..offset + PREFIX_LEN]).unwrap();
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_offset = offset + size;

        if next_offset > data.len() {
            crate::bail!("Invalid .eh_frame data");
        }

        if prefix.cie_id == 0 {
            // CIE
            let mut referenced_symbols: SmallVec<[SymbolId; 1]> = Default::default();
            let mut eligible_for_deduplication = true;

            while let Some((_, rel)) = rel_iter.peek() {
                if rel.offset() >= next_offset as u64 {
                    break;
                }

                match handler.process_cie_relocation(rel)? {
                    Some(sym_id) => referenced_symbols.push(sym_id),
                    None => eligible_for_deduplication = false,
                }
                rel_iter.next();
            }

            handler.store_cie(
                offset as u32,
                Cie {
                    bytes: &data[offset..next_offset],
                    eligible_for_deduplication,
                    referenced_symbols,
                },
            );
        } else {
            // FDE
            let mut section_index = None;
            let rel_start_index = rel_iter.peek().map_or(0, |(i, _)| *i);
            let mut rel_end_index = 0;

            while let Some((rel_index, rel)) = rel_iter.peek() {
                if rel.offset() < next_offset as u64 {
                    let is_pc_begin = (rel.offset() as usize - offset) == FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin {
                        section_index = handler.fde_target_section(rel)?;
                    }
                    rel_end_index = rel_index + 1;
                    rel_iter.next();
                } else {
                    break;
                }
            }

            if let Some(section_index) = section_index
                && let Some(previous_frame) = handler.link_fde_to_section(section_index)
            {
                exception_frames.push(RawExceptionFrame {
                    rel_range: rel_start_index..rel_end_index,
                    frame_size: size as u32,
                    previous_frame_for_section: previous_frame,
                });
            }
        }
        offset = next_offset;
    }

    let trailing_bytes = data.len() - offset;
    Ok((exception_frames, trailing_bytes))
}
