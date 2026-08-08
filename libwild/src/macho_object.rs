//! Data types used by the Mach-O object file.

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::U16;
use zerocopy::U32;
use zerocopy::U64;

pub(crate) const DYLD_CHAINED_IMPORT: u32 = 1;
pub(crate) const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;

// header of the LC_DYLD_CHAINED_FIXUPS payload
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct DyldChainedFixupsHeader {
    // 0
    pub(crate) fixups_version: U32<zerocopy::LittleEndian>,
    // offset of dyld_chained_starts_in_image in chain_data
    pub(crate) starts_offset: U32<zerocopy::LittleEndian>,
    // offset of imports table in chain_data
    pub(crate) imports_offset: U32<zerocopy::LittleEndian>,
    // offset of symbol strings in chain_data
    pub(crate) symbols_offset: U32<zerocopy::LittleEndian>,
    // number of imported symbol names
    pub(crate) imports_count: U32<zerocopy::LittleEndian>,
    // DYLD_CHAINED_IMPORT*
    pub(crate) imports_format: U32<zerocopy::LittleEndian>,
    // 0 => uncompressed, 1 => zlib compressed
    pub(crate) symbols_format: U32<zerocopy::LittleEndian>,
}

// This struct is embedded in LC_DYLD_CHAINED_FIXUPS payload
// struct dyld_chained_starts_in_image
// {
//     uint32_t    seg_count;
//     uint32_t    seg_info_offset[1];  // each entry is offset into this struct for that segment
//     // followed by pool of dyld_chain_starts_in_segment data
// };

// This struct is embedded in dyld_chain_starts_in_image
// and passed down to the kernel for page-in linking
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct DyldChainedStartsInSegment {
    // size of this (amount kernel needs to copy)
    pub(crate) size: U32<zerocopy::LittleEndian>,
    // 0x1000 or 0x4000
    pub(crate) page_size: U16<zerocopy::LittleEndian>,
    // DYLD_CHAINED_PTR_*
    pub(crate) pointer_format: U16<zerocopy::LittleEndian>,
    // offset in memory to start of segment
    pub(crate) segment_offset: U64<zerocopy::LittleEndian>,
    // for 32-bit OS, any value beyond this is not a pointer
    pub(crate) max_valid_pointer: U32<zerocopy::LittleEndian>,
    // how many pages are in array
    pub(crate) page_count: U16<zerocopy::LittleEndian>,
    // each entry is offset in each page of first element in chain
    // or DYLD_CHAINED_PTR_START_NONE if no fixups on paget
    // uint16_t page_start[1];
    //
    // some 32-bit formats may require multiple starts per page.
    // for those, if high bit is set in page_starts[], then it
    // is index into chain_starts[] which is a list of starts
    // the last of which has the high bit set
    // uint16_t chain_starts[1];
}
