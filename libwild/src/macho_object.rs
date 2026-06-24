//! Data types used by the Mach-O object file.

use zerocopy::BigEndian;
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

// Code signature data structures are always stored big-endian, regardless of
// the target architecture's byte order.
//
// Data structures mirroring the following URL:
// https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h.

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureSuperBlob {
    // magic number
    pub(crate) magic: U32<BigEndian>,
    // total length of SuperBlob
    pub(crate) length: U32<BigEndian>,
    // number of index entries following
    pub(crate) count: U32<BigEndian>,
    // (count) entries
    // CodeSignatureBlobIndex index[];
    // followed by Blobs in no particular order as indicated by offsets in index
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureBlobIndex {
    // type of entry
    pub(crate) type_: U32<BigEndian>,
    // offset of entry
    pub(crate) offset: U32<BigEndian>,
    // an extra padding so that we have CodeSignatureSuperBlob + CodeSignatureBlobIndex aligned to
    // 8 bytes!
    pub(crate) padding: U32<BigEndian>,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Clone, Copy)]
#[repr(C)]
pub(crate) struct CodeSignatureCodeDirectory {
    // magic number (CSMAGIC_CODEDIRECTORY)
    pub(crate) magic: U32<BigEndian>,
    // total length of CodeDirectory blob
    pub(crate) length: U32<BigEndian>,
    // compatibility version
    pub(crate) version: U32<BigEndian>,
    // setup and mode flags
    pub(crate) flags: U32<BigEndian>,
    // offset of hash slot element at index zero
    pub(crate) hash_offset: U32<BigEndian>,
    // offset of identifier string
    pub(crate) ident_offset: U32<BigEndian>,
    // number of special hash slots
    pub(crate) n_special_slots: U32<BigEndian>,
    // number of ordinary (code) hash slots
    pub(crate) n_code_slots: U32<BigEndian>,
    // limit to main image signature range
    pub(crate) code_limit: U32<BigEndian>,
    // size of each hash in bytes
    pub(crate) hash_size: u8,
    // type of hash (cdHashType* constants)
    pub(crate) hash_type: u8,
    // platform identifier; zero if not platform binary
    pub(crate) platform: u8,
    // log2(page size in bytes); 0 => infinite
    pub(crate) page_size: u8,
    // unused (must be zero)
    pub(crate) spare2: U32<BigEndian>,

    // Version 0x20100
    //
    // offset of optional scatter vector
    pub(crate) scatter_offset: U32<BigEndian>,

    // Version 0x20200
    //
    // offset of optional team identifier
    pub(crate) team_offset: U32<BigEndian>,

    // Version 0x20300
    //
    // unused (must be zero)
    pub(crate) spare3: U32<BigEndian>,
    // limit to main image signature range, 64 bits
    pub(crate) code_limit64: U64<BigEndian>,

    // Version 0x20400
    //
    // offset of executable segment
    pub(crate) exec_seg_base: U64<BigEndian>,
    // limit of executable segment
    pub(crate) exec_seg_limit: U64<BigEndian>,
    // executable segment flags
    pub(crate) exec_seg_flags: U64<BigEndian>,
    // Version 0x20500 and 0x20600 are unused!
    // followed by dynamic content as located by offset fields above
}

pub(crate) const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub(crate) const CSSLOT_CODEDIRECTORY: u32 = 0;
pub(crate) const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub(crate) const CS_SUPPORTSEXECSEG: u32 = 0x20400;
// Ad hoc signed
pub(crate) const CS_ADHOC: u32 = 0x00000002;
// Automatically signed by the linker
pub(crate) const CS_LINKER_SIGNED: u32 = 0x00020000;
pub(crate) const CS_HASHTYPE_SHA256: u8 = 2;
pub(crate) const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
