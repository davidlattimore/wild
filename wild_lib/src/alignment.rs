use crate::error::Result;
use anyhow::bail;
use std::fmt::Debug;
use std::fmt::Display;

/// An alignment. Always a power of two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub(crate) struct Alignment {
    pub(crate) exponent: u8,
}

pub(crate) const NUM_ALIGNMENTS: usize = 16;

/// The minimum alignment that we support.
pub(crate) const MIN: Alignment = Alignment { exponent: 0 };

/// The maximum alignment that we support.
pub(crate) const MAX: Alignment = Alignment { exponent: 15 };

/// Alignment for entries in the symbol table.
pub(crate) const SYMTAB_ENTRY: Alignment = Alignment { exponent: 3 };

/// Alignment for entries in the global offset table.
pub(crate) const GOT_ENTRY: Alignment = Alignment { exponent: 3 };

/// The minimum alignment of a rela entry.
pub(crate) const RELA_ENTRY: Alignment = Alignment { exponent: 3 };

/// Alignment of the .gnu.hash section.
pub(crate) const GNU_HASH: Alignment = Alignment { exponent: 3 };

/// The minimum alignment of a phdr entry.
pub(crate) const PROGRAM_HEADER_ENTRY: Alignment = Alignment { exponent: 3 };

/// The minimum alignment of loadable program segments.
pub(crate) const PAGE: Alignment = Alignment { exponent: 12 };

/// The minimum alignment of a PLT entry.
pub(crate) const PLT: Alignment = Alignment { exponent: 4 };

pub(crate) const VERSION_R: Alignment = Alignment { exponent: 3 };
pub(crate) const VERSYM: Alignment = Alignment { exponent: 1 };

pub(crate) const USIZE: Alignment = Alignment { exponent: 3 };

pub(crate) const EH_FRAME_HDR: Alignment = Alignment { exponent: 2 };

impl Alignment {
    pub(crate) fn new(raw: u64) -> Result<Self> {
        let exponent = raw.trailing_zeros();
        if 1_u64.checked_shl(exponent) != Some(raw) {
            bail!("Invalid alignment 0x{raw:x}");
        }
        if exponent > MAX.exponent as u32 {
            bail!("Unsupported alignment 0x{raw:x}");
        }
        Ok(Alignment {
            exponent: exponent as u8,
        })
    }

    pub(crate) fn value(self) -> u64 {
        1 << self.exponent
    }

    pub(crate) fn align_up(&self, value: u64) -> u64 {
        let base = value & (u64::MAX << self.exponent);
        if value == base {
            // Already aligned
            value
        } else {
            base + (1 << self.exponent)
        }
    }

    pub(crate) fn align_up_usize(&self, value: usize) -> usize {
        let base = value & (usize::MAX << self.exponent);
        if value == base {
            // Already aligned
            value
        } else {
            base + (1 << self.exponent)
        }
    }

    /// Returns `mem_offset`, possibly adjusted up so that it is >= `align_up(mem_offset)` and has
    /// the same modulo as `file_offset`
    pub(crate) fn align_modulo(&self, file_offset: u64, mut mem_offset: u64) -> u64 {
        let mask = self.value() - 1;
        mem_offset = self.align_up(mem_offset);
        if mem_offset & mask == file_offset & mask {
            return mem_offset;
        }
        let mut adjustment = (file_offset & mask) + self.value() - (mem_offset & mask);
        if adjustment > self.value() {
            adjustment -= self.value();
        }
        mem_offset + adjustment
    }
}

impl Display for Alignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value(), f)
    }
}

#[test]
fn test_align_up() {
    assert_eq!(Alignment::new(16).unwrap().align_up(16), 16);
    assert_eq!(Alignment::new(16).unwrap().align_up(15), 16);
    assert_eq!(Alignment::new(16).unwrap().align_up(1), 16);
    assert_eq!(Alignment::new(16).unwrap().align_up(0), 0);
    assert_eq!(Alignment::new(16).unwrap().align_up(31), 32);
}

#[test]
fn test_align_modulo() {
    assert_eq!(PAGE.align_modulo(0x123456, 0x987456), 0x988456);
    assert_eq!(PAGE.align_modulo(0x123456, 0x987555), 0x988456);
    assert_eq!(PAGE.align_modulo(0x123456, 0x987222), 0x988456);
    assert_eq!(PAGE.align_modulo(0x123456, 0x987001), 0x988456);
    assert_eq!(PAGE.align_modulo(0x123456, 0x987000), 0x987456);
    assert_eq!(PAGE.align_modulo(0x2afce, 0x42af7e), 0x42bfce);
}
