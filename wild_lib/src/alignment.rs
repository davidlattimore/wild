use crate::error::Result;
use anyhow::bail;
use std::fmt::Debug;
use std::fmt::Display;
use std::ops::AddAssign;
use std::ops::Index;
use std::ops::IndexMut;

/// An alignment. Always a power of two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub(crate) struct Alignment {
    pub(crate) exponent: u16,
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

pub(crate) const USIZE: Alignment = Alignment { exponent: 3 };

pub(crate) const EH_FRAME_HDR: Alignment = Alignment { exponent: 2 };

/// A map from alignments to some value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AlignmentMap<T> {
    // TODO: Consider only storing frequently used alignments in an array and storing less
    // frequently used alignments in an on-demand sorted Vec or smallvec.
    values: [T; NUM_ALIGNMENTS],
}

impl Alignment {
    pub(crate) fn new(raw: u64) -> Result<Self> {
        let exponent = raw.trailing_zeros();
        if 1 << exponent != raw {
            bail!("Invalid alignment 0x{raw:x}");
        }
        if exponent > MAX.exponent as u32 {
            bail!("Unsupported alignment 0x{raw:x}");
        }
        Ok(Alignment {
            exponent: exponent as u16,
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

impl<T> AlignmentMap<T> {
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (Alignment, &T)> {
        all_alignments().zip(self.values.iter())
    }

    /// Returns an iterator over keys, mutable values from `self` and immutable values from `other`.
    pub(crate) fn mut_zip<'t, 'u, U>(
        &'t mut self,
        other: &'u AlignmentMap<U>,
    ) -> impl ExactSizeIterator<Item = (Alignment, &'t mut T, &'u U)> {
        all_alignments()
            .zip(self.values.iter_mut())
            .zip(other.values.iter())
            .map(|((id, t), u)| (id, t, u))
    }

    pub(crate) fn raw_values(&self) -> &[T] {
        &self.values
    }
}

pub(crate) fn all_alignments(
) -> impl ExactSizeIterator<Item = Alignment> + DoubleEndedIterator<Item = Alignment> {
    (MIN.exponent..=MAX.exponent).map(|exponent| Alignment { exponent })
}

impl<T: Default> Default for AlignmentMap<T> {
    fn default() -> Self {
        Self {
            values: Default::default(),
        }
    }
}

impl<T> Index<Alignment> for AlignmentMap<T> {
    type Output = T;

    fn index(&self, index: Alignment) -> &Self::Output {
        &self.values[index.exponent as usize]
    }
}

impl<T> IndexMut<Alignment> for AlignmentMap<T> {
    fn index_mut(&mut self, index: Alignment) -> &mut Self::Output {
        &mut self.values[index.exponent as usize]
    }
}

impl<T: AddAssign + Copy> AlignmentMap<T> {
    pub(crate) fn merge(&mut self, other: &AlignmentMap<T>) {
        self.values
            .iter_mut()
            .zip(other.values.iter())
            .for_each(|(a, b)| *a += *b);
    }
}

impl<T: Default> FromIterator<(Alignment, T)> for AlignmentMap<T> {
    fn from_iter<I: IntoIterator<Item = (Alignment, T)>>(iter: I) -> Self {
        let mut out: AlignmentMap<T> = Default::default();
        for (id, v) in iter {
            out[id] = v;
        }
        out
    }
}

impl<T: Clone> Clone for AlignmentMap<T> {
    fn clone(&self) -> Self {
        Self {
            values: self.values.clone(),
        }
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
