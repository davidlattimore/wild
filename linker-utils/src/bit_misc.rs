use std::ops::Range;

// Half-opened range bounded inclusively below and exclusively above: [`start`, `end`)
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct BitRange {
    pub start: u32,
    pub end: u32,
}

pub trait BitExtraction {
    /// Extract a single bit from the provided `value`.
    #[must_use]
    fn extract_bit(self, position: u32) -> u64;

    /// Extract range bits from the provided `value`.
    #[must_use]
    fn extract_bit_range(self, range: Range<u32>) -> u64;

    /// Extract the low `num_bits` bits from `self`.
    #[must_use]
    fn low_bits(self, num_bits: u32) -> u64;

    /// Extract the low `num_bits` bits from `self`, sign extending from the most significant bit.
    #[must_use]
    fn low_bits_signed(self, num_bits: u32) -> u64;

    /// Sign-extend `self` from the given sign bit.
    #[must_use]
    fn sign_extend(self, sign_bit: u32) -> u64;
}

impl BitExtraction for u64 {
    fn extract_bit(self, position: u32) -> u64 {
        self.extract_bit_range(position..position + 1)
    }

    fn extract_bit_range(self, range: Range<u32>) -> u64 {
        if range.start == 0 && range.end == u64::BITS {
            return self;
        }
        debug_assert!(range.start < range.end);
        (self >> range.start) & ((1 << range.len()) - 1)
    }

    fn low_bits(self, num_bits: u32) -> u64 {
        self & ((1 << num_bits) - 1)
    }

    fn low_bits_signed(self, num_bits: u32) -> u64 {
        self.low_bits(num_bits).sign_extend(num_bits - 1)
    }

    fn sign_extend(self, sign_bit: u32) -> u64 {
        if self & (1 << sign_bit) != 0 {
            self | !((2 << sign_bit) - 1)
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_operations() {
        assert_eq!(0b11000, 0b1100_0000u64.extract_bit_range(3..8));
        assert_eq!(
            0b1010_1010_0000,
            0b10101010_00001111u64.extract_bit_range(4..16)
        );
        assert_eq!(u32::MAX, u64::MAX.extract_bit_range(0..32) as u32);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_extract_bits_wrong_range() {
        let _ = 0u64.extract_bit_range(2..1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn test_extract_bits_too_large() {
        let _ = 0u64.extract_bit_range(0..100);
    }

    #[test]
    fn test_sign_extend() {
        assert_eq!(0u64.sign_extend(5), 0);
        assert_eq!(31u64.sign_extend(5), 31);
        assert_eq!(32u64.sign_extend(5) as i64, -32);
        assert_eq!(33u64.sign_extend(5) as i64, -31);
        assert_eq!(63u64.sign_extend(5) as i64, -1);
    }
}
