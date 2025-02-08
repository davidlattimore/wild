// Return u32 from a byte slice
#[must_use]
pub fn u32_from_slice(data: &[u8]) -> u32 {
    u32::from_le_bytes(*data.first_chunk::<4>().unwrap())
}
