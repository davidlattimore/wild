// Return u32 from a byte slice
#[must_use]
pub fn u32_from_slice(data: &[u8]) -> u32 {
    u32::from_le_bytes(*data.first_chunk::<4>().unwrap())
}

// Copy `mask` slice into the `dest` slice using OR operation.
pub fn or_from_slice(dest: &mut [u8], mask_bytes: &[u8]) {
    for (i, v) in mask_bytes.iter().enumerate() {
        dest[i] |= *v;
    }
}
