use anyhow::Result;
use anyhow::ensure;
use std::ffi::CStr;

// Return u32 from a byte slice
#[must_use]
pub fn u32_from_slice(data: &[u8]) -> u32 {
    u32::from_le_bytes(*data.first_chunk::<4>().unwrap())
}

// Return u64 from a byte slice
#[must_use]
pub fn u64_from_slice(data: &[u8]) -> u64 {
    u64::from_le_bytes(*data.first_chunk::<8>().unwrap())
}

// Copy `mask` slice into the `dest` slice using OR operation.
pub fn or_from_slice(dest: &mut [u8], mask_bytes: &[u8]) {
    for (i, v) in mask_bytes.iter().enumerate() {
        dest[i] |= *v;
    }
}

// And `mask` slice with the `dest` slice using AND operation.
pub fn and_from_slice(dest: &mut [u8], mask_bytes: &[u8]) {
    for (i, v) in mask_bytes.iter().enumerate() {
        dest[i] &= *v;
    }
}

// Interpret all bytes in `data` as a slice of `T`.
#[must_use]
pub fn slice_from_all_bytes<T: object::Pod>(data: &[u8]) -> &[T] {
    object::slice_from_bytes(data, data.len() / size_of::<T>())
        .unwrap()
        .0
}

#[must_use]
pub fn slice_from_all_bytes_mut<T: object::Pod>(data: &mut [u8]) -> &mut [T] {
    object::slice_from_bytes_mut(data, data.len() / size_of::<T>())
        .unwrap()
        .0
}

pub fn read_u32(content: &mut &[u8]) -> Result<u32> {
    ensure!(content.len() >= 4, "Not enough bytes to read u32");
    let value = u32::from_le_bytes(content[..4].try_into()?);
    *content = &content[4..];
    Ok(value)
}

pub fn read_string(content: &mut &[u8]) -> Result<String> {
    let cstr = CStr::from_bytes_until_nul(content)
        .map_err(|_| anyhow::anyhow!("No null terminator found in string"))?;
    let len = cstr.count_bytes() + 1; // include the null terminator
    let s = cstr.to_string_lossy().to_string();
    *content = &content[len..];
    Ok(s)
}

pub fn read_uleb128(content: &mut &[u8]) -> Result<u64> {
    leb128::read::unsigned(content)
        .map_err(|e| anyhow::anyhow!("Failed to read ULEB128 value: {e}"))
}
