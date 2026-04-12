/// LEB128 encoding/decoding utilities for WASM binary format.
///
/// All functions work directly on byte slices — no allocations.

/// Read an unsigned LEB128 value. Returns (value, bytes_consumed).
pub fn read_u32(data: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte < 0x80 {
            return Some((result, i + 1));
        }
        if shift >= 35 {
            return None;
        }
    }
    None
}

/// Write an unsigned LEB128 value to a Vec.
pub fn write_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Compute the byte length of an unsigned LEB128 encoding.
pub fn u32_size(mut value: u32) -> usize {
    let mut size = 1;
    while value >= 128 {
        value >>= 7;
        size += 1;
    }
    size
}

/// Read a 5-byte padded unsigned LEB128 at a specific offset.
pub fn read_padded_u32(data: &[u8], offset: usize) -> u32 {
    let mut result = 0u32;
    for i in 0..5 {
        if offset + i >= data.len() {
            break;
        }
        let byte = data[offset + i];
        result |= ((byte & 0x7F) as u32) << (i * 7);
        if byte < 0x80 {
            break;
        }
    }
    result
}

/// Write a 5-byte padded unsigned LEB128 at a specific offset.
pub fn write_padded_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = (value & 0x7F) as u8 | 0x80;
    buf[offset + 1] = ((value >> 7) & 0x7F) as u8 | 0x80;
    buf[offset + 2] = ((value >> 14) & 0x7F) as u8 | 0x80;
    buf[offset + 3] = ((value >> 21) & 0x7F) as u8 | 0x80;
    buf[offset + 4] = ((value >> 28) & 0x0F) as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u32() {
        for value in [0, 1, 127, 128, 16383, 16384, u32::MAX] {
            let mut buf = Vec::new();
            write_u32(&mut buf, value);
            let (decoded, len) = read_u32(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(len, buf.len());
            assert_eq!(len, u32_size(value));
        }
    }

    #[test]
    fn padded_roundtrip() {
        let mut buf = [0u8; 5];
        for value in [0, 1, 42, 128, 65536, u32::MAX >> 4] {
            write_padded_u32(&mut buf, 0, value);
            let decoded = read_padded_u32(&buf, 0);
            assert_eq!(decoded, value);
        }
    }
}
