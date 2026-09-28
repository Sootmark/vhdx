//! CRC-32C (Castagnoli), the checksum VHDX uses for headers and regions.

const POLYNOMIAL: u32 = 0x82f6_3b78;

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC-32C of `data`, computed as if the 4 bytes at `zeroed` were zero (VHDX
/// structures embed their own checksum in the range they cover).
pub(crate) fn checksum_with_hole(data: &[u8], zeroed: usize) -> u32 {
    let hole = zeroed..zeroed + 4;
    let crc = data.iter().enumerate().fold(!0u32, |crc, (i, &byte)| {
        let byte = if hole.contains(&i) { 0 } else { byte };
        TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8)
    });
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_check_value() {
        // The CRC-32C check value for "123456789", with the hole past the end.
        assert_eq!(checksum_with_hole(b"123456789", 100), 0xe306_9283);
    }

    #[test]
    fn the_hole_reads_as_zeros() {
        let mut data = *b"1234\xff\xff\xff\xff9";
        let with_hole = checksum_with_hole(&data, 4);
        data[4..8].copy_from_slice(&[0; 4]);
        assert_eq!(with_hole, checksum_with_hole(&data, 100));
    }
}
