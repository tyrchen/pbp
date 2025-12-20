// This module implements the ASCII armoring required by the OpenPGP
// specification, converting binary PGP datagrams into ASCII data.
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use byteorder::{BigEndian, ByteOrder};

use crate::PgpError;
use crate::PgpError::InvalidAsciiArmor;

impl From<base64::DecodeError> for PgpError {
    fn from(_: base64::DecodeError) -> PgpError {
        InvalidAsciiArmor
    }
}

impl From<base64::DecodeSliceError> for PgpError {
    fn from(_: base64::DecodeSliceError) -> PgpError {
        InvalidAsciiArmor
    }
}

// Convert from an ASCII armored string into binary data.
pub fn remove_ascii_armor(
    s: &str,
    expected_header: &str,
    expected_footer: &str,
) -> Result<Vec<u8>, PgpError> {
    let lines: Vec<&str> = s.lines().map(|s| s.trim()).collect();
    let header = lines.first().ok_or(InvalidAsciiArmor)?;
    let footer = lines.last().ok_or(InvalidAsciiArmor)?;

    // Check header and footer
    if !header.starts_with("-----")
        || !footer.starts_with("-----")
        || !header.ends_with("-----")
        || !footer.ends_with("-----")
        || header.trim_matches('-').trim() != expected_header
        || footer.trim_matches('-').trim() != expected_footer
    {
        return Err(InvalidAsciiArmor);
    }

    // Find the end of the header section
    let end_of_headers = 1 + lines.iter().take_while(|l| !l.is_empty()).count();
    if end_of_headers >= lines.len() - 2 {
        return Err(InvalidAsciiArmor);
    }

    // Decode the base64'd data
    let ascii_armored: String = lines[end_of_headers..lines.len() - 2].concat();
    let data = STANDARD.decode(&ascii_armored)?;

    // Confirm checksum
    let cksum_line = &lines[lines.len() - 2];

    if !cksum_line.starts_with("=") || cksum_line.len() <= 1 {
        return Err(InvalidAsciiArmor);
    }
    let mut cksum = [0; 4];
    // Use URL_SAFE_NO_PAD for checksum decoding (base64 alphabet compatible)
    STANDARD.decode_slice(&cksum_line[1..], &mut cksum[1..])?;

    if BigEndian::read_u32(&cksum[..]) != checksum_crc24(&data) {
        return Err(InvalidAsciiArmor);
    }

    Ok(data)
}

// Ascii armors data into the formatter
pub fn ascii_armor(
    header: &'static str,
    footer: &'static str,
    data: &[u8],
    f: &mut fmt::Formatter,
) -> fmt::Result {
    // Header Line
    f.write_str("-----")?;
    f.write_str(header)?;
    f.write_str("-----\n\n")?;

    // Base64'd data with line wrapping
    let encoded = STANDARD.encode(data);
    // Write in 76 character lines (PGP standard)
    for chunk in encoded.as_bytes().chunks(76) {
        f.write_str(std::str::from_utf8(chunk).unwrap())?;
        f.write_str("\n")?;
    }
    f.write_str("=")?;

    // Checksum
    let cksum = checksum_crc24(data);
    let mut cksum_buf = [0; 4];
    BigEndian::write_u32(&mut cksum_buf, cksum);
    f.write_str(&STANDARD.encode(&cksum_buf[1..4]))?;

    // Footer Line
    f.write_str("\n-----")?;
    f.write_str(footer)?;
    f.write_str("-----\n")?;

    Ok(())
}

// Translation of checksum function from RFC 4880, section 6.1.
fn checksum_crc24(data: &[u8]) -> u32 {
    const CRC24_INIT: u32 = 0x_00B7_04CE;
    const CRC24_POLY: u32 = 0x_0186_4CFB;

    let mut crc = CRC24_INIT;

    for &byte in data {
        crc ^= (byte as u32) << 16;

        for _ in 0..8 {
            crc <<= 1;

            if (crc & 0x_0100_0000) != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0x_00FF_FFFF
}
