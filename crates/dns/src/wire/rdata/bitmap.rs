use std::collections::BTreeSet;

use crate::TypeBitmap;
use crate::wire::{Decoder, Encoder, Result, WireError};

pub(super) fn decode_type_bitmap(
    decoder: &mut Decoder<'_>,
    record_type: &'static str,
) -> Result<TypeBitmap> {
    if decoder.remaining() == 0 {
        return Err(WireError::InvalidRData {
            record_type,
            detail: "type bitmap must contain at least one window",
        });
    }

    let mut codes = BTreeSet::new();
    let mut previous_window = None;
    while decoder.remaining() != 0 {
        let window = decoder.read_u8()?;
        if previous_window.is_some_and(|previous| window <= previous) {
            return Err(WireError::InvalidRData {
                record_type,
                detail: "type bitmap windows are not strictly increasing",
            });
        }
        previous_window = Some(window);

        let length = usize::from(decoder.read_u8()?);
        if !(1..=32).contains(&length) {
            return Err(WireError::InvalidRData {
                record_type,
                detail: "type bitmap window length must be between 1 and 32",
            });
        }
        let bitmap = decoder.read_exact(length)?;
        if bitmap.last() == Some(&0) {
            return Err(WireError::InvalidRData {
                record_type,
                detail: "type bitmap contains a trailing zero octet",
            });
        }

        for (octet_index, octet) in bitmap.iter().copied().enumerate() {
            for bit in 0..8_u8 {
                if octet & (0x80 >> bit) != 0 {
                    let low =
                        u16::try_from(octet_index * 8).expect("bitmap index fits") + u16::from(bit);
                    let code = (u16::from(window) << 8) | low;
                    codes.insert(code);
                }
            }
        }
    }

    TypeBitmap::from_received_codes(codes).map_err(|_| WireError::InvalidRData {
        record_type,
        detail: "type bitmap contains no ordinary RR TYPEs",
    })
}

pub(super) fn encode_type_bitmap(bitmap: &TypeBitmap, encoder: &mut Encoder) {
    let mut codes = bitmap.wire_codes().iter().copied().peekable();
    while let Some(first) = codes.next() {
        let window = (first >> 8) as u8;
        // Each RFC 4034 window contains at most 256 bits. Write its bits
        // directly into bounded storage, retaining ignored received TYPE bits
        // from wire_codes because they remain part of authenticated RDATA.
        let mut octets = [0_u8; 32];
        let mut largest = first as u8;
        octets[usize::from(largest / 8)] |= 0x80 >> (largest % 8);
        while let Some(&next) = codes.peek() {
            if (next >> 8) as u8 != window {
                break;
            }
            largest = next as u8;
            octets[usize::from(largest / 8)] |= 0x80 >> (largest % 8);
            codes.next();
        }
        let length = usize::from(largest / 8) + 1;
        encoder.write_u8(window);
        encoder.write_u8(length as u8);
        encoder.write_exact(&octets[..length]);
    }
}

pub(super) fn validate_wks_bitmap(bitmap: &[u8]) -> Result<()> {
    if bitmap.len() > 8192 {
        return Err(crate::wire::WireError::InvalidRData {
            record_type: "WKS",
            detail: "service bitmap exceeds the 16-bit port-number space",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_encoding_preserves_every_received_bit_across_all_windows() {
        for codes in [
            vec![
                1, 7, 8, 41, 46, 47, 128, 249, 255, 256, 511, 512, 32768, 65535,
            ],
            vec![128],
            (1..=u16::MAX).collect(),
        ] {
            let mut flat = [0_u8; 8192];
            for &code in &codes {
                flat[usize::from(code / 8)] |= 0x80 >> (code % 8);
            }
            let mut expected = Vec::new();
            for (window, bits) in flat.as_chunks::<32>().0.iter().enumerate() {
                if let Some(last) = bits.iter().rposition(|&octet| octet != 0) {
                    expected.extend_from_slice(&[window as u8, (last + 1) as u8]);
                    expected.extend_from_slice(&bits[..=last]);
                }
            }
            let bitmap = TypeBitmap::from_received_codes(codes.into_iter().collect()).unwrap();
            let mut encoder = Encoder::new();
            encode_type_bitmap(&bitmap, &mut encoder);
            let wire = encoder.into_bytes();
            assert_eq!(wire, expected);
            let decoded = decode_type_bitmap(&mut Decoder::new(&wire), "NSEC").unwrap();
            assert_eq!(decoded, bitmap);
        }
    }
}
