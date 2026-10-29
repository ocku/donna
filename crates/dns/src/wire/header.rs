use crate::constants::header::{
    AA_FLAG, AD_FLAG, CD_FLAG, OPCODE_MASK, OPCODE_SHIFT, QR_FLAG, RA_FLAG, RCODE_MASK, RD_FLAG,
    TC_FLAG, Z_MASK, Z_SHIFT,
};
use crate::protocol::{HeaderFieldValueError, Headers, OpCode, RCode, SectionCounts};
use crate::wire::{Decoder, Encoder, Result, WireError};

pub(crate) fn decode_header(decoder: &mut Decoder<'_>) -> Result<(Headers, SectionCounts)> {
    decode_header_with_policy(decoder, false)
}

/// mDNS receivers ignore the legacy Z bit (RFC 6762 section 18.8).
pub(crate) fn decode_mdns_header(decoder: &mut Decoder<'_>) -> Result<(Headers, SectionCounts)> {
    decode_header_with_policy(decoder, true)
}

fn decode_header_with_policy(
    decoder: &mut Decoder<'_>,
    ignore_z: bool,
) -> Result<(Headers, SectionCounts)> {
    let id = decoder.read_u16()?;
    let flags = decoder.read_u16()?;
    let flags = if ignore_z { flags & !Z_MASK } else { flags };
    let headers = decode_flags(id, flags)?;
    let counts = SectionCounts {
        questions: decoder.read_u16()?,
        answers: decoder.read_u16()?,
        authorities: decoder.read_u16()?,
        additionals: decoder.read_u16()?,
    };
    Ok((headers, counts))
}

pub(crate) fn encode_header(
    headers: &Headers,
    counts: SectionCounts,
    encoder: &mut Encoder,
) -> Result<()> {
    let flags = encode_flags(headers)?;
    encoder.write_u16(headers.id);
    encoder.write_u16(flags);
    encoder.write_u16(counts.questions);
    encoder.write_u16(counts.answers);
    encoder.write_u16(counts.authorities);
    encoder.write_u16(counts.additionals);
    Ok(())
}

fn decode_flags(id: u16, flags: u16) -> Result<Headers> {
    let opcode = decode_opcode(flags)?;
    let z = (flags & Z_MASK) >> Z_SHIFT;
    if z != 0 && opcode != OpCode::Update {
        return Err(WireError::InvalidValue {
            field: "Z",
            value: u64::from(z),
        });
    }

    Ok(Headers {
        id,
        qr: flags & QR_FLAG != 0,
        opcode,
        aa: flags & AA_FLAG != 0,
        tc: flags & TC_FLAG != 0,
        rd: flags & RD_FLAG != 0,
        ra: flags & RA_FLAG != 0,
        ad: flags & AD_FLAG != 0,
        cd: flags & CD_FLAG != 0,
        rcode: decode_rcode(flags)?,
    })
}

fn decode_opcode(flags: u16) -> Result<OpCode> {
    let value = (flags >> OPCODE_SHIFT) & OPCODE_MASK;
    OpCode::try_from(value as u8).map_err(|_| WireError::InvalidValue {
        field: "OPCODE",
        value: u64::from(value),
    })
}

fn decode_rcode(flags: u16) -> Result<RCode> {
    let value = flags & RCODE_MASK;
    RCode::try_from(value as u8).map_err(|_| WireError::InvalidValue {
        field: "RCODE",
        value: u64::from(value),
    })
}

fn encode_flags(headers: &Headers) -> Result<u16> {
    headers.validate_wire().map_err(|error| match error {
        HeaderFieldValueError::TooWide { field, value, .. }
        | HeaderFieldValueError::Reserved { field, value } => WireError::InvalidValue {
            field,
            value: u64::from(value),
        },
    })?;
    let opcode = headers.opcode.value();
    let rcode = headers.rcode.value();

    Ok((u16::from(headers.qr) * QR_FLAG)
        | (u16::from(opcode) << OPCODE_SHIFT)
        | (u16::from(headers.aa) * AA_FLAG)
        | (u16::from(headers.tc) * TC_FLAG)
        | (u16::from(headers.rd) * RD_FLAG)
        | (u16::from(headers.ra) * RA_FLAG)
        | (u16::from(headers.ad) * AD_FLAG)
        | (u16::from(headers.cd) * CD_FLAG)
        | u16::from(rcode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_counts() -> SectionCounts {
        SectionCounts {
            questions: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
        }
    }

    #[test]
    fn encodes_and_decodes_fixed_header_fields() {
        let headers = Headers {
            id: 0x1234,
            qr: true,
            opcode: OpCode::Status,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
            rcode: RCode::Refused,
        };
        let counts = SectionCounts {
            questions: 1,
            answers: 2,
            authorities: 3,
            additionals: 4,
        };
        let expected = [
            0x12, 0x34, 0x97, 0xb5, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        ];

        let mut encoder = Encoder::new();
        encode_header(&headers, counts, &mut encoder).unwrap();
        assert_eq!(encoder.into_bytes(), expected);

        let mut decoder = Decoder::new(&expected);
        let (decoded, decoded_counts) = decode_header(&mut decoder).unwrap();
        assert_eq!(decoded.id, headers.id);
        assert_eq!(decoded.qr, headers.qr);
        assert_eq!(decoded.opcode, headers.opcode);
        assert_eq!(decoded.aa, headers.aa);
        assert_eq!(decoded.tc, headers.tc);
        assert_eq!(decoded.rd, headers.rd);
        assert_eq!(decoded.ra, headers.ra);
        assert_eq!(decoded.ad, headers.ad);
        assert_eq!(decoded.cd, headers.cd);
        assert_eq!(decoded.rcode, headers.rcode);
        assert_eq!(decoded_counts, counts);
        assert_eq!(decoder.remaining(), 0);
    }

    #[test]
    fn assigned_rfc6895_codes_round_trip() {
        for opcode in [OpCode::Notify, OpCode::Update] {
            let headers = Headers {
                qr: true,
                opcode,
                ..Headers::default()
            };
            let mut encoder = Encoder::new();
            encode_header(&headers, zero_counts(), &mut encoder).unwrap();
            let bytes = encoder.into_bytes();
            let (decoded, _) = decode_header(&mut Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded.opcode, opcode);
        }

        for rcode in [
            RCode::YXDomain,
            RCode::YXRRSet,
            RCode::NXRRSet,
            RCode::NotAuthoritative,
            RCode::NotZone,
        ] {
            let headers = Headers {
                qr: true,
                rcode,
                ..Headers::default()
            };
            let mut encoder = Encoder::new();
            encode_header(&headers, zero_counts(), &mut encoder).unwrap();
            let bytes = encoder.into_bytes();
            let (decoded, _) = decode_header(&mut Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded.rcode, rcode);
        }
    }

    #[test]
    fn update_ignores_the_legacy_reserved_z_bit_on_receive() {
        let bytes = [
            0x12, 0x34, 0x28, 0x40, // ID, UPDATE opcode, and reserved Z bit
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (headers, counts) = decode_header(&mut Decoder::new(&bytes)).unwrap();
        assert_eq!(headers.opcode, OpCode::Update);
        assert_eq!(counts, zero_counts());
    }

    #[test]
    fn rejects_the_remaining_nonzero_z_bit() {
        let bytes = [0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut decoder = Decoder::new(&bytes);
        assert!(matches!(
            decode_header(&mut decoder),
            Err(WireError::InvalidValue {
                field: "Z",
                value: 1
            })
        ));
    }

    #[test]
    fn rejects_every_truncated_header_length() {
        for length in 0..12 {
            let bytes = vec![0; length];
            let mut decoder = Decoder::new(&bytes);
            assert!(matches!(
                decode_header(&mut decoder),
                Err(WireError::Truncated { .. })
            ));
        }
    }

    #[test]
    fn public_encoder_rejects_unassigned_and_too_wide_codes_before_writing() {
        for (headers, field, value) in [
            (
                Headers {
                    opcode: OpCode::Unknown(3),
                    ..Headers::default()
                },
                "OPCODE",
                3,
            ),
            (
                Headers {
                    rcode: RCode::Unknown(11),
                    ..Headers::default()
                },
                "RCODE",
                11,
            ),
            (
                Headers {
                    opcode: OpCode::Unknown(16),
                    ..Headers::default()
                },
                "OPCODE",
                16,
            ),
            (
                Headers {
                    rcode: RCode::Unknown(16),
                    ..Headers::default()
                },
                "RCODE",
                16,
            ),
        ] {
            let mut encoder = Encoder::new();
            assert!(matches!(
                encode_header(&headers, zero_counts(), &mut encoder),
                Err(WireError::InvalidValue {
                    field: actual,
                    value: actual_value
                }) if actual == field && actual_value == value
            ));
            assert_eq!(encoder.position(), 0);
        }
    }
}
