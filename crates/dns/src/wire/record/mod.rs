use crate::ResourceRecord;
use crate::constants::MAX_TTL;
use crate::wire::{
    Decoder, Encoder, FromWire, IntoWire, Result, class, decode_complete, decode_name,
    decode_rdata, encode_rdata, record_type,
};

use super::rdata::validation_error_to_wire;

pub(crate) fn decode_record(decoder: &mut Decoder<'_>) -> Result<ResourceRecord> {
    let name = decode_name(decoder)?;
    let rtype = record_type(decoder.read_u16()?)?;
    let class_code = decoder.read_u16()?;
    // OPT overloads CLASS with an unsigned UDP payload size, including values
    // that are reserved or have named meanings in the ordinary CLASS space.
    let class = if matches!(rtype, crate::RecordType::OPT | crate::RecordType::TSIG)
        || (rtype == crate::RecordType::SIG && class_code == 255)
    {
        crate::ClassType::Unknown(class_code)
    } else {
        class(class_code)?
    };
    let received_ttl = decoder.read_u32()?;
    // OPT overloads TTL with extended RCODE, version, and flag bits.
    let ttl = if !matches!(rtype, crate::RecordType::OPT | crate::RecordType::TSIG)
        && received_ttl > MAX_TTL
    {
        0
    } else {
        received_ttl
    };
    let length = usize::from(decoder.read_u16()?);
    let rdata = decode_rdata(rtype, class, decoder, length)?;
    Ok(ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    })
}

/// Decodes an RFC 2136 prerequisite or update record. These sections overload
/// CLASS with ANY/NONE and TYPE with ANY, so they cannot use the ordinary RR
/// decoder without losing the operation's semantics.
pub(crate) fn decode_update_record(
    decoder: &mut Decoder<'_>,
    zone_class: Option<crate::ClassType>,
    prerequisite: bool,
) -> Result<ResourceRecord> {
    let name = decode_name(decoder)?;
    let type_code = decoder.read_u16()?;
    let rtype = if matches!(type_code, 251..=255) {
        crate::RecordType::Unknown(type_code)
    } else {
        record_type(type_code)?
    };
    let class_code = decoder.read_u16()?;
    let class = match class_code {
        254 | 255 => crate::ClassType::Unknown(class_code),
        _ => class(class_code)?,
    };
    let ttl = decoder.read_u32()?;
    let length = usize::from(decoder.read_u16()?);
    let rdata = if length == 0 && (class_code == 255 || (prerequisite && class_code == 254)) {
        crate::RData::Unknown(Vec::new())
    } else {
        let rdata_class = if class_code == 254 {
            zone_class.unwrap_or(class)
        } else {
            class
        };
        decode_rdata(rtype, rdata_class, decoder, length)?
    };
    Ok(ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    })
}

pub(crate) fn encode_record(record: &ResourceRecord, encoder: &mut Encoder) -> Result<()> {
    record
        .validate_for_forwarding()
        .map_err(validation_error_to_wire)?;
    encode_validated_record(record, encoder)
}

/// Used only after record validation, including the complete record walk in
/// normal message validation. No value can mutate through these shared borrows.
pub(crate) fn encode_validated_record(
    record: &ResourceRecord,
    encoder: &mut Encoder,
) -> Result<()> {
    encode_validated_record_with_ttl(record, record.ttl, encoder)
}

/// The caller has validated the immutable record and effective RRset TTL.
/// This stays private to checked message writers.
pub(crate) fn encode_validated_record_with_ttl(
    record: &ResourceRecord,
    ttl: u32,
    encoder: &mut Encoder,
) -> Result<()> {
    encoder.write_name(&record.name)?;
    encoder.write_u16(record.rtype.into());
    encoder.write_u16(record.class.value());
    encoder.write_u32(ttl);
    encoder.write_rdata(|encoder| super::rdata::encode_validated_rdata(&record.rdata, encoder))
}

pub(crate) fn encode_update_record(
    record: &ResourceRecord,
    _zone_class: Option<crate::ClassType>,
    encoder: &mut Encoder,
) -> Result<()> {
    encoder.write_name(&record.name)?;
    encoder.write_u16(record.rtype.into());
    encoder.write_u16(record.class.value());
    encoder.write_u32(record.ttl);
    encoder.write_rdata(|encoder| encode_rdata(&record.rdata, encoder))
}

impl IntoWire for ResourceRecord {
    fn into_wire(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        encode_record(self, &mut encoder)?;
        Ok(encoder.into_bytes())
    }
}

impl FromWire for ResourceRecord {
    fn from_wire(bytes: &[u8]) -> Result<Self> {
        decode_complete(bytes, decode_record)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::wire::WireError;
    use crate::{ClassType, DomainName, RData, RecordType};

    use super::*;

    fn a_record(ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    #[test]
    fn round_trips_the_rfc2181_maximum_ttl() {
        let record = a_record(MAX_TTL);
        assert_eq!(
            ResourceRecord::from_wire(&record.into_wire().unwrap())
                .unwrap()
                .ttl,
            MAX_TTL
        );
    }

    #[test]
    fn treats_received_ttls_with_the_high_bit_set_as_zero() {
        for ttl in [MAX_TTL + 1, u32::MAX] {
            let mut wire = vec![0, 0, 1, 0, 1]; // root owner, TYPE A, CLASS IN
            wire.extend_from_slice(&ttl.to_be_bytes());
            wire.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
            assert_eq!(ResourceRecord::from_wire(&wire).unwrap().ttl, 0);
        }
    }

    #[test]
    fn rejects_outbound_ttls_above_the_rfc2181_maximum() {
        assert!(matches!(
            a_record(MAX_TTL + 1).into_wire(),
            Err(WireError::InvalidValue {
                field: "TTL",
                value,
            }) if value == u64::from(MAX_TTL + 1)
        ));
    }

    #[test]
    fn rejects_reserved_and_query_only_type_codes_in_resource_records() {
        for rtype in [251_u16, 252, 253, 254, 255] {
            let mut wire = vec![0x00]; // root owner name
            wire.extend_from_slice(&rtype.to_be_bytes());
            wire.extend_from_slice(&1_u16.to_be_bytes()); // CLASS IN
            wire.extend_from_slice(&0_u32.to_be_bytes()); // TTL
            wire.extend_from_slice(&0_u16.to_be_bytes()); // RDLENGTH
            assert!(matches!(
                ResourceRecord::from_wire(&wire),
                Err(WireError::InvalidValue { field: "TYPE", .. })
            ));
        }

        for rtype in [
            0_u16,
            1,
            41,
            62,
            250,
            251,
            252,
            253,
            254,
            255,
            257,
            u16::MAX,
        ] {
            let record = ResourceRecord {
                name: DomainName::root(),
                rtype: RecordType::Unknown(rtype),
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::Unknown(Vec::new()),
            };
            assert!(matches!(
                record.into_wire(),
                Err(WireError::InvalidValue { field: "TYPE", .. })
            ));
        }
    }

    #[test]
    fn preserves_unassigned_rr_classes_as_opaque_data() {
        let bytes = [
            0, // root owner
            0, 1, // TYPE A
            0, 2, // RFC 6895 unassigned CLASS
            0, 0, 0, 1, // TTL
            0, 4, // RDLENGTH
            192, 0, 2, 1,
        ];
        let record = ResourceRecord::from_wire(&bytes).unwrap();
        assert_eq!(record.class, ClassType::Unknown(2));
        assert_eq!(record.rdata, RData::Unknown(vec![192, 0, 2, 1]));
        assert_eq!(record.into_wire().unwrap(), bytes);
    }

    #[test]
    fn rejects_noncanonical_or_query_only_classes_in_resource_records() {
        let bytes = [0, 0, 1, 0, 255, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1];
        assert!(matches!(
            ResourceRecord::from_wire(&bytes),
            Err(WireError::InvalidValue {
                field: "CLASS",
                value: 255
            })
        ));

        for class in [0, 1, 3, 4, 255, u16::MAX] {
            let record = ResourceRecord {
                class: ClassType::Unknown(class),
                ..a_record(0)
            };
            assert!(matches!(
                record.into_wire(),
                Err(WireError::InvalidValue {
                    field: "CLASS",
                    value
                }) if value == u64::from(class)
            ));
        }
    }

    #[test]
    fn invalid_record_is_rejected_before_writing() {
        let owner = DomainName::from_labels(vec![b"example".to_vec()]).unwrap();
        let invalid = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::HINFO,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::HINFO {
                cpu: vec![0; 256],
                os: Vec::new(),
            },
        };
        let mut encoder = Encoder::new();
        assert!(encode_record(&invalid, &mut encoder).is_err());
        assert_eq!(encoder.position(), 0);

        let valid = ResourceRecord {
            name: owner,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::A(Ipv4Addr::LOCALHOST),
        };
        encode_record(&valid, &mut encoder).unwrap();
        assert_eq!(encoder.into_bytes()[0], 7);
    }
}
