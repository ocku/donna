use std::net::{Ipv4Addr, Ipv6Addr};

use crate::constants::MAX_TTL;
use crate::protocol::is_valid_caa_property_tag;
use crate::{Caa, ClassType, Csync, DomainName, RData, RecordType, TypeBitmap};

use super::MasterError;
use super::presentation::{
    decode_character_string, name_from_presentation, validate_character_string,
};
use super::record::parse_type_value;
use super::wks::{wks_bitmap, wks_protocol, wks_service};

mod codecs;
mod generic;
mod legacy_security;

use codecs::*;
use generic::{decode_structured_generic, parse_generic_rdata};
use legacy_security::{parse_key, parse_sig};

pub(super) fn parse_rdata(
    rtype: RecordType,
    class: ClassType,
    fields: &[String],
    origin: Option<&DomainName>,
    record_ttl: Option<u32>,
) -> Result<RData, MasterError> {
    if !rtype.has_standard_rdata_format(class) {
        return parse_generic_rdata(fields);
    }

    if fields.first().is_some_and(|field| field == "\\#")
        && !matches!(rtype, RecordType::NULL | RecordType::OPT | RecordType::TSIG)
    {
        return decode_structured_generic(rtype, class, fields);
    }

    let name = |index| field_name(fields, index, origin);
    let u16_field = |index, label| {
        parse_bytes_number(&field_bytes(fields, index)?, label).and_then(|number| {
            u16::try_from(number).map_err(|_| MasterError::new(format!("{label} exceeds 65535")))
        })
    };

    match rtype {
        RecordType::A => {
            exactly(fields, 1, "A")?;
            Ok(RData::A(
                std::str::from_utf8(&field_bytes(fields, 0)?)
                    .map_err(|_| MasterError::new("A address is not text"))?
                    .parse::<Ipv4Addr>()
                    .map_err(|_| MasterError::new("invalid A address"))?,
            ))
        }
        RecordType::AAAA => {
            exactly(fields, 1, "AAAA")?;
            Ok(RData::AAAA(
                std::str::from_utf8(&field_bytes(fields, 0)?)
                    .map_err(|_| MasterError::new("AAAA address is not text"))?
                    .parse::<Ipv6Addr>()
                    .map_err(|_| MasterError::new("invalid AAAA address"))?,
            ))
        }
        RecordType::NS => {
            exactly(fields, 1, "NS")?;
            Ok(RData::NS(name(0)?))
        }
        RecordType::MD => {
            exactly(fields, 1, "MD")?;
            Ok(RData::MD(name(0)?))
        }
        RecordType::MF => {
            exactly(fields, 1, "MF")?;
            Ok(RData::MF(name(0)?))
        }
        RecordType::DNAME => {
            exactly(fields, 1, "DNAME")?;
            Ok(RData::DNAME(name(0)?))
        }
        RecordType::CNAME => {
            exactly(fields, 1, "CNAME")?;
            Ok(RData::CNAME(name(0)?))
        }
        RecordType::SOA => {
            exactly(fields, 7, "SOA")?;
            Ok(RData::SOA {
                mname: name(0)?,
                rname: name(1)?,
                serial: parse_bytes_number(&field_bytes(fields, 2)?, "SOA serial")?,
                refresh: parse_bytes_number(&field_bytes(fields, 3)?, "SOA refresh")?,
                retry: parse_bytes_number(&field_bytes(fields, 4)?, "SOA retry")?,
                expire: parse_bytes_number(&field_bytes(fields, 5)?, "SOA expire")?,
                minimum: parse_bytes_number(&field_bytes(fields, 6)?, "SOA minimum")?,
            })
        }
        RecordType::MB => {
            exactly(fields, 1, "MB")?;
            Ok(RData::MB(name(0)?))
        }
        RecordType::MG => {
            exactly(fields, 1, "MG")?;
            Ok(RData::MG(name(0)?))
        }
        RecordType::MR => {
            exactly(fields, 1, "MR")?;
            Ok(RData::MR(name(0)?))
        }
        RecordType::WKS => {
            if fields.len() < 2 {
                return Err(MasterError::new("WKS requires address and protocol"));
            }
            let address = std::str::from_utf8(&field_bytes(fields, 0)?)
                .map_err(|_| MasterError::new("WKS address is not text"))?
                .parse()
                .map_err(|_| MasterError::new("invalid WKS address"))?;
            let protocol = wks_protocol(&field_bytes(fields, 1)?)?;
            let ports = fields[2..]
                .iter()
                .map(|field| wks_service(&decode_character_string(field)?, protocol))
                .collect::<Result<Vec<_>, _>>()?;
            let bitmap = wks_bitmap(&ports);
            Ok(RData::WKS {
                address,
                protocol,
                bitmap,
            })
        }
        RecordType::PTR => {
            exactly(fields, 1, "PTR")?;
            Ok(RData::PTR(name(0)?))
        }
        RecordType::HINFO => {
            exactly(fields, 2, "HINFO")?;
            let cpu = field_bytes(fields, 0)?;
            let os = field_bytes(fields, 1)?;
            validate_character_string(&cpu, "HINFO CPU")?;
            validate_character_string(&os, "HINFO OS")?;
            Ok(RData::HINFO { cpu, os })
        }
        RecordType::MINFO => {
            exactly(fields, 2, "MINFO")?;
            Ok(RData::MINFO {
                rmailbx: name(0)?,
                emailbx: name(1)?,
            })
        }
        RecordType::MX => {
            exactly(fields, 2, "MX")?;
            Ok(RData::MX {
                preference: u16_field(0, "MX preference")?,
                exchange: name(1)?,
            })
        }
        RecordType::SRV => {
            exactly(fields, 4, "SRV")?;
            Ok(RData::SRV {
                priority: u16_field(0, "SRV priority")?,
                weight: u16_field(1, "SRV weight")?,
                port: u16_field(2, "SRV port")?,
                target: name(3)?,
            })
        }
        RecordType::TXT => {
            if fields.is_empty() {
                return Err(MasterError::new(
                    "TXT requires at least one character-string",
                ));
            }
            let strings = fields
                .iter()
                .map(|field| decode_character_string(field))
                .collect::<Result<Vec<_>, _>>()?;
            for string in &strings {
                validate_character_string(string, "TXT character-string")?;
            }
            let length = strings.iter().map(|string| string.len() + 1).sum::<usize>();
            if length > usize::from(u16::MAX) {
                return Err(MasterError::new("TXT RDATA exceeds 65535 octets"));
            }
            Ok(RData::TXT(strings))
        }
        RecordType::SIG => parse_sig(fields, origin, class, record_ttl),
        RecordType::KEY => parse_key(fields, class),
        RecordType::DS => parse_ds(fields, class),
        RecordType::RRSIG => parse_rrsig(fields, origin, class),
        RecordType::NSEC => parse_nsec(fields, origin, class),
        RecordType::DNSKEY => parse_dnskey(fields, class),
        RecordType::NSEC3 => parse_nsec3(fields, class),
        RecordType::NSEC3PARAM => parse_nsec3param(fields, class),
        RecordType::TLSA => parse_certificate_association(fields, class, RecordType::TLSA),
        RecordType::SMIMEA => parse_certificate_association(fields, class, RecordType::SMIMEA),
        RecordType::NULL => Err(MasterError::new(
            "NULL records are not allowed in master files",
        )),
        RecordType::OPT => Err(MasterError::new(
            "OPT pseudo-records are not allowed in master files",
        )),
        RecordType::CAA => {
            exactly(fields, 3, "CAA")?;
            let flags = u8::try_from(parse_bytes_number(&field_bytes(fields, 0)?, "CAA flags")?)
                .map_err(|_| MasterError::new("CAA flags exceed 255"))?;
            if flags & !Caa::ISSUER_CRITICAL_FLAG != 0 {
                return Err(MasterError::new(
                    "CAA records produced under RFC 6844 must clear reserved flags",
                ));
            }

            let mut tag = field_bytes(fields, 1)?;
            if tag.is_empty() {
                return Err(MasterError::new("CAA property tag must not be empty"));
            }
            if tag.len() > usize::from(u8::MAX) {
                return Err(MasterError::new("CAA property tag exceeds 255 octets"));
            }
            if !is_valid_caa_property_tag(&tag) {
                return Err(MasterError::new(
                    "CAA presentation property tag must contain only ASCII letters and digits",
                ));
            }
            tag.make_ascii_lowercase();

            let value = field_bytes(fields, 2)?;
            // RFC 6844 erratum 4062, incorporated by RFC 8659 section
            // 4.1.1, clarifies that CAA presentation borrows the quoting and
            // escaping rules of <character-string> but has no length octet
            // and therefore is not limited to 255 octets. The enclosing
            // RDATA limit is enforced by strict record validation.
            Ok(RData::CAA(Caa { flags, tag, value }))
        }
        RecordType::CSYNC => {
            if fields.len() < 3 {
                return Err(MasterError::new(
                    "CSYNC requires an SOA serial, flags, and at least one RR TYPE",
                ));
            }
            let soa_serial = parse_bytes_number(&field_bytes(fields, 0)?, "CSYNC SOA serial")?;
            let flags = u16_field(1, "CSYNC flags")?;
            let codes = fields[2..]
                .iter()
                .map(|field| {
                    let bytes = decode_character_string(field)?;
                    let value = std::str::from_utf8(&bytes)
                        .map_err(|_| MasterError::new("CSYNC RR TYPE is not text"))?;
                    Ok(u16::from(parse_type_value(value)?))
                })
                .collect::<Result<Vec<_>, MasterError>>()?;
            let type_bitmap = TypeBitmap::new(codes)
                .map_err(|error| MasterError::new(format!("invalid CSYNC type bitmap: {error}")))?;
            Ok(RData::CSYNC(Csync {
                soa_serial,
                flags,
                type_bitmap,
            }))
        }
        RecordType::TSIG => Err(MasterError::new(
            "TSIG transaction records are not allowed in master files",
        )),
        RecordType::Unknown(_) => parse_generic_rdata(fields),
    }
}

fn field(fields: &[String], index: usize) -> Result<&str, MasterError> {
    fields
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| MasterError::new("missing RDATA field"))
}
fn field_bytes(fields: &[String], index: usize) -> Result<Vec<u8>, MasterError> {
    decode_character_string(field(fields, index)?)
}
fn field_name(
    fields: &[String],
    index: usize,
    origin: Option<&DomainName>,
) -> Result<DomainName, MasterError> {
    name_from_presentation(field(fields, index)?, origin)
}
fn exactly(fields: &[String], expected: usize, kind: &str) -> Result<(), MasterError> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(MasterError::new(format!(
            "{kind} requires {expected} RDATA field(s), got {}",
            fields.len()
        )))
    }
}
pub(super) fn parse_number(value: &str, label: &str) -> Result<u32, MasterError> {
    let number = value
        .parse()
        .map_err(|_| MasterError::new(format!("invalid {label}: {value}")))?;
    if number > MAX_TTL {
        return Err(MasterError::new(format!(
            "{label} {number} exceeds the RFC 2181 maximum of {MAX_TTL}"
        )));
    }
    Ok(number)
}

pub(super) fn parse_bytes_number(value: &[u8], label: &str) -> Result<u32, MasterError> {
    std::str::from_utf8(value)
        .map_err(|_| MasterError::new(format!("{label} is not text")))?
        .parse()
        .map_err(|_| MasterError::new(format!("invalid {label}")))
}
