//! RFC 2535 presentation formats for the original SIG and KEY record types.

use crate::{ClassType, DomainName, Key, RData, RecordType, Sig};

use super::codecs::{
    decode_base64_fields, field_text, parse_algorithm_field, parse_signature_time, parse_u8_field,
    parse_u16_field,
};
use super::generic::decode_structured_generic;
use super::{MasterError, field_bytes, field_name, parse_bytes_number, parse_type_value};

pub(super) fn parse_sig(
    fields: &[String],
    origin: Option<&DomainName>,
    class: ClassType,
    record_ttl: Option<u32>,
) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::SIG, class, fields);
    }
    if fields.len() < 8 {
        return Err(MasterError::new("SIG requires at least eight RDATA fields"));
    }
    // RFC 2535 §7.2 distinguishes an omitted TTL by the following calendar
    // date, which exceeds every possible TTL. Numeric times remain supported
    // with an explicit original TTL; field count alone cannot disambiguate
    // them because the base64 signature can span multiple tokens.
    let ttl_or_date = field_text(fields, 3, "SIG original TTL or expiration")?;
    let omitted_ttl =
        ttl_or_date.len() == 14 && ttl_or_date.as_bytes().iter().all(u8::is_ascii_digit);
    let (original_ttl, expiration_index) = if omitted_ttl {
        (
            record_ttl.ok_or_else(|| {
                MasterError::new("SIG omits original TTL without a record TTL to inherit")
            })?,
            3,
        )
    } else {
        if fields.len() < 9 {
            return Err(MasterError::new(
                "SIG with original TTL requires nine RDATA fields",
            ));
        }
        (
            parse_bytes_number(&field_bytes(fields, 3)?, "SIG original TTL")?,
            4,
        )
    };
    Ok(RData::SIG(Sig {
        type_covered: u16::from(parse_type_value(field_text(
            fields,
            0,
            "SIG covered TYPE",
        )?)?),
        algorithm: parse_algorithm_field(fields, 1, "SIG algorithm")?,
        labels: parse_u8_field(fields, 2, "SIG labels")?,
        original_ttl,
        signature_expiration: parse_signature_time(field_text(
            fields,
            expiration_index,
            "SIG expiration",
        )?)?,
        signature_inception: parse_signature_time(field_text(
            fields,
            expiration_index + 1,
            "SIG inception",
        )?)?,
        key_tag: parse_u16_field(fields, expiration_index + 2, "SIG key tag")?,
        signer_name: field_name(fields, expiration_index + 3, origin)?,
        signature: decode_base64_fields(&fields[expiration_index + 4..])?,
    }))
}

pub(super) fn parse_key(fields: &[String], class: ClassType) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::KEY, class, fields);
    }
    if fields.len() < 3 {
        return Err(MasterError::new(
            "KEY requires flags, protocol, and algorithm",
        ));
    }
    let flags = parse_key_flags(field_text(fields, 0, "KEY flags")?)?;
    let protocol_text = field_text(fields, 1, "KEY protocol")?;
    let protocol = match protocol_text.to_ascii_uppercase().as_str() {
        "NONE" => 0,
        "TLS" => 1,
        "EMAIL" => 2,
        "DNSSEC" => 3,
        "IPSEC" => 4,
        "ALL" => 255,
        _ => parse_u8_field(fields, 1, "KEY protocol")?,
    };
    let algorithm = parse_algorithm_field(fields, 2, "KEY algorithm")?;
    let no_key = flags & 0xc000 == 0xc000;
    let public_key = if no_key {
        if fields.len() != 3 {
            return Err(MasterError::new("NOKEY must not contain public key data"));
        }
        Vec::new()
    } else {
        decode_base64_fields(&fields[3..])?
    };
    Ok(RData::KEY(Key {
        flags,
        protocol,
        algorithm,
        public_key,
    }))
}

fn parse_key_flags(value: &str) -> Result<u16, MasterError> {
    if let Ok(flags) = value.parse::<u16>() {
        return Ok(flags);
    }
    let mut flags = 0;
    let mut name_type = None;
    let mut signatory = None;
    for symbol in value.to_ascii_uppercase().split('|') {
        let bits = match symbol {
            "NOCONF" => 0x4000,
            "NOAUTH" => 0x8000,
            "NOKEY" => 0xc000,
            "FLAG2" => 0x2000,
            "EXTEND" => 0x1000,
            "FLAG4" => 0x0800,
            "FLAG5" => 0x0400,
            "USER" | "ZONE" | "HOST" | "NTYP3" => {
                let bits = match symbol {
                    "USER" => 0,
                    "ZONE" => 0x0100,
                    "HOST" => 0x0200,
                    _ => 0x0300,
                };
                set_field(&mut name_type, bits)?;
                bits
            }
            "FLAG8" => 0x0080,
            "FLAG9" => 0x0040,
            "FLAG10" => 0x0020,
            "FLAG11" => 0x0010,
            _ => {
                let bits = symbol
                    .strip_prefix("SIG")
                    .filter(|number| {
                        !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
                    })
                    .and_then(|number| number.parse::<u16>().ok())
                    .filter(|number| *number <= 15)
                    .ok_or_else(|| MasterError::new(format!("invalid KEY flag: {symbol}")))?;
                set_field(&mut signatory, bits)?;
                bits
            }
        };
        flags |= bits;
    }
    Ok(flags)
}

fn set_field(field: &mut Option<u16>, value: u16) -> Result<(), MasterError> {
    if field.is_some_and(|previous| previous != value) {
        return Err(MasterError::new("conflicting KEY flag field values"));
    }
    *field = Some(value);
    Ok(())
}
