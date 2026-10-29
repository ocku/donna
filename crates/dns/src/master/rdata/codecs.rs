use crate::{
    CertificateAssociation, ClassType, Dnskey, DomainName, Ds, Nsec, Nsec3, Nsec3param, RData,
    RecordType, Rrsig, TypeBitmap,
};

use super::generic::decode_structured_generic;

use super::{
    MasterError, decode_character_string, exactly, field, field_bytes, field_name,
    parse_bytes_number, parse_type_value,
};

pub(super) fn parse_certificate_association(
    fields: &[String],
    class: ClassType,
    rtype: RecordType,
) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(rtype, class, fields);
    }
    if fields.len() < 4 {
        return Err(MasterError::new(
            "TLSA/SMIMEA requires usage, selector, matching type, and association data",
        ));
    }
    let association = CertificateAssociation {
        certificate_usage: parse_u8_field(fields, 0, "certificate usage")?,
        selector: parse_u8_field(fields, 1, "selector")?,
        matching_type: parse_u8_field(fields, 2, "matching type")?,
        association_data: decode_hex_fields(&fields[3..], "certificate association data")?,
    };
    Ok(match rtype {
        RecordType::TLSA => RData::TLSA(association),
        RecordType::SMIMEA => RData::SMIMEA(association),
        _ => unreachable!("caller selects an association record type"),
    })
}

pub(super) fn parse_ds(fields: &[String], class: ClassType) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::DS, class, fields);
    }
    if fields.len() < 4 {
        return Err(MasterError::new("DS requires four RDATA fields"));
    }
    Ok(RData::DS(Ds {
        key_tag: parse_u16_field(fields, 0, "DS key tag")?,
        algorithm: parse_algorithm_field(fields, 1, "DS algorithm")?,
        digest_type: parse_u8_field(fields, 2, "DS digest type")?,
        digest: decode_hex_fields(&fields[3..], "DS digest")?,
    }))
}

pub(super) fn parse_rrsig(
    fields: &[String],
    origin: Option<&DomainName>,
    class: ClassType,
) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::RRSIG, class, fields);
    }
    if fields.len() < 9 {
        return Err(MasterError::new("RRSIG requires nine RDATA fields"));
    }
    let covered = field_text(fields, 0, "RRSIG covered TYPE")?;
    Ok(RData::RRSIG(Rrsig {
        type_covered: u16::from(parse_type_value(covered)?),
        algorithm: parse_algorithm_field(fields, 1, "RRSIG algorithm")?,
        labels: parse_u8_field(fields, 2, "RRSIG labels")?,
        original_ttl: parse_bytes_number(&field_bytes(fields, 3)?, "RRSIG original TTL")?,
        signature_expiration: parse_signature_time(field_text(fields, 4, "RRSIG expiration")?)?,
        signature_inception: parse_signature_time(field_text(fields, 5, "RRSIG inception")?)?,
        key_tag: parse_u16_field(fields, 6, "RRSIG key tag")?,
        signer_name: field_name(fields, 7, origin)?,
        signature: decode_base64_fields(&fields[8..])?,
    }))
}

pub(super) fn parse_nsec(
    fields: &[String],
    origin: Option<&DomainName>,
    class: ClassType,
) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::NSEC, class, fields);
    }
    if fields.len() < 2 {
        return Err(MasterError::new(
            "NSEC requires a next domain name and at least one RR TYPE",
        ));
    }
    let type_codes = fields[1..]
        .iter()
        .map(|field| {
            let value = decode_character_string(field)?;
            let value = std::str::from_utf8(&value)
                .map_err(|_| MasterError::new("NSEC RR TYPE is not text"))?;
            Ok(u16::from(parse_type_value(value)?))
        })
        .collect::<Result<Vec<_>, MasterError>>()?;
    let type_bitmap = TypeBitmap::new(type_codes)
        .map_err(|error| MasterError::new(format!("invalid NSEC type bitmap: {error}")))?;
    Ok(RData::NSEC(Nsec {
        next_domain_name: field_name(fields, 0, origin)?,
        type_bitmap,
    }))
}

pub(super) fn parse_dnskey(fields: &[String], class: ClassType) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::DNSKEY, class, fields);
    }
    if fields.len() < 4 {
        return Err(MasterError::new("DNSKEY requires four RDATA fields"));
    }
    Ok(RData::DNSKEY(Dnskey {
        flags: parse_u16_field(fields, 0, "DNSKEY flags")?,
        protocol: parse_u8_field(fields, 1, "DNSKEY protocol")?,
        algorithm: parse_algorithm_field(fields, 2, "DNSKEY algorithm")?,
        public_key: decode_base64_fields(&fields[3..])?,
    }))
}

pub(super) fn parse_nsec3(fields: &[String], class: ClassType) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::NSEC3, class, fields);
    }
    if fields.len() < 5 {
        return Err(MasterError::new(
            "NSEC3 requires at least five RDATA fields",
        ));
    }
    let type_bitmap = if fields.len() == 5 {
        None
    } else {
        let codes = fields[5..]
            .iter()
            .map(|field| {
                let bytes = decode_character_string(field)?;
                let value = std::str::from_utf8(&bytes)
                    .map_err(|_| MasterError::new("NSEC3 RR TYPE is not text"))?;
                Ok(u16::from(parse_type_value(value)?))
            })
            .collect::<Result<Vec<_>, MasterError>>()?;
        Some(
            TypeBitmap::new(codes)
                .map_err(|error| MasterError::new(format!("invalid NSEC3 type bitmap: {error}")))?,
        )
    };
    Ok(RData::NSEC3(Nsec3 {
        hash_algorithm: parse_u8_field(fields, 0, "NSEC3 hash algorithm")?,
        flags: parse_u8_field(fields, 1, "NSEC3 flags")?,
        iterations: parse_u16_field(fields, 2, "NSEC3 iterations")?,
        salt: parse_nsec3_salt(fields, 3)?,
        next_hashed_owner_name: decode_base32hex(field_text(
            fields,
            4,
            "NSEC3 next hashed owner name",
        )?)?,
        type_bitmap,
    }))
}

pub(super) fn parse_nsec3param(fields: &[String], class: ClassType) -> Result<RData, MasterError> {
    if fields.first().is_some_and(|field| field == "\\#") {
        return decode_structured_generic(RecordType::NSEC3PARAM, class, fields);
    }
    exactly(fields, 4, "NSEC3PARAM")?;
    Ok(RData::NSEC3PARAM(Nsec3param {
        hash_algorithm: parse_u8_field(fields, 0, "NSEC3PARAM hash algorithm")?,
        flags: parse_u8_field(fields, 1, "NSEC3PARAM flags")?,
        iterations: parse_u16_field(fields, 2, "NSEC3PARAM iterations")?,
        salt: parse_nsec3_salt(fields, 3)?,
    }))
}

fn parse_nsec3_salt(fields: &[String], index: usize) -> Result<Vec<u8>, MasterError> {
    if field(fields, index)? == "-" {
        Ok(Vec::new())
    } else {
        decode_hex_fields(&fields[index..=index], "NSEC3 salt")
    }
}

fn decode_base32hex(value: &str) -> Result<Vec<u8>, MasterError> {
    if value.is_empty() || value.contains('=') || !value.is_ascii() {
        return Err(MasterError::new("invalid NSEC3 Base32hex value"));
    }
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    for octet in value.bytes() {
        let digit = match octet.to_ascii_uppercase() {
            b'0'..=b'9' => octet - b'0',
            uppercase @ b'A'..=b'V' => uppercase - b'A' + 10,
            _ => return Err(MasterError::new("invalid NSEC3 Base32hex value")),
        };
        accumulator = (accumulator << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    if bits >= 5 || accumulator != 0 || output.is_empty() {
        return Err(MasterError::new("invalid NSEC3 Base32hex value"));
    }
    Ok(output)
}

pub(super) fn parse_u8_field(
    fields: &[String],
    index: usize,
    label: &str,
) -> Result<u8, MasterError> {
    u8::try_from(parse_bytes_number(&field_bytes(fields, index)?, label)?)
        .map_err(|_| MasterError::new(format!("{label} exceeds 255")))
}

pub(super) fn parse_u16_field(
    fields: &[String],
    index: usize,
    label: &str,
) -> Result<u16, MasterError> {
    u16::try_from(parse_bytes_number(&field_bytes(fields, index)?, label)?)
        .map_err(|_| MasterError::new(format!("{label} exceeds 65535")))
}

pub(super) fn field_text<'a>(
    fields: &'a [String],
    index: usize,
    label: &str,
) -> Result<&'a str, MasterError> {
    let value = field(fields, index)?;
    if value.is_ascii() {
        Ok(value)
    } else {
        Err(MasterError::new(format!("{label} is not ASCII text")))
    }
}

pub(super) fn parse_algorithm_field(
    fields: &[String],
    index: usize,
    label: &str,
) -> Result<u8, MasterError> {
    let value = field_text(fields, index, label)?;
    if let Ok(number) = value.parse::<u8>() {
        return Ok(number);
    }
    let algorithm = match value.to_ascii_uppercase().as_str() {
        "RSAMD5" => 1,
        "DH" => 2,
        "DSA" => 3,
        "ECC" => 4,
        "RSASHA1" => 5,
        "DSA-NSEC3-SHA1" => 6,
        "RSASHA1-NSEC3-SHA1" => 7,
        "RSASHA256" => 8,
        "RSASHA512" => 10,
        "ECC-GOST" => 12,
        "ECDSAP256SHA256" => 13,
        "ECDSAP384SHA384" => 14,
        "ED25519" => 15,
        "ED448" => 16,
        "INDIRECT" => 252,
        "PRIVATEDNS" => 253,
        "PRIVATEOID" => 254,
        _ => return Err(MasterError::new(format!("invalid {label}: {value}"))),
    };
    Ok(algorithm)
}

fn decode_hex_fields(fields: &[String], label: &str) -> Result<Vec<u8>, MasterError> {
    let mut hex = Vec::new();
    for field in fields {
        hex.extend(field_bytes(std::slice::from_ref(field), 0)?);
    }
    if hex.is_empty() || hex.len() % 2 != 0 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(MasterError::new(format!(
            "{label} is not valid hexadecimal"
        )));
    }
    Ok(hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).expect("validated hexadecimal is ASCII"),
                16,
            )
            .expect("two hexadecimal digits fit in one octet")
        })
        .collect())
}

pub(super) fn parse_signature_time(value: &str) -> Result<u32, MasterError> {
    if value.len() != 14 {
        return value
            .parse::<u32>()
            .map_err(|_| MasterError::new(format!("invalid signature time: {value}")));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(MasterError::new(format!("invalid signature time: {value}")));
    }
    let number = |range: std::ops::Range<usize>| {
        value[range]
            .parse::<u32>()
            .expect("validated decimal digits parse as an integer")
    };
    let year = number(0..4);
    let month = number(4..6);
    let day = number(6..8);
    let hour = number(8..10);
    let minute = number(10..12);
    let second = number(12..14);
    if !(1970..=2106).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(MasterError::new(format!("invalid signature time: {value}")));
    }
    let leap_year = |candidate: u32| {
        candidate.is_multiple_of(4)
            && (!candidate.is_multiple_of(100) || candidate.is_multiple_of(400))
    };
    let mut month_days = [31_u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if leap_year(year) {
        month_days[1] = 29;
    }
    if day == 0 || day > month_days[(month - 1) as usize] {
        return Err(MasterError::new(format!("invalid signature time: {value}")));
    }
    let days_before_year = (1970..year)
        .map(|candidate| if leap_year(candidate) { 366_u64 } else { 365 })
        .sum::<u64>();
    let days_before_month = month_days[..(month - 1) as usize]
        .iter()
        .map(|days| u64::from(*days))
        .sum::<u64>();
    let seconds = (days_before_year + days_before_month + u64::from(day - 1)) * 86_400
        + u64::from(hour) * 3_600
        + u64::from(minute) * 60
        + u64::from(second);
    u32::try_from(seconds)
        .map_err(|_| MasterError::new(format!("signature time exceeds 32 bits: {value}")))
}

pub(super) fn decode_base64_fields(fields: &[String]) -> Result<Vec<u8>, MasterError> {
    let mut encoded = Vec::new();
    for field in fields {
        encoded.extend(field_bytes(std::slice::from_ref(field), 0)?);
    }
    if encoded.is_empty() || encoded.len() % 4 != 0 {
        return Err(MasterError::new("base64 data has invalid length"));
    }
    let mut output = Vec::with_capacity(encoded.len() / 4 * 3);
    for (chunk_index, chunk) in encoded.as_chunks::<4>().0.iter().enumerate() {
        let final_chunk = chunk_index + 1 == encoded.len() / 4;
        let value = |octet| match octet {
            b'A'..=b'Z' => Some(octet - b'A'),
            b'a'..=b'z' => Some(octet - b'a' + 26),
            b'0'..=b'9' => Some(octet - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        };
        let a = value(chunk[0]);
        let b = value(chunk[1]);
        let c = value(chunk[2]);
        let d = value(chunk[3]);
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if a.is_none()
            || b.is_none()
            || (chunk[2] != b'=' && c.is_none())
            || (chunk[3] != b'=' && d.is_none())
            || padding > 2
            || (padding != 0 && !final_chunk)
            || (chunk[2] == b'=' && chunk[3] != b'=')
        {
            return Err(MasterError::new("invalid base64 data"));
        }
        let bits = (u32::from(a.unwrap()) << 18)
            | (u32::from(b.unwrap()) << 12)
            | (u32::from(c.unwrap_or(0)) << 6)
            | u32::from(d.unwrap_or(0));
        output.push((bits >> 16) as u8);
        if padding < 2 {
            output.push((bits >> 8) as u8);
        }
        if padding == 0 {
            output.push(bits as u8);
        }
    }
    Ok(output)
}
