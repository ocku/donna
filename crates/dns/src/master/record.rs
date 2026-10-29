use crate::{ClassType, DomainName, RData, RecordType, ResourceRecord};

use super::MasterError;
use super::lexer::Entry;
use super::presentation::name_from_presentation;
use super::rdata::{parse_number, parse_rdata};
use super::state::State;

pub(super) fn parse_record(
    entry: Entry<'_>,
    state: &mut State,
) -> Result<ResourceRecord, MasterError> {
    if !entry.inherited && entry.first_group == Some(0) {
        return Err(MasterError::new("record owner cannot be parenthesized"));
    }
    let (name, fields) = if entry.inherited {
        (inherited_owner(state)?, entry.fields.as_slice())
    } else {
        let name = name_from_presentation(entry.fields[0], state.origin.as_ref())?;
        state.owner = Some(name.clone());
        (name, &entry.fields[1..])
    };
    let (rtype, class, ttl, rdata) = parse_rr(fields, state)?;
    // An omitted SIG original TTL defaults to this record's ordinary TTL.
    // An explicit original TTL still supplies a TTL-less SIG's TTL below.
    let record_ttl = ttl.or(state.default_ttl).or(state.last_explicit_ttl);
    let rdata = parse_rdata(rtype, class, &rdata, state.origin.as_ref(), record_ttl)?;
    let ttl = inherited_ttl(ttl, rtype, &rdata, state)?;

    Ok(ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    })
}

fn inherited_ttl(
    explicit: Option<u32>,
    rtype: RecordType,
    rdata: &RData,
    state: &State,
) -> Result<u32, MasterError> {
    if let Some(ttl) = explicit {
        return Ok(ttl);
    }

    // RFC 2308 §4: an otherwise TTL-less SIG gets the original TTL from
    // its RDATA rather than the master file's $TTL default.
    if rtype == RecordType::SIG {
        let RData::SIG(sig) = rdata else {
            unreachable!("SIG uses structured RDATA")
        };
        let original_ttl = sig.original_ttl;
        if original_ttl > crate::constants::MAX_TTL {
            return Err(MasterError::new(format!(
                "SIG original TTL {original_ttl} exceeds the RFC 2181 maximum of {}",
                crate::constants::MAX_TTL
            )));
        }
        return Ok(original_ttl);
    }

    state
        .default_ttl
        .or(state.last_explicit_ttl)
        .ok_or_else(|| {
            MasterError::new(
                "record omits TTL before a $TTL directive or explicit TTL has been stated",
            )
        })
}

fn inherited_owner(state: &State) -> Result<DomainName, MasterError> {
    state
        .owner
        .clone()
        .ok_or_else(|| MasterError::new("record omits an owner before any owner has been stated"))
}

fn parse_rr(
    fields: &[&str],
    state: &mut State,
) -> Result<(RecordType, ClassType, Option<u32>, Vec<String>), MasterError> {
    let mut explicit_ttl = None;
    let mut explicit_class = false;
    for (index, value) in fields.iter().enumerate() {
        if value.bytes().all(|b| b.is_ascii_digit()) {
            if explicit_ttl.is_some() {
                return Err(MasterError::new("duplicate record TTL"));
            }
            let ttl = parse_number(value, "TTL")?;
            state.last_explicit_ttl = Some(ttl);
            explicit_ttl = Some(ttl);
        } else if is_class(value) {
            if explicit_class {
                return Err(MasterError::new("duplicate record class"));
            }
            state.class = Some(parse_class(value)?);
            explicit_class = true;
        } else {
            let rtype = parse_type(value)?;
            let rdata = &fields[index + 1..];
            if rdata.is_empty() {
                return Err(MasterError::new("record omits RDATA"));
            }
            for value in rdata {
                super::lexer::character_string(value)?;
            }
            let class = state.class.ok_or_else(|| {
                MasterError::new("record omits class before any class has been stated")
            })?;
            return Ok((
                rtype,
                class,
                explicit_ttl,
                rdata.iter().map(|s| (*s).to_owned()).collect(),
            ));
        }
    }
    Err(MasterError::new("record omits RR TYPE"))
}

fn is_class(value: &str) -> bool {
    matches!(value.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS")
        || value
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("CLASS"))
}

fn parse_class(value: &str) -> Result<ClassType, MasterError> {
    let uppercase = value.to_ascii_uppercase();
    match uppercase.as_str() {
        "IN" => Ok(ClassType::IN),
        "CH" => Ok(ClassType::CH),
        "HS" => Ok(ClassType::HS),
        _ => {
            let code = uppercase
                .strip_prefix("CLASS")
                .ok_or_else(|| MasterError::new(format!("unknown class {value}")))?
                .parse::<u16>()
                .map_err(|_| MasterError::new(format!("invalid class {value}")))?;
            crate::wire::class(code)
                .map_err(|_| MasterError::new(format!("invalid resource-record class {value}")))
        }
    }
}
fn parse_type(value: &str) -> Result<RecordType, MasterError> {
    let rtype = parse_type_value(value)?;
    if matches!(rtype, RecordType::MD | RecordType::MF) {
        Err(MasterError::new(format!(
            "obsolete {} records are not accepted in master files",
            value.to_ascii_uppercase()
        )))
    } else {
        Ok(rtype)
    }
}

pub(super) fn parse_type_value(value: &str) -> Result<RecordType, MasterError> {
    let uppercase = value.to_ascii_uppercase();
    match uppercase.as_str() {
        "A" => Ok(RecordType::A),
        "NS" => Ok(RecordType::NS),
        "MD" => Ok(RecordType::MD),
        "MF" => Ok(RecordType::MF),
        "CNAME" => Ok(RecordType::CNAME),
        "DNAME" => Ok(RecordType::DNAME),
        "SOA" => Ok(RecordType::SOA),
        "MB" => Ok(RecordType::MB),
        "MG" => Ok(RecordType::MG),
        "MR" => Ok(RecordType::MR),
        "NULL" => Ok(RecordType::NULL),
        "WKS" => Ok(RecordType::WKS),
        "PTR" => Ok(RecordType::PTR),
        "HINFO" => Ok(RecordType::HINFO),
        "MINFO" => Ok(RecordType::MINFO),
        "MX" => Ok(RecordType::MX),
        "TXT" => Ok(RecordType::TXT),
        "SIG" => Ok(RecordType::SIG),
        "KEY" => Ok(RecordType::KEY),
        "AAAA" => Ok(RecordType::AAAA),
        "SRV" => Ok(RecordType::SRV),
        "CSYNC" => Ok(RecordType::CSYNC),
        "TSIG" => Ok(RecordType::TSIG),
        "CAA" => Ok(RecordType::CAA),
        "OPT" => Ok(RecordType::OPT),
        "DS" => Ok(RecordType::DS),
        "RRSIG" => Ok(RecordType::RRSIG),
        "NSEC" => Ok(RecordType::NSEC),
        "DNSKEY" => Ok(RecordType::DNSKEY),
        "NSEC3" => Ok(RecordType::NSEC3),
        "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
        "TLSA" => Ok(RecordType::TLSA),
        "SMIMEA" => Ok(RecordType::SMIMEA),
        _ => {
            let code = uppercase
                .strip_prefix("TYPE")
                .ok_or_else(|| MasterError::new(format!("unknown type {value}")))?
                .parse::<u16>()
                .map_err(|_| MasterError::new(format!("invalid type {value}")))?;
            let rtype = crate::wire::record_type(code)
                .map_err(|_| MasterError::new(format!("invalid resource-record type {value}")))?;
            Ok(rtype)
        }
    }
}
