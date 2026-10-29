//! Authenticate BIND-captured DNSKEYs and negative answers using Donna's API.
use std::{env, fs, path::PathBuf, time::SystemTime};

use dns::{
    ClassType, DnssecValidation, DomainName, FromWire, Message, RData, RecordType,
    authenticate_dnskey_with_anchor,
};
use donna_interop::Failure;

fn read(path: PathBuf) -> Result<Message, Failure> {
    Ok(Message::from_wire(&fs::read(path)?)?)
}

fn main() -> Result<(), Failure> {
    let directory = PathBuf::from(env::args().nth(1).ok_or("provide a capture directory")?);
    let mode = env::args().nth(2).unwrap_or("nsec".into());
    let directory = directory.join(&mode);
    let keys = read(directory.join("keys.wire"))?;
    let key_records = keys
        .answers
        .iter()
        .filter(|r| r.rtype == RecordType::DNSKEY)
        .cloned()
        .collect::<Vec<_>>();
    let signatures = keys
        .answers
        .iter()
        .filter(|r| r.rtype == RecordType::RRSIG)
        .cloned()
        .collect::<Vec<_>>();
    let anchor = key_records
        .iter()
        .find_map(|r| match &r.rdata {
            RData::DNSKEY(key) if key.flags & 1 != 0 => Some(key),
            _ => None,
        })
        .ok_or("missing fixture KSK")?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as u32;
    let authenticated = authenticate_dnskey_with_anchor(
        &DomainName::from_dotted("example.test.")?,
        ClassType::IN,
        &key_records,
        &signatures,
        anchor,
        now,
    );
    let DnssecValidation::Secure(authenticated) = authenticated else {
        return Err(format!("fixture DNSKEY authentication failed: {authenticated:?}").into());
    };
    let mut failures = Vec::new();
    for (name, qtype, name_error) in [
        ("empty.example.test.", "A", false),
        ("deep.empty.example.test.", "AAAA", false),
        ("alias-empty.example.test.", "A", false),
        ("missing.empty.example.test.", "A", true),
        ("missing.example.test.", "A", true),
    ] {
        let response = read(directory.join(format!("{name}{qtype}.wire")))?;
        let records = response
            .authorities
            .iter()
            .filter(|r| {
                r.rtype
                    == if mode == "nsec" {
                        RecordType::NSEC
                    } else {
                        RecordType::NSEC3
                    }
            })
            .cloned()
            .collect::<Vec<_>>();
        let signatures = response
            .authorities
            .iter()
            .filter(|r| r.rtype == RecordType::RRSIG)
            .cloned()
            .collect::<Vec<_>>();
        let mut name = DomainName::from_dotted(name)?;
        // Authenticate each CNAME before following the denial's final name.
        for _ in 0..response.answers.len() {
            let Some(record) = response.answers.iter().find(|record| {
                record.name.eq_dns(&name) && matches!(record.rdata, RData::CNAME(_))
            }) else {
                break;
            };
            let cname_signatures = response
                .answers
                .iter()
                .filter(|record| record.rtype == RecordType::RRSIG)
                .cloned()
                .collect::<Vec<_>>();
            let result =
                authenticated.validate_rrset(std::slice::from_ref(record), &cname_signatures, now);
            if !matches!(result, DnssecValidation::Secure(_)) {
                return Err(format!("fixture CNAME authentication failed: {result:?}").into());
            }
            let RData::CNAME(target) = &record.rdata else {
                unreachable!()
            };
            name = target.clone();
        }
        let result = match (mode.as_str(), name_error) {
            ("nsec", true) => {
                authenticated.validate_nsec_name_error(&name, &records, &signatures, now)
            }
            ("nsec", false) => authenticated.validate_nsec_nodata(
                &name,
                if qtype == "A" { 1 } else { 28 },
                &records,
                &signatures,
                now,
            ),
            (_, true) => {
                authenticated.validate_nsec3_name_error(&name, &records, &signatures, now, 10)
            }
            (_, false) => authenticated.validate_nsec3_nodata(
                &name,
                if qtype == "A" { 1 } else { 28 },
                &records,
                &signatures,
                now,
                10,
            ),
        };
        println!("{mode} {name:?} {qtype}: {result:?}");
        if !matches!(result, DnssecValidation::Secure(_)) {
            failures.push(format!("{name:?} {qtype}"));
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "independent BIND proof validation failed: {}",
            failures.join(", ")
        )
        .into());
    }
    Ok(())
}
