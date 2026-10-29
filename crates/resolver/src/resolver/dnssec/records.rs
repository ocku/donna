use std::time::SystemTime;

use dns::{
    ClassType, DnssecValidation, DnssecValidationError, DomainName, Message, QClassType, QueryType,
    Question, RData, RecordType, ResourceRecord,
};

use crate::{ResolveError, response::query_type_matches_record};

pub(super) fn validation_result<T>(validation: DnssecValidation<T>) -> Result<T, ResolveError> {
    match validation {
        DnssecValidation::Secure(value) => Ok(value),
        DnssecValidation::Insecure => Err(ResolveError::DnssecIndeterminate(
            DnssecValidationError::NoValidSignature,
        )),
        DnssecValidation::Bogus(error) => Err(ResolveError::DnssecBogus(error)),
        DnssecValidation::Indeterminate(error) => Err(ResolveError::DnssecIndeterminate(error)),
    }
}

pub(super) fn records_at_type(
    records: &[ResourceRecord],
    owner: &DomainName,
    rtype: RecordType,
    class: ClassType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| {
            record.name.eq_dns(owner) && record.rtype == rtype && record.class == class
        })
        .cloned()
        .collect()
}

pub(super) fn signatures_covering(
    records: &[ResourceRecord],
    owner: &DomainName,
    covered: RecordType,
    class: ClassType,
) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|record| {
            record.name.eq_dns(owner)
                && record.class == class
                && matches!(&record.rdata, RData::RRSIG(rrsig)
                    if rrsig.type_covered == u16::from(covered))
        })
        .cloned()
        .collect()
}

pub(super) fn clamp_rrset_ttl(
    records: &mut [ResourceRecord],
    owner: &DomainName,
    covered: RecordType,
    class: ClassType,
    ttl: u32,
) {
    for record in records {
        let is_rrset_member = record.name.eq_dns(owner)
            && record.class == class
            && (record.rtype == covered
                || matches!(&record.rdata, RData::RRSIG(rrsig)
                    if rrsig.type_covered == u16::from(covered)));
        if is_rrset_member {
            record.ttl = record.ttl.min(ttl);
        }
    }
}

pub(super) fn clamp_denial_ttl(records: &mut [ResourceRecord], ttl: u32) {
    for record in records {
        let is_denial = matches!(record.rtype, RecordType::NSEC | RecordType::NSEC3);
        let is_denial_signature = matches!(&record.rdata, RData::RRSIG(rrsig)
            if matches!(rrsig.type_covered, value
                if value == u16::from(RecordType::NSEC)
                    || value == u16::from(RecordType::NSEC3)));
        if is_denial || is_denial_signature {
            record.ttl = record.ttl.min(ttl);
        }
    }
}

pub(super) fn clamp_all_ttl(response: &mut Message, ttl: u32) {
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
        .filter(|record| record.rtype != RecordType::OPT)
    {
        record.ttl = record.ttl.min(ttl);
    }
}

pub(super) fn signature_signer(record: &ResourceRecord) -> Option<DomainName> {
    match &record.rdata {
        RData::RRSIG(rrsig) => Some(rrsig.signer_name.clone()),
        _ => None,
    }
}

pub(super) fn parent_signer(
    response: &Message,
    child: &DomainName,
    class: ClassType,
) -> Option<DomainName> {
    response
        .answers
        .iter()
        .chain(&response.authorities)
        .filter(|record| record.class == class)
        .filter_map(|record| match &record.rdata {
            RData::RRSIG(rrsig)
                if (rrsig.type_covered == u16::from(RecordType::DS)
                    && record.name.eq_dns(child))
                    || matches!(
                        rrsig.type_covered,
                        value if value == u16::from(RecordType::NSEC)
                            || value == u16::from(RecordType::NSEC3)
                    ) =>
            {
                Some(rrsig.signer_name.clone())
            }
            _ => None,
        })
        .next()
}

pub(super) fn answer_rrsets(records: &[ResourceRecord]) -> Vec<Vec<ResourceRecord>> {
    let mut sets: Vec<Vec<ResourceRecord>> = Vec::new();
    for record in records
        .iter()
        .filter(|record| record.rtype != RecordType::RRSIG)
    {
        if let Some(set) = sets.iter_mut().find(|set| {
            set[0].name.eq_dns(&record.name)
                && set[0].rtype == record.rtype
                && set[0].class == record.class
        }) {
            set.push(record.clone());
        } else {
            sets.push(vec![record.clone()]);
        }
    }
    sets
}

pub(super) fn is_negative(response: &Message, question: &Question) -> bool {
    let terminal = terminal_name(question, &response.answers);
    response.headers.rcode == dns::RCode::NameError
        || (response.headers.rcode == dns::RCode::Ok
            && !response.answers.iter().any(|record| {
                record.name.eq_dns(&terminal)
                    && question.qclass == QClassType::Class(record.class)
                    && query_type_matches_record(question.qtype, record.rtype)
            }))
}

pub(super) fn terminal_name(question: &Question, answers: &[ResourceRecord]) -> DomainName {
    let mut current = question.qname.clone();
    if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
        return current;
    }
    for _ in 0..answers.len() {
        let Some(target) = answers.iter().find_map(|record| {
            (record.rtype == RecordType::CNAME
                && question.qclass == QClassType::Class(record.class)
                && record.name.eq_dns(&current))
            .then(|| match &record.rdata {
                RData::CNAME(target) => Some(target.clone()),
                _ => None,
            })
            .flatten()
        }) else {
            break;
        };
        current = target;
    }
    current
}

pub(super) fn closest_soa_owner(
    response: &Message,
    name: &DomainName,
    class: ClassType,
) -> Option<DomainName> {
    response
        .answers
        .iter()
        .chain(&response.authorities)
        .filter(|record| {
            record.rtype == RecordType::SOA
                && record.class == class
                && name.is_descendant_of(&record.name)
        })
        .max_by_key(|record| record.name.as_ref().len())
        .map(|record| record.name.clone())
}

pub(super) fn unix_time() -> u32 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs() as u32
}
