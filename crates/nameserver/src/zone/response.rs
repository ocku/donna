use dns::{DomainName, RData, ResourceRecord};

pub(crate) fn additional_address_target(record: &ResourceRecord) -> Option<&DomainName> {
    match &record.rdata {
        RData::NS(name) | RData::MB(name) | RData::MD(name) | RData::MF(name) => Some(name),
        RData::MX { exchange, .. } => Some(exchange),
        RData::SRV { target, .. } if !target.as_ref().is_empty() => Some(target),
        _ => None,
    }
}

pub(crate) fn contains_record(records: &[ResourceRecord], candidate: &ResourceRecord) -> bool {
    records.iter().any(|record| {
        record.rtype == candidate.rtype
            && record.class == candidate.class
            && record.name.eq_dns(&candidate.name)
            && record.rdata == candidate.rdata
    })
}
