use crate::ZoneError;
use dns::master::MasterFile;
use dns::{ClassType, DomainName, RData, RecordType, ResourceRecord};

pub(super) fn validate_snapshot(
    apex: &DomainName,
    expected_class: Option<ClassType>,
    master: MasterFile,
) -> Result<(Vec<ResourceRecord>, ResourceRecord), ZoneError> {
    master
        .validate_strict()
        .map_err(|error| ZoneError::new(error.to_string()))?;
    let records = master.records;
    if records
        .iter()
        .any(|record| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0()))
    {
        return Err(ZoneError::new(
            "a transaction-only SIG(0) cannot be published as zone data",
        ));
    }
    let soa = required_apex_soa(apex, &records)?;
    let class = expected_class.unwrap_or(soa.class);
    if soa.class != class || records.iter().any(|record| record.class != class) {
        return Err(ZoneError::new(
            "every record in a zone snapshot must use the zone's class",
        ));
    }

    require_apex_ns(apex, &records)?;
    validate_csync(apex, &records)?;
    validate_dnames(apex, &records)?;
    validate_ownership_and_delegations(apex, &records)?;
    validate_canonical_targets(apex, &records)?;
    Ok((records, soa))
}

fn validate_dnames(apex: &DomainName, records: &[ResourceRecord]) -> Result<(), ZoneError> {
    for dname in records
        .iter()
        .filter(|record| record.rtype == RecordType::DNAME)
    {
        if dname
            .name
            .as_ref()
            .first()
            .is_some_and(|label| label == b"*")
        {
            return Err(ZoneError::new("wildcard DNAME is not supported"));
        }
        if records
            .iter()
            .filter(|record| record.rtype == RecordType::DNAME && record.name.eq_dns(&dname.name))
            .count()
            > 1
        {
            return Err(ZoneError::new("a DNAME owner must have exactly one DNAME"));
        }
        if !dname.name.eq_dns(apex)
            && records
                .iter()
                .any(|record| record.rtype == RecordType::NS && record.name.eq_dns(&dname.name))
        {
            return Err(ZoneError::new("DNAME cannot coexist with a delegation"));
        }
    }
    Ok(())
}

pub(super) fn validate_canonical_targets(
    apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), ZoneError> {
    let cuts = active_delegation_cuts(apex, records);
    for record in records {
        if cuts
            .iter()
            .any(|cut| record.name.is_descendant_of(cut) && !record.name.eq_dns(cut))
        {
            continue;
        }
        let (kind, target, requires_address) = match &record.rdata {
            RData::PTR(target) => ("PTR", target, false),
            RData::NS(target) => ("NS", target, true),
            RData::MX { exchange, .. } => ("MX", exchange, true),
            RData::SRV { target, .. } => ("SRV", target, !target.as_ref().is_empty()),
            RData::SOA { mname, .. } => {
                // RFC 2181 section 7.3 discourages using the zone name as a
                // placeholder. An apex with address data can also be the actual
                // primary hostname (RFC 1035 section 3.3.13).
                if mname.as_ref().is_empty()
                    || (mname.eq_dns(apex)
                        && !records.iter().any(|candidate| {
                            candidate.name.eq_dns(mname) && is_address_record(candidate)
                        }))
                {
                    return Err(ZoneError::new(
                        "SOA MNAME must identify a primary server; an apex primary requires address data",
                    ));
                }
                ("SOA MNAME", mname, false)
            }
            _ => continue,
        };
        if records.iter().any(|candidate| {
            !name_is_occluded(&candidate.name, &cuts)
                && ((candidate.rtype == RecordType::CNAME && candidate.name.eq_dns(target))
                    || (candidate.rtype == RecordType::DNAME
                        && target.is_descendant_of(&candidate.name)
                        && !target.eq_dns(&candidate.name)))
        }) {
            return Err(ZoneError::new(format!(
                "{kind} target must not be an alias"
            )));
        }
        if requires_address
            && target_is_authoritative(apex, target, &cuts)
            && !records
                .iter()
                .any(|candidate| candidate.name.eq_dns(target) && is_address_record(candidate))
        {
            return Err(ZoneError::new(format!(
                "authoritative in-zone {kind} target requires an address record"
            )));
        }
    }
    Ok(())
}

fn target_is_authoritative(apex: &DomainName, target: &DomainName, cuts: &[DomainName]) -> bool {
    target.is_descendant_of(apex) && !cuts.iter().any(|cut| target.is_descendant_of(cut))
}

fn name_is_occluded(name: &DomainName, cuts: &[DomainName]) -> bool {
    cuts.iter()
        .any(|cut| name.is_descendant_of(cut) && !name.eq_dns(cut))
}

pub(super) fn required_apex_soa(
    apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<ResourceRecord, ZoneError> {
    let apex_soa_records: Vec<_> = records
        .iter()
        .filter(|record| record.rtype == RecordType::SOA && record.name.eq_dns(apex))
        .cloned()
        .collect();
    let cuts = active_delegation_cuts(apex, records);
    let has_visible_non_apex_soa = records.iter().any(|record| {
        record.rtype == RecordType::SOA
            && !record.name.eq_dns(apex)
            && !cuts
                .iter()
                .any(|cut| record.name.is_descendant_of(cut) && !record.name.eq_dns(cut))
    });

    match apex_soa_records.as_slice() {
        [soa] if !has_visible_non_apex_soa => Ok(soa.clone()),
        _ => Err(ZoneError::new(
            "a zone requires exactly one visible SOA, located at its apex",
        )),
    }
}

pub(super) fn require_apex_ns(
    apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), ZoneError> {
    if records
        .iter()
        .any(|record| record.name.eq_dns(apex) && record.rtype == RecordType::NS)
    {
        Ok(())
    } else {
        Err(ZoneError::new("a zone requires an NS RRSet at its apex"))
    }
}

pub(super) fn validate_csync(
    apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), ZoneError> {
    let csync = records
        .iter()
        .filter(|record| record.rtype == RecordType::CSYNC)
        .collect::<Vec<_>>();
    if csync.len() > 1 || csync.iter().any(|record| !record.name.eq_dns(apex)) {
        return Err(ZoneError::new(
            "a child zone may publish at most one CSYNC record, located at its apex",
        ));
    }
    if let Some(record) = csync.first() {
        let RData::CSYNC(csync) = &record.rdata else {
            return Err(ZoneError::new("CSYNC TYPE does not contain CSYNC RDATA"));
        };
        if csync.unknown_flags() != 0 {
            return Err(ZoneError::new(
                "a published CSYNC record has reserved flags set",
            ));
        }
        if csync
            .type_bitmap
            .codes()
            .iter()
            .any(|code| matches!(code, 43 | 48 | 59 | 60 | 62))
        {
            return Err(ZoneError::new(
                "CSYNC must not request synchronization of DNSSEC or CSYNC records",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_ownership_and_delegations(
    apex: &DomainName,
    records: &[ResourceRecord],
) -> Result<(), ZoneError> {
    if records
        .iter()
        .any(|record| !record.name.is_descendant_of(apex))
    {
        return Err(ZoneError::new(
            "a zone cannot contain an owner outside its apex",
        ));
    }

    let cuts = active_delegation_cuts(apex, records);

    for cut in &cuts {
        for record in records.iter().filter(|record| record.name.eq_dns(cut)) {
            let allowed = record.rtype == RecordType::NS
                || matches!(u16::from(record.rtype), 43 | 46 | 47)
                || (is_address_record(record)
                    && records.iter().any(|candidate| {
                        candidate.name.eq_dns(cut)
                            && matches!(&candidate.rdata, RData::NS(target) if target.eq_dns(cut))
                    }));
            if !allowed {
                return Err(ZoneError::new(
                    "a parent zone cannot contain non-delegation data at a zone cut",
                ));
            }
        }

        for nameserver in records.iter().filter_map(|record| {
            if record.name.eq_dns(cut) {
                match &record.rdata {
                    RData::NS(host) if host.is_descendant_of(cut) => Some(host),
                    _ => None,
                }
            } else {
                None
            }
        }) {
            let has_address = records
                .iter()
                .any(|record| record.name.eq_dns(nameserver) && is_address_record(record));
            if !has_address {
                return Err(ZoneError::new(
                    "an in-bailiwick delegation name server requires address glue",
                ));
            }
        }
    }

    Ok(())
}

fn active_delegation_cuts(apex: &DomainName, records: &[ResourceRecord]) -> Vec<DomainName> {
    let candidates = records
        .iter()
        .filter(|record| record.rtype == RecordType::NS && !record.name.eq_dns(apex))
        .map(|record| record.name.clone())
        .fold(Vec::<DomainName>::new(), |mut cuts, name| {
            if !cuts.iter().any(|cut| cut.eq_dns(&name)) {
                cuts.push(name);
            }
            cuts
        });
    candidates
        .iter()
        .filter(|cut| {
            !candidates
                .iter()
                .any(|ancestor| !cut.eq_dns(ancestor) && cut.is_descendant_of(ancestor))
        })
        .cloned()
        .collect()
}

fn is_address_record(record: &ResourceRecord) -> bool {
    match (&record.rtype, &record.rdata, record.class) {
        (RecordType::A, RData::A(_), dns::ClassType::IN)
        | (RecordType::AAAA, RData::AAAA(_), dns::ClassType::IN) => true,
        (RecordType::A, RData::Unknown(_), class) => class != dns::ClassType::IN,
        _ => false,
    }
}
