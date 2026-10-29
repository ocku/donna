//! Applies validated RFC 2136 operations to a private zone snapshot.
use super::*;

pub(super) fn apply_operations(
    zone: &Zone,
    operations: &[ResourceRecord],
) -> Option<Vec<ResourceRecord>> {
    let mut records = zone.records().to_vec();
    let initial_serial = soa_serial(&records, zone.apex())?;

    for operation in operations {
        match operation.class {
            class if class == zone.class() => add_record(&mut records, operation.clone(), zone),
            ClassType::Unknown(ANY_CLASS) if is_any(operation.rtype) => {
                records.retain(|record| {
                    if !record.name.eq_dns(&operation.name) {
                        return true;
                    }
                    operation.name.eq_dns(zone.apex())
                        && matches!(record.rtype, RecordType::SOA | RecordType::NS)
                });
            }
            ClassType::Unknown(ANY_CLASS) => {
                if operation.name.eq_dns(zone.apex())
                    && matches!(operation.rtype, RecordType::SOA | RecordType::NS)
                {
                    continue;
                }
                records.retain(|record| {
                    !record.name.eq_dns(&operation.name) || record.rtype != operation.rtype
                });
            }
            ClassType::Unknown(NONE_CLASS) => {
                if operation.rtype == RecordType::SOA {
                    continue;
                }
                let matching_apex_ns = records
                    .iter()
                    .filter(|record| {
                        record.name.eq_dns(zone.apex()) && record.rtype == RecordType::NS
                    })
                    .count();
                if operation.name.eq_dns(zone.apex())
                    && operation.rtype == RecordType::NS
                    && matching_apex_ns == 1
                {
                    continue;
                }
                let mut normalized = operation.clone();
                normalized.class = zone.class();
                records.retain(|record| !record.eq_dns(&normalized));
            }
            _ => return None,
        }
    }

    if records_unchanged(zone.records(), &records) {
        return Some(records);
    }
    let current_serial = soa_serial(&records, zone.apex())?;
    if current_serial == initial_serial {
        set_soa_serial(&mut records, zone.apex(), next_soa_serial(initial_serial));
    }
    Some(records)
}

fn add_record(records: &mut Vec<ResourceRecord>, update: ResourceRecord, zone: &Zone) {
    // RFC 6672 permits replacing a DNAME but prohibits wildcard DNAMEs in
    // this implementation and DNAME at a non-apex delegation.
    if update.rtype == RecordType::DNAME
        && (update
            .name
            .as_ref()
            .first()
            .is_some_and(|label| label == b"*")
            || (!update.name.eq_dns(zone.apex())
                && records.iter().any(|record| {
                    record.name.eq_dns(&update.name) && record.rtype == RecordType::NS
                })))
    {
        return;
    }
    if update.rtype == RecordType::NS
        && !update.name.eq_dns(zone.apex())
        && records
            .iter()
            .any(|record| record.name.eq_dns(&update.name) && record.rtype == RecordType::DNAME)
    {
        return;
    }
    let owner_has_cname = records
        .iter()
        .any(|record| record.name.eq_dns(&update.name) && record.rtype == RecordType::CNAME);
    let owner_has_other_data = records.iter().any(|record| {
        record.name.eq_dns(&update.name)
            && record.rtype != RecordType::CNAME
            && !record.rtype.is_cname_companion()
    });
    if (update.rtype == RecordType::CNAME && owner_has_other_data)
        || (update.rtype != RecordType::CNAME
            && !update.rtype.is_cname_companion()
            && owner_has_cname)
    {
        return;
    }

    if update.rtype == RecordType::SOA {
        if !update.name.eq_dns(zone.apex()) {
            return;
        }
        let Some(old_serial) = soa_serial(records, zone.apex()) else {
            return;
        };
        let Some(new_serial) = record_soa_serial(&update) else {
            return;
        };
        if new_serial == 0
            || SerialNumber::new(old_serial).compare(SerialNumber::new(new_serial))
                != Some(Ordering::Less)
        {
            return;
        }
    }

    let existing_rrset_ttl = records
        .iter()
        .find(|record| record.name.eq_dns(&update.name) && record.rtype == update.rtype)
        .map(|record| record.ttl);
    if let Some(existing) = records.iter_mut().find(|record| {
        record.name.eq_dns(&update.name)
            && record.rtype == update.rtype
            && (matches!(
                update.rtype,
                RecordType::CNAME | RecordType::DNAME | RecordType::SOA
            ) || wks_key_equal(record, &update))
    }) {
        *existing = update.clone();
        // SOA, CNAME, and matching WKS updates replace an existing member.
        // Keep the RRset coherent when a WKS RRset has more than one member.
        for record in records
            .iter_mut()
            .filter(|record| record.name.eq_dns(&update.name) && record.rtype == update.rtype)
        {
            record.ttl = update.ttl;
        }
        return;
    }

    // An ordinary duplicate RDATA is silently ignored, including its TTL.
    // This makes a retransmitted addition a true no-op: it neither advances
    // the SOA serial nor causes a durable write.
    if records.iter().any(|record| record.eq_dns(&update)) {
        return;
    }

    let mut update = update;
    // RRset members have one TTL. An addition to an existing RRset adopts its
    // TTL, while the first member of a new RRset retains the supplied TTL.
    if let Some(ttl) = existing_rrset_ttl {
        update.ttl = ttl;
    }
    records.push(update);
}

fn next_soa_serial(current: u32) -> u32 {
    current.wrapping_add(1).max(1)
}

fn wks_key_equal(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    matches!(
        (&left.rdata, &right.rdata),
        (
            RData::WKS {
                address: left_address,
                protocol: left_protocol,
                ..
            },
            RData::WKS {
                address: right_address,
                protocol: right_protocol,
                ..
            }
        ) if left_address == right_address && left_protocol == right_protocol
    )
}

pub(super) fn unique_records(
    records: impl IntoIterator<Item = ResourceRecord>,
) -> Vec<ResourceRecord> {
    records.into_iter().fold(Vec::new(), |mut unique, record| {
        if !unique.iter().any(|existing| record.eq_dns(existing)) {
            unique.push(record);
        }
        unique
    })
}

pub(super) fn same_record_set(left: &[ResourceRecord], right: &[ResourceRecord]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|record| right.iter().any(|candidate| record.eq_dns(candidate)))
}
