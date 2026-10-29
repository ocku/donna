//! Indexed work for large response sections; DNS policy remains in the caller.
use std::collections::{HashMap, HashSet, hash_map::Entry};

use dns::{ClassType, DomainName, RData, RecordType, ResourceRecord};

type RrsetKey<'a> = (&'a DomainName, RecordType, ClassType, Option<&'a RData>);

fn rrset_key(record: &ResourceRecord) -> RrsetKey<'_> {
    (
        &record.name,
        record.rtype,
        record.class,
        (u16::from(record.rtype) == 46).then_some(&record.rdata),
    )
}

pub(super) fn remove_lower_ranked(higher: &[ResourceRecord], lower: &mut Vec<ResourceRecord>) {
    let mut sets = HashSet::new();
    for record in higher {
        sets.insert(rrset_key(record));
    }
    lower.retain(|record| !sets.contains(&rrset_key(record)));
}

pub(super) fn deduplicate_section(records: &mut Vec<ResourceRecord>) {
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if !seen.insert((&record.name, record.rtype, record.class, &record.rdata)) {
            duplicates.push(index);
        }
    }
    // Keys borrow record identity. End those borrows before moving or removing
    // records, and preserve the first occurrence and its original wire order.
    drop(seen);
    if duplicates.is_empty() {
        return;
    }
    let mut duplicates = duplicates.into_iter().peekable();
    let mut index = 0;
    records.retain(|_| {
        let duplicate = duplicates.next_if_eq(&index).is_some();
        index += 1;
        !duplicate
    });
}

struct TtlGroup {
    first: u32,
    minimum: u32,
    mixed: bool,
    authoritative: bool,
}

pub(super) fn normalize_section(
    records: &mut Vec<ResourceRecord>,
    is_authoritative: impl Fn(&ResourceRecord) -> bool,
) -> bool {
    let mut by_rrset = HashMap::new();
    let mut groups: Vec<TtlGroup> = Vec::new();
    let mut record_groups = Vec::with_capacity(records.len());
    for record in records.iter() {
        if matches!(u16::from(record.rtype), 41 | 46) {
            record_groups.push(None);
            continue;
        }
        let key = (&record.name, record.rtype, record.class);
        let group = match by_rrset.entry(key) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = groups.len();
                groups.push(TtlGroup {
                    first: record.ttl,
                    minimum: record.ttl,
                    mixed: false,
                    // The caller's authority decision is based on the owner;
                    // every member of this RRset has the same authority scope.
                    authoritative: is_authoritative(record),
                });
                entry.insert(index);
                index
            }
        };
        let group_ttls = &mut groups[group];
        group_ttls.minimum = group_ttls.minimum.min(record.ttl);
        group_ttls.mixed |= group_ttls.first != record.ttl;
        record_groups.push(Some(group));
    }
    drop(by_rrset);

    let mut record_groups = record_groups.into_iter();
    let mut removed = false;
    records.retain_mut(|record| {
        let Some(group) = record_groups.next().expect("each record has a group") else {
            return true;
        };
        let group = &groups[group];
        if !group.mixed {
            return true;
        }
        if group.authoritative {
            record.ttl = group.minimum;
            true
        } else {
            removed = true;
            false
        }
    });
    removed
}
