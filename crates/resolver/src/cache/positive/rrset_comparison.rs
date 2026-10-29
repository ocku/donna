//! Compare overlapping cached RRsets without repeatedly scanning their members.
use std::collections::{HashMap, HashSet};

use dns::{ClassType, DomainName, RData, RecordType, ResourceRecord};

type RrsetKey<'a> = (&'a DomainName, RecordType, ClassType, Option<u16>);
type RecordKey<'a> = (RrsetKey<'a>, &'a RData);

fn rrset_key(record: &ResourceRecord) -> RrsetKey<'_> {
    // RFC 4035 §2.2: RRSIGs are tied to the covered RRset, rather than
    // forming one ordinary owner/type/class RRset of their own. Different
    // algorithms and keys for the same covered type still compare together.
    let covered = match &record.rdata {
        RData::RRSIG(signature) if record.rtype == RecordType::RRSIG => {
            Some(signature.type_covered)
        }
        _ => None,
    };
    (&record.name, record.rtype, record.class, covered)
}

fn record_key(record: &ResourceRecord) -> RecordKey<'_> {
    (rrset_key(record), &record.rdata)
}

pub(super) fn rrsets_overlap(left: &[ResourceRecord], right: &[ResourceRecord]) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    // Most aggregate/concrete comparisons share the first RRset. Avoid
    // constructing indexes when that already establishes their overlap.
    if rrset_key(&left[0]) == rrset_key(&right[0]) {
        return true;
    }
    if left.len().min(right.len()) <= 8 {
        return left.iter().any(|record| {
            right
                .iter()
                .any(|candidate| rrset_key(record) == rrset_key(candidate))
        });
    }
    let mut sets = HashSet::new();
    for record in left {
        sets.insert(rrset_key(record));
    }
    right.iter().any(|record| sets.contains(&rrset_key(record)))
}

pub(super) fn rrsets_conflict(left: &[ResourceRecord], right: &[ResourceRecord]) -> bool {
    if left.len().max(right.len()) <= 8 {
        return small_rrsets_conflict(left, right);
    }
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let left_counts = rrset_counts(left);
    let right_counts = rrset_counts(right);
    let mut overlaps = false;
    for (key, count) in &left_counts {
        if let Some(right_count) = right_counts.get(key) {
            overlaps = true;
            if count != right_count {
                return true;
            }
        }
    }
    if !overlaps {
        return false;
    }

    // Record identity excludes the outer TTL. DomainName and RData implement
    // DNS-aware equality and matching hashes, including embedded name case.
    // Full keys still decide equality even if two hashes collide.
    let right_members: HashSet<_> = right.iter().map(record_key).collect();
    left.iter().any(|record| {
        right_counts.contains_key(&rrset_key(record))
            && !right_members.contains(&record_key(record))
    })
}

fn rrset_counts(records: &[ResourceRecord]) -> HashMap<RrsetKey<'_>, usize> {
    let mut counts = HashMap::new();
    for record in records {
        *counts.entry(rrset_key(record)).or_insert(0) += 1;
    }
    counts
}

fn small_rrsets_conflict(left: &[ResourceRecord], right: &[ResourceRecord]) -> bool {
    for (index, record) in left.iter().enumerate() {
        let key = rrset_key(record);
        // Compare each overlapping RRset once, including in the bounded path.
        if left[..index]
            .iter()
            .any(|previous| rrset_key(previous) == key)
        {
            continue;
        }
        let right_count = right
            .iter()
            .filter(|candidate| rrset_key(candidate) == key)
            .count();
        if right_count == 0 {
            continue;
        }
        let left_count = left
            .iter()
            .filter(|candidate| rrset_key(candidate) == key)
            .count();
        if left_count != right_count
            || left
                .iter()
                .filter(|candidate| rrset_key(candidate) == key)
                .any(|member| !right.iter().any(|candidate| member.eq_dns(candidate)))
        {
            return true;
        }
    }
    false
}
