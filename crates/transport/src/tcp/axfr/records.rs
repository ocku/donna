//! AXFR RRSet identity, duplicate suppression, and TTL normalization.
//!
//! RFC 2181 §5 defines an RRSet by owner, type, and class, with RRSIG sets
//! additionally separated by their covered type. Section 5.2 requires a
//! receiver that encounters unequal TTLs in one RRSet to use the lowest TTL
//! for every member.

use std::collections::HashMap;

use super::same_rr_ignoring_ttl;

/// RRSIG's assigned RR TYPE value (RFC 4034 §3).
const RRSIG_TYPE: u16 = 46;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(in crate::tcp) struct RrsetKey {
    name: Vec<Vec<u8>>,
    rtype: dns::RecordType,
    class: dns::ClassType,
    rrsig: RrsigRrset,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum RrsigRrset {
    NotRrsig,
    TypeCovered([u8; 2]),
    Malformed,
}

impl From<&dns::ResourceRecord> for RrsetKey {
    fn from(record: &dns::ResourceRecord) -> Self {
        let name = record
            .name
            .as_ref()
            .iter()
            .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
            .collect();
        let rrsig = match (u16::from(record.rtype), &record.rdata) {
            (RRSIG_TYPE, dns::RData::RRSIG(rrsig)) => {
                RrsigRrset::TypeCovered(rrsig.type_covered.to_be_bytes())
            }
            (RRSIG_TYPE, dns::RData::Unknown(data)) => match data.as_slice() {
                [first, second, ..] => RrsigRrset::TypeCovered([*first, *second]),
                _ => RrsigRrset::Malformed,
            },
            (RRSIG_TYPE, _) => RrsigRrset::Malformed,
            _ => RrsigRrset::NotRrsig,
        };
        Self {
            name,
            rtype: record.rtype,
            class: record.class,
            rrsig,
        }
    }
}

#[derive(Debug)]
pub(super) struct TransferRrset {
    ttl: u32,
    record_indices: Vec<usize>,
}

pub(super) fn add_transfer_record(
    records: &mut Vec<dns::ResourceRecord>,
    rrsets: &mut HashMap<RrsetKey, TransferRrset>,
    mut record: dns::ResourceRecord,
    retain_duplicate: bool,
) {
    let key = RrsetKey::from(&record);
    if let Some(rrset) = rrsets.get_mut(&key) {
        // RFC 2181 §5.2: normalize every record already emitted from this set,
        // as well as this new record, to the lowest TTL seen in the transfer.
        let ttl = rrset.ttl.min(record.ttl);
        if ttl != rrset.ttl {
            for &index in &rrset.record_indices {
                records[index].ttl = ttl;
            }
            rrset.ttl = ttl;
        }
        record.ttl = ttl;
        // DNS names compare case-insensitively. `same_rr_ignoring_ttl` applies
        // that semantic comparison and deliberately ignores the TTL already
        // normalized above.
        if !retain_duplicate
            && rrset
                .record_indices
                .iter()
                .any(|&index| same_rr_ignoring_ttl(&records[index], &record))
        {
            return;
        }
        rrset.record_indices.push(records.len());
    } else {
        rrsets.insert(
            key,
            TransferRrset {
                ttl: record.ttl,
                record_indices: vec![records.len()],
            },
        );
    }
    records.push(record);
}
