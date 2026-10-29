//! Select and bound the authority evidence retained with a negative answer.
use super::*;
use dns::{ClassType, RecordType};

const LEGACY_NXT_TYPE: u16 = 30;

pub(super) struct AuthorityLifetime {
    pub(super) observed_at: Instant,
    pub(super) max_ttl: Duration,
    pub(super) lifetime: Duration,
    pub(super) expires_at: Instant,
    pub(super) now: Instant,
}

// RFC 2181 section 8 treats a received TTL with its high bit set as zero.
pub(super) fn received_ttl(ttl: u32) -> u32 {
    if ttl > i32::MAX as u32 { 0 } else { ttl }
}

fn is_denial_type(rtype: u16) -> bool {
    rtype == LEGACY_NXT_TYPE
        || rtype == u16::from(RecordType::NSEC)
        || rtype == u16::from(RecordType::NSEC3)
}

fn is_signature_type(rtype: u16) -> bool {
    rtype == u16::from(RecordType::SIG) || rtype == u16::from(RecordType::RRSIG)
}

pub(super) fn denial_records(
    reply: &Message,
    class: ClassType,
    soa: &ResourceRecord,
) -> (Vec<ResourceRecord>, Vec<ResourceRecord>) {
    let proof_records = reply
        .authorities
        .iter()
        .filter(|record| {
            record.class == class
                && is_denial_type(u16::from(record.rtype))
                && record.name.is_descendant_of(&soa.name)
        })
        .cloned()
        .collect::<Vec<_>>();
    let signature_records = reply
        .authorities
        .iter()
        .filter(|record| {
            if record.class != class || !is_signature_type(u16::from(record.rtype)) {
                return false;
            }
            let covered_type = match &record.rdata {
                RData::SIG(sig) => sig.type_covered,
                RData::RRSIG(rrsig) => rrsig.type_covered,
                RData::Unknown(rdata) => {
                    let Some(bytes) = rdata.get(..2) else {
                        return false;
                    };
                    u16::from_be_bytes([bytes[0], bytes[1]])
                }
                _ => return false,
            };
            (covered_type == u16::from(dns::RecordType::SOA) && record.name.eq_dns(&soa.name))
                || (is_denial_type(covered_type)
                    && proof_records.iter().any(|proof| {
                        u16::from(proof.rtype) == covered_type && proof.name.eq_dns(&record.name)
                    }))
        })
        .cloned()
        .collect::<Vec<_>>();
    (proof_records, signature_records)
}

pub(super) fn referral_records(
    reply: &Message,
    question: &Question,
    class: ClassType,
    soa: &ResourceRecord,
) -> Vec<ResourceRecord> {
    // RFC2308 implicit referrals remain available for non-AD negatives.
    // Optional NS has no authentication provenance in a secure negative.
    let referral_owner = (!reply.headers.ad)
        .then_some(reply)
        .into_iter()
        .flat_map(|reply| reply.authorities.iter())
        .filter(|record| {
            record.rtype == dns::RecordType::NS
                && record.class == class
                && question.qname.is_descendant_of(&record.name)
                && record.name.is_descendant_of(&soa.name)
        })
        .map(|record| &record.name)
        .max_by_key(|name| name.as_ref().len())
        .cloned();
    let mut referral_records = referral_owner.map_or_else(Vec::new, |owner| {
        reply
            .authorities
            .iter()
            .filter(|record| {
                record.rtype == dns::RecordType::NS
                    && record.class == class
                    && record.name.eq_dns(&owner)
            })
            .cloned()
            .collect::<Vec<_>>()
    });
    if let Some(ttl) = referral_records.iter().map(|record| record.ttl).min() {
        for record in &mut referral_records {
            record.ttl = ttl;
        }
    }
    referral_records
}

pub(super) fn cache_authorities(
    soa: ResourceRecord,
    proof_records: Vec<ResourceRecord>,
    signature_records: Vec<ResourceRecord>,
    referral_records: Vec<ResourceRecord>,
    lifetime_bounds: AuthorityLifetime,
) -> Vec<CachedAuthority> {
    let AuthorityLifetime {
        observed_at,
        max_ttl,
        lifetime,
        expires_at,
        now,
    } = lifetime_bounds;
    let mut authority_records = Vec::with_capacity(
        1 + proof_records.len() + signature_records.len() + referral_records.len(),
    );
    authority_records.push(soa);
    authority_records.extend(proof_records);
    authority_records.extend(signature_records);
    authority_records.extend(referral_records);
    authority_records
        .into_iter()
        .filter_map(|mut record| {
            record.ttl = received_ttl(record.ttl);
            let record_lifetime = Duration::from_secs(u64::from(record.ttl))
                .min(max_ttl)
                .min(lifetime);
            let record_expiry = observed_at
                .checked_add(record_lifetime)
                .unwrap_or(observed_at)
                .min(expires_at);
            (record_expiry > now).then_some(CachedAuthority {
                record,
                expires_at: record_expiry,
            })
        })
        .collect()
}

pub(super) fn negative_soa(
    reply: &Message,
    question: &Question,
    class: ClassType,
) -> Option<(ResourceRecord, u32)> {
    reply
        .authorities
        .iter()
        .filter_map(|record| {
            let RData::SOA { minimum, .. } = &record.rdata else {
                return None;
            };
            (record.class == class && question.qname.is_descendant_of(&record.name))
                .then(|| (record.clone(), *minimum))
        })
        // A malformed response can contain SOAs for several enclosing
        // zones. RFC 2308's negative TTL belongs to the zone containing
        // QNAME, so use the closest applicable authority rather than
        // depending on wire order.
        .max_by_key(|(record, _)| record.name.as_ref().len())
}
