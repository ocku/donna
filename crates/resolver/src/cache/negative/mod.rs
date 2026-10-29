#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

#[cfg(test)]
use dns::{ClassType, DomainName, Headers};
use dns::{Message, QClassType, Question, RCode, RData, ResourceRecord};

use crate::{
    cache::entries::CacheEntries,
    cache::store::CacheEntry,
    name::{PackedName, packed_key},
    response::has_requested_answer,
};

use key::{NegativeKey, NegativeKeyRef};

mod entry;
mod evidence;
mod key;
mod rendering;
pub(crate) use rendering::keep_authority;
mod selection;
pub(crate) use selection::{DenialKeys, SelectedNegative};
mod codec;

/// A bounded RFC 2308 cache for NXDOMAIN and NODATA responses.
pub(crate) struct NegativeCache {
    capacity: usize,
    entries: Mutex<CacheEntries<Entry>>,
}

pub(crate) enum CachedNegativeUdp {
    Message(Message),
    Encoded {
        reply: dns::wire::EncodedReply,
        implicit_referral: bool,
    },
}

struct Entry {
    key: NegativeKey,
    hash: u64,
    authorities: Arc<NegativeRecords>,
    rcode: RCode,
    authoritative: bool,
    authenticated: bool,
    expires_at: Instant,
    hits: u32,
    prepared: [OnceLock<Option<Box<PreparedNegative>>>; 2],
}

struct PreparedNegative {
    reply: dns::wire::PreparedNegativeReply,
    // Filtered wire order mapped back to immutable admitted record deadlines.
    indices: Box<[usize]>,
}

struct NegativeRecords {
    records: Vec<CachedAuthority>,
    denial_keys: Mutex<Option<DenialKeys>>,
    composed: OnceLock<Mutex<[Option<Box<ComposedNegative>>; 2]>>,
}

impl std::ops::Deref for NegativeRecords {
    type Target = [CachedAuthority];
    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

pub(crate) struct ComposedNegative {
    pub(crate) aliases: Vec<crate::cache::positive::SelectionIdentity>,
    pub(crate) nameservers: Box<[ResourceRecord]>,
    pub(crate) reply: dns::wire::PreparedNegativeReply,
}

struct CachedAuthority {
    record: ResourceRecord,
    expires_at: Instant,
}

impl NegativeCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(CacheEntries::with_capacity(capacity)),
        }
    }

    pub(crate) fn get(&self, question: &Question) -> Option<Message> {
        self.with_entry(question, |entry, now| {
            Self::materialize(entry, question, now)
        })
    }

    fn with_entry<R>(
        &self,
        question: &Question,
        render: impl FnOnce(&Entry, Instant) -> R,
    ) -> Option<R> {
        let QClassType::Class(class) = question.qclass else {
            return None;
        };
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let packed = PackedName::new(&question.qname);
        let name_key = NegativeKeyRef::Name {
            qname: packed.as_ref(),
            class,
        };
        let type_key = NegativeKeyRef::Type {
            qname: packed.as_ref(),
            qtype: question.qtype.into(),
            class,
        };
        loop {
            // One selector policy for native borrowed indexes and cold view
            // scratch. Name-error precedence and large-bucket hashes are shared.
            let found = entries.with_owner_bucket(packed.as_ref(), |bucket| {
                if bucket.len() <= 8 {
                    bucket
                        .iter()
                        .copied()
                        .find(|&index| entries.values[index].key.as_ref() == name_key)
                        .or_else(|| {
                            bucket
                                .iter()
                                .copied()
                                .find(|&index| entries.values[index].key.as_ref() == type_key)
                        })
                } else {
                    entries
                        .find(entries.hash_key(&name_key), |entry| {
                            entry.key.as_ref() == name_key
                        })
                        .or_else(|| {
                            entries.find(entries.hash_key(&type_key), |entry| {
                                entry.key.as_ref() == type_key
                            })
                        })
                }
            })?;
            let index = found?;
            if entries.values[index].expires_at <= now {
                entries.remove(index);
                continue;
            }
            entries.touch(index);
            let entry = &entries.values[index];
            return Some(render(entry, now));
        }
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &self,
        question: &Question,
        reply: &Message,
        authoritative: bool,
        max_ttl: Duration,
    ) -> bool {
        self.insert_at(
            question,
            reply,
            authoritative,
            max_ttl,
            Instant::now(),
            None,
        )
    }

    pub(crate) fn insert_at(
        &self,
        question: &Question,
        reply: &Message,
        authoritative: bool,
        max_ttl: Duration,
        observed_at: Instant,
        not_after: Option<Instant>,
    ) -> bool {
        // A truncated negative response can be missing its SOA or denial
        // proofs. It is not a complete negative answer and must never create
        // state that can outlive this transaction.
        if reply.headers.tc || !reply.headers.aa || !authoritative {
            return false;
        }
        let QClassType::Class(class) = question.qclass else {
            return false;
        };
        let key = match reply.headers.rcode {
            RCode::NameError => NegativeKey::name(&question.qname, class),
            RCode::Ok if !has_requested_answer(&reply.answers, question) => {
                NegativeKey::qtype(&question.qname, question.qtype.into(), class)
            }
            _ => return false,
        };
        let Some((mut soa, minimum)) = evidence::negative_soa(reply, question, class) else {
            return false;
        };

        // RFC 2181 §8: a received RR TTL with its high bit set is zero.
        soa.ttl = evidence::received_ttl(soa.ttl);
        let mut lifetime = Duration::from_secs(u64::from(soa.ttl.min(minimum))).min(max_ttl);
        if self.capacity == 0 || lifetime.is_zero() {
            return false;
        }
        let now = Instant::now();
        let Some(mut expires_at) = observed_at.checked_add(lifetime) else {
            return false;
        };
        if let Some(not_after) = not_after {
            expires_at = expires_at.min(not_after);
        }
        if expires_at <= now {
            return false;
        }

        let (proof_records, signature_records) = evidence::denial_records(reply, class, &soa);
        // An authenticated hit must retain every denial RRset and signature
        // for its whole lifetime. Otherwise AD could survive a missing proof.
        if reply.headers.ad {
            for record in proof_records.iter().chain(&signature_records) {
                let ttl = evidence::received_ttl(record.ttl);
                lifetime = lifetime.min(Duration::from_secs(u64::from(ttl)));
            }
            if lifetime.is_zero() {
                return false;
            }
            expires_at = observed_at.checked_add(lifetime).unwrap_or(observed_at);
            if let Some(not_after) = not_after {
                expires_at = expires_at.min(not_after);
            }
            if expires_at <= now {
                return false;
            }
        }
        let referral_records = evidence::referral_records(reply, question, class, &soa);
        let authorities = evidence::cache_authorities(
            soa,
            proof_records,
            signature_records,
            referral_records,
            evidence::AuthorityLifetime {
                observed_at,
                max_ttl,
                lifetime,
                expires_at,
                now,
            },
        );

        self.retain_negative(key, authorities, reply, authoritative, expires_at)
    }

    fn retain_negative(
        &self,
        key: NegativeKey,
        authorities: Vec<CachedAuthority>,
        reply: &Message,
        authoritative: bool,
        expires_at: Instant,
    ) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let now = Instant::now();
        // Lock contention must not admit an expired negative or evict a live
        // contradictory answer after the packet's lifetime has elapsed.
        if expires_at <= now {
            return false;
        }
        entries.remove_expired(now);
        let candidates = entries.owner_indices(key.owner(), now);
        let mut remove: Vec<_> = candidates
            .into_iter()
            .filter(|&index| {
                key == entries.values[index].key || key.contradicts(&entries.values[index].key)
            })
            .collect();
        let hash = entries.hash_key(&key);
        if let Some(index) = entries.find(hash, |entry| entry.key == key) {
            remove.push(index);
        }
        entries.remove_indices(remove);
        entries.insert(
            Entry {
                key,
                hash,
                authorities: Arc::new(NegativeRecords {
                    records: authorities,
                    composed: OnceLock::new(),
                    denial_keys: Mutex::new(None),
                }),
                rcode: reply.headers.rcode,
                authoritative,
                authenticated: reply.headers.ad,
                expires_at,
                hits: 0,
                prepared: [OnceLock::new(), OnceLock::new()],
            },
            self.capacity,
            now,
        );
        true
    }

    pub(crate) fn has_authoritative_positive_conflict(
        &self,
        question: &Question,
        answers: &[ResourceRecord],
        cname: bool,
    ) -> bool {
        let QClassType::Class(class) = question.qclass else {
            return false;
        };
        let qname = packed_key(&question.qname);
        let positive_types = positive_types(question, answers, class);
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(now);
        entries.owner_indices(&qname, now).into_iter().any(|index| {
            let entry = &entries.values[index];
            entry.authoritative
                && entry
                    .key
                    .conflicts_positive(&qname, &positive_types, class, cname)
        })
    }

    pub(crate) fn remove_positive_conflicts(
        &self,
        question: &Question,
        answers: &[ResourceRecord],
        cname: bool,
    ) {
        let QClassType::Class(class) = question.qclass else {
            return;
        };
        let qname = packed_key(&question.qname);
        let positive_types = positive_types(question, answers, class);
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(now);
        let remove = entries
            .owner_indices(&qname, now)
            .into_iter()
            .filter(|&index| {
                entries.values[index]
                    .key
                    .conflicts_positive(&qname, &positive_types, class, cname)
            })
            .collect();
        entries.remove_indices(remove);
    }
}

fn positive_types(
    question: &Question,
    answers: &[ResourceRecord],
    class: dns::ClassType,
) -> Vec<u16> {
    answers
        .iter()
        .filter(|record| record.class == class && record.name.eq_dns(&question.qname))
        .map(|record| record.rtype.into())
        .collect()
}

#[cfg(test)]
mod tests;
