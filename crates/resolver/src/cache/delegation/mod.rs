use std::{
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use dns::{
    ClassType, DomainName, QClassType, QueryType, Question, RData, RecordType, ResourceRecord,
};

use crate::{
    cache::entries::CacheEntries,
    cache::store::CacheEntry,
    name::{PackedName, packed_key_from_labels},
    protocol::Referral,
};
mod codec;
mod refresh;
use refresh::RefreshLease;

/// A bounded cache of usable name server addresses learned from delegations.
pub(crate) struct DelegationCache {
    capacity: usize,
    entries: Mutex<CacheEntries<Entry>>,
}

pub(crate) struct CachedDelegation {
    pub(crate) zone: DomainName,
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) name_servers: Vec<DomainName>,
}

struct Entry {
    key: DelegationKey,
    hash: u64,
    zone: DomainName,
    candidates: Vec<(SocketAddr, Instant)>,
    name_servers: Vec<DomainName>,
    expires_at: Instant,
    hits: u32,
    refresh: [Option<RefreshLease>; 2],
}

#[derive(Clone, Eq, PartialEq)]
struct DelegationKey {
    zone: Box<[u8]>,
    class: ClassType,
}

impl Hash for DelegationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.zone.as_ref(), self.class).hash(state);
    }
}

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::Delegation,
                owner: self.key.zone.to_vec(),
                class: self.key.class.value(),
            },
            discriminator: Vec::new(),
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.key.zone
    }
    fn expires_at(&self) -> Instant {
        self.refresh
            .iter()
            .flatten()
            .fold(self.expires_at, |expiry, lease| {
                expiry.max(if lease.failed {
                    lease.expires_at
                } else {
                    lease.expires_at + Duration::from_secs(300)
                })
            })
    }
    fn hits(&self) -> u32 {
        self.hits
    }
    fn set_hits(&mut self, hits: u32) {
        self.hits = hits;
    }
}

impl DelegationCache {
    /// Creates a cache holding at most `capacity` delegated zones.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(CacheEntries::with_capacity(capacity)),
        }
    }

    /// Returns the closest fresh cached delegation applicable to `question`.
    pub(crate) fn get(&self, question: &Question) -> Option<CachedDelegation> {
        self.with_closest(question, |entry, _| CachedDelegation {
            zone: entry.zone.clone(),
            candidates: entry
                .candidates
                .iter()
                .map(|(address, _)| *address)
                .collect(),
            name_servers: entry.name_servers.clone(),
        })
    }

    /// Adds the same delegation metadata without allocating address and
    /// name-server vectors that a cached negative answer would discard.
    pub(crate) fn append_referral_records(
        &self,
        question: &Question,
        records: &mut impl Extend<ResourceRecord>,
    ) {
        let QClassType::Class(class) = question.qclass else {
            return;
        };
        let _ = self.with_closest(question, |entry, now| {
            let ttl = remaining_ttl(entry, now);
            records.extend(entry.name_servers.iter().map(|name_server| ResourceRecord {
                name: entry.zone.clone(),
                rtype: RecordType::NS,
                class,
                ttl,
                rdata: RData::NS(name_server.clone()),
            }));
        });
    }

    fn with_closest<R>(
        &self,
        question: &Question,
        project: impl FnOnce(&Entry, Instant) -> R,
    ) -> Option<R> {
        let mut project = Some(project);
        self.with_closest_state(question, |entry, now| {
            (entry.expires_at > now).then(|| project.take().expect("selected once")(entry, now))
        })
    }

    fn with_closest_state<R>(
        &self,
        question: &Question,
        mut project: impl FnMut(&Entry, Instant) -> Option<R>,
    ) -> Option<R> {
        let QClassType::Class(class) = question.qclass else {
            return None;
        };
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Delegations apply to a zone and every descendant. Probe qname, then
        // its parent zones, so lookup is O(number of labels), not O(cache size).
        let labels = question.qname.as_ref();
        // DS belongs to the parent side of a cut (RFC 4035 section 2.4).
        // Child-apex NODATA cannot establish the absence of the parent's DS.
        // Root has no parent, so its DS query still starts at root hints.
        let first_suffix = usize::from(question.qtype == QueryType::DS && !labels.is_empty());
        let packed = PackedName::new(&question.qname);
        let mut suffix_offset = if first_suffix == 0 {
            0
        } else {
            labels[0].len() + 1
        };
        for suffix_start in first_suffix..=labels.len() {
            let key = (&packed.as_ref()[suffix_offset..], class);
            if suffix_start < labels.len() {
                suffix_offset += labels[suffix_start].len() + 1;
            }
            let hash = entries.hash_key(&key);
            let Some(index) = entries.find(hash, |entry| {
                entry.key.zone.as_ref() == key.0 && entry.key.class == key.1
            }) else {
                continue;
            };
            if entries.values[index].expires_at() <= now {
                entries.remove(index);
                continue;
            }
            entries.touch(index);
            {
                let entry = &mut entries.values[index];
                entry.candidates.retain(|(_, expires_at)| *expires_at > now);
                if let Some(value) = project(entry, now) {
                    return Some(value);
                }
            }
        }
        None
    }

    /// Stores a parsed delegation, limiting its lifetime to `max_ttl`.
    #[cfg(test)]
    pub(crate) fn insert(&self, referral: &Referral, max_ttl: Duration) {
        self.insert_at(referral, max_ttl, Instant::now());
    }

    /// Preserve receipt time across backend checkout, commit and retries.
    pub(crate) fn insert_at(&self, referral: &Referral, max_ttl: Duration, observed_at: Instant) {
        let lifetime = referral.ttl.min(max_ttl);
        // A referral whose only immediately usable addresses are provisional
        // (for example root sibling glue) is useful for this lookup, but an
        // addressless cached copy would make the next lookup spend its budget
        // resolving NS hosts instead of reacquiring the referral-scoped hints.
        // Keep provisional addresses out of the cache by rejecting that state
        // as a whole. Truly glueless referrals remain cacheable.
        let provisional_only =
            !referral.candidates.is_empty() && referral.candidate_ttls.is_empty();
        if self.capacity == 0
            || referral.name_servers.is_empty()
            || lifetime.is_zero()
            || provisional_only
        {
            return;
        }
        let now = Instant::now();
        let Some(expires_at) = observed_at
            .checked_add(lifetime)
            .filter(|expiry| *expiry > now)
        else {
            return;
        };
        let candidates = referral
            .candidate_ttls
            .iter()
            .filter_map(|(address, ttl)| {
                let lifetime = (*ttl).min(max_ttl);
                (!lifetime.is_zero())
                    .then(|| {
                        observed_at
                            .checked_add(lifetime)
                            .filter(|expiry| *expiry > now)
                            .map(|expires_at| (*address, expires_at))
                    })
                    .flatten()
            })
            .collect();
        let key = DelegationKey::new(&referral.zone, referral.class);

        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(now);
        let hash = entries.hash_key(&key);
        let refresh = if let Some(index) = entries.find(hash, |entry| entry.key == key) {
            let refresh = entries.values[index].refresh;
            entries.remove(index);
            refresh
        } else {
            [None; 2]
        };
        entries.insert(
            Entry {
                key,
                hash,
                zone: referral.zone.clone(),
                candidates,
                name_servers: referral.name_servers.clone(),
                expires_at,
                hits: 0,
                refresh,
            },
            self.capacity,
            now,
        );
    }
}

fn remaining_ttl(entry: &Entry, now: Instant) -> u32 {
    entry
        .expires_at
        .saturating_duration_since(now)
        .as_secs()
        .min(u64::from(u32::MAX)) as u32
}

impl DelegationKey {
    fn new(zone: &DomainName, class: ClassType) -> Self {
        Self::from_labels(zone.as_ref(), class)
    }

    fn from_labels(labels: &[Vec<u8>], class: ClassType) -> Self {
        Self {
            zone: packed_key_from_labels(labels),
            class,
        }
    }
}

#[cfg(test)]
mod tests;
