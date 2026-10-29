use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

use dns::{DomainName, Question};

use crate::{cache::entries::CacheEntries, cache::store::CacheEntry, name::packed_key};

use super::{
    policy::PackedResponse,
    query_types_overlap,
    rrset_comparison::{rrsets_conflict, rrsets_overlap},
};

pub(super) struct Entries {
    store: CacheEntries<Entry>,
}

// Keep callers' response projection separate from index maintenance.
impl std::ops::Deref for Entries {
    type Target = CacheEntries<Entry>;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}
impl std::ops::DerefMut for Entries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
}

pub(super) struct Entry {
    pub(super) hash: u64,
    pub(super) expires_at: Instant,
    pub(super) hits: u32,
    pub(super) authoritative: bool,
    pub(super) authenticated: bool,
    pub(super) owner_data: OwnerData,
    pub(super) key: CacheKey,
    pub(super) response: Arc<PackedResponse>,
    pub(super) prepared: [OnceLock<Option<Box<dns::wire::PreparedPositiveReply>>>; 2],
}

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::Positive,
                owner: self.key.qname.to_vec(),
                class: self.key.qclass,
            },
            discriminator: self.key.qtype.to_be_bytes().to_vec(),
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.key.qname
    }
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
    fn hits(&self) -> u32 {
        self.hits
    }
    fn set_hits(&mut self, hits: u32) {
        self.hits = hits;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum OwnerData {
    Cname,
    Ordinary,
    Companion,
}

#[derive(Eq, PartialEq)]
pub(super) struct CacheKey {
    pub(super) qname: Box<[u8]>,
    pub(super) qtype: u16,
    pub(super) qclass: u16,
}

impl Entries {
    pub(super) fn view() -> Self {
        Self {
            store: CacheEntries::view(),
        }
    }
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            store: CacheEntries::with_capacity(capacity),
        }
    }

    pub(super) fn find_question(&self, hash: u64, question: &Question) -> Option<usize> {
        self.store.find(hash, |entry| entry.key.matches(question))
    }

    pub(super) fn insert(&mut self, entry: Entry, capacity: usize) -> bool {
        let now = Instant::now();
        // Every admitted answer is projected to the question's owner. The
        // owner index groups all QTYPEs and classes. The full key and concrete
        // RRset comparisons below decide trust and class isolation.
        let candidates = self.store.owner_indices(&entry.key.qname, now);
        if !entry.authoritative
            && candidates.iter().any(|&index| {
                let cached = &self.store.values[index];
                cached.authoritative
                    && (cached.key == entry.key
                        || (cached.key.same_name_class(&entry.key)
                            && cached.owner_data.conflicts(entry.owner_data))
                        || rrsets_overlap(&cached.response.answers, &entry.response.answers))
            })
        {
            return false;
        }

        let mut remove: Vec<_> = candidates
            .into_iter()
            .filter(|&index| {
                let cached = &self.store.values[index];
                cached.key == entry.key
                    || (cached.key.same_name_class(&entry.key)
                        && cached.owner_data.conflicts(entry.owner_data))
                    || rrsets_conflict(&cached.response.answers, &entry.response.answers)
            })
            .collect();
        // Incremental cleanup may leave an expired exact key. Replace that
        // slot too, so hash lookup can never encounter two identical keys.
        if let Some(index) = self
            .store
            .find(entry.hash, |cached| cached.key == entry.key)
        {
            remove.push(index);
        }
        self.store.remove_indices(remove);
        self.store.insert(entry, capacity, now);
        true
    }

    pub(super) fn has_name(&self, key: &CacheKey) -> bool {
        self.store
            .owner_indices(&key.qname, Instant::now())
            .into_iter()
            .any(|index| self.store.values[index].key.same_name_class(key))
    }

    pub(super) fn has_nodata_conflict(&self, key: &CacheKey) -> bool {
        self.store
            .owner_indices(&key.qname, Instant::now())
            .into_iter()
            .any(|index| self.store.values[index].conflicts_nodata(key))
    }

    pub(super) fn remove_name(&mut self, key: &CacheKey) {
        self.remove_matching(key, |entry| entry.key.same_name_class(key));
    }

    pub(super) fn remove_nodata_conflicts(&mut self, key: &CacheKey) {
        self.remove_matching(key, |entry| entry.conflicts_nodata(key));
    }

    fn remove_matching(&mut self, key: &CacheKey, predicate: impl Fn(&Entry) -> bool) {
        let remove = self
            .store
            .owner_indices(&key.qname, Instant::now())
            .into_iter()
            .filter(|&index| predicate(&self.store.values[index]))
            .collect();
        self.store.remove_indices(remove);
    }
}

impl Entry {
    fn conflicts_nodata(&self, key: &CacheKey) -> bool {
        if !self.key.same_name_class(key) {
            return false;
        }
        if self.owner_data == OwnerData::Cname || self.key == *key {
            return true;
        }
        if !query_types_overlap(self.key.qtype, key.qtype) {
            return false;
        }
        if !matches!(self.key.qtype, 253..=255) {
            return true;
        }

        self.response
            .answers
            .iter()
            .any(|record| query_types_overlap(key.qtype, record.rtype.into()))
    }
}

impl OwnerData {
    fn conflicts(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Cname, Self::Ordinary) | (Self::Ordinary, Self::Cname)
        )
    }
}

impl CacheKey {
    pub(super) fn new(question: &Question) -> Self {
        Self {
            qname: packed_key(&question.qname),
            qtype: question.qtype.into(),
            qclass: question.qclass.value(),
        }
    }

    fn matches(&self, question: &Question) -> bool {
        self.qtype == u16::from(question.qtype)
            && self.qclass == question.qclass.value()
            && normalized_name_matches(&self.qname, &question.qname)
    }

    fn same_name_class(&self, other: &Self) -> bool {
        self.qclass == other.qclass && self.qname == other.qname
    }
}

fn normalized_name_matches(cached: &[u8], name: &DomainName) -> bool {
    let mut cursor = 0;
    for label in name.as_ref() {
        if cached.get(cursor).copied() != Some(label.len() as u8) {
            return false;
        }
        cursor += 1;
        let Some(cached_label) = cached.get(cursor..cursor + label.len()) else {
            return false;
        };
        if !cached_label
            .iter()
            .zip(label)
            .all(|(cached, input)| *cached == input.to_ascii_lowercase())
        {
            return false;
        }
        cursor += label.len();
    }
    cached.get(cursor) == Some(&0) && cursor + 1 == cached.len()
}
