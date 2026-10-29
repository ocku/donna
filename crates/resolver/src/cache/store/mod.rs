//! Bounded cache indexes. DNS admission and trust policy stay with each cache.
mod popularity;
use popularity::Popularity;
use std::{
    collections::{BTreeSet, HashMap},
    hash::{BuildHasher, Hash, RandomState},
    time::Instant,
};

// Composition setup costs tens of microseconds. This hint gates the new
// negative compositions using existing ranks, without adding cache touches.
pub(crate) const NEGATIVE_COMPOSITION_MIN_HITS: u32 = 32;

pub(crate) trait CacheEntry {
    fn hash(&self) -> u64;
    fn owner(&self) -> &[u8];
    fn expires_at(&self) -> Instant;
    fn hits(&self) -> u32;
    fn set_hits(&mut self, hits: u32);
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        None
    }
}

pub(crate) struct CacheStore<E> {
    data: crate::cache::entries::EntryData<E>,
    key_hasher: RandomState,
    by_hash: HashMap<u64, Vec<usize>>,
    by_owner: HashMap<Box<[u8]>, Vec<usize>>,
    expiration: BTreeSet<(Instant, usize)>,
    popularity: Popularity,
}

impl<E> CacheStore<E> {
    pub(crate) fn data(&self) -> &crate::cache::entries::EntryData<E> {
        &self.data
    }
    pub(crate) fn data_mut(&mut self) -> &mut crate::cache::entries::EntryData<E> {
        &mut self.data
    }
}
impl<E> std::ops::Deref for CacheStore<E> {
    type Target = crate::cache::entries::EntryData<E>;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
impl<E> std::ops::DerefMut for CacheStore<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<E: CacheEntry> CacheStore<E> {
    pub(crate) fn restore_values(&mut self, values: Vec<E>) {
        self.data.values = values;
        self.by_hash.clear();
        self.by_owner.clear();
        self.expiration.clear();
        self.popularity = Popularity::with_capacity(self.data.values.len());
        for index in 0..self.data.values.len() {
            self.index(index);
        }
    }
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            data: crate::cache::entries::EntryData {
                values: Vec::with_capacity(capacity),
            },
            key_hasher: RandomState::new(),
            by_hash: HashMap::with_capacity(capacity),
            by_owner: HashMap::with_capacity(capacity),
            expiration: BTreeSet::new(),
            popularity: Popularity::with_capacity(capacity),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.values.len()
    }

    pub(crate) fn hash_key(&self, key: &impl Hash) -> u64 {
        self.key_hasher.hash_one(key)
    }

    pub(crate) fn modify(&mut self, index: usize, change: impl FnOnce(&mut E)) {
        self.unindex(index);
        change(&mut self.data.values[index]);
        self.index(index);
    }

    pub(crate) fn find(&self, hash: u64, matches: impl Fn(&E) -> bool) -> Option<usize> {
        self.by_hash
            .get(&hash)?
            .iter()
            .copied()
            .find(|&index| matches(&self.data.values[index]))
    }

    pub(crate) fn owner_indices(&self, owner: &[u8], now: Instant) -> Vec<usize> {
        self.by_owner
            .get(owner)
            .into_iter()
            .flatten()
            .copied()
            .filter(|&index| self.data.values[index].expires_at() > now)
            .collect()
    }

    pub(crate) fn owner_bucket(&self, owner: &[u8]) -> Option<&[usize]> {
        self.by_owner.get(owner).map(Vec::as_slice)
    }

    pub(crate) fn touch(&mut self, index: usize) {
        let entry = &mut self.data.values[index];
        entry.set_hits(entry.hits().saturating_add(1));
        self.popularity.update(index, entry.hits());
    }

    pub(crate) fn insert(&mut self, entry: E, capacity: usize, now: Instant) {
        assert!(capacity > 0);
        self.remove_expired(now);
        if self.len() == capacity {
            let victim = if let Some(&(expiry, index)) = self.expiration.first()
                && expiry <= now
            {
                index
            } else {
                self.popularity.first().expect("full cache has an entry").1
            };
            self.remove(victim);
        }
        let index = self.len();
        self.data.values.push(entry);
        self.index(index);
    }

    pub(crate) fn remove_earliest(&mut self) {
        if let Some(&(_, index)) = self.expiration.first() {
            self.remove(index);
        }
    }

    /// Incremental cleanup bounds work after a long idle period. Every read and
    /// policy comparison also checks the entry's real deadline independently.
    pub(crate) fn remove_expired(&mut self, now: Instant) {
        for _ in 0..16 {
            let Some(&(expiry, index)) = self.expiration.first() else {
                break;
            };
            if expiry > now {
                break;
            }
            self.remove(index);
        }
    }

    pub(crate) fn remove_indices(&mut self, mut indices: Vec<usize>) {
        indices.sort_unstable();
        indices.dedup();
        for index in indices.into_iter().rev() {
            self.remove(index);
        }
    }

    pub(crate) fn remove(&mut self, index: usize) {
        self.unindex(index);
        let last = self.len() - 1;
        if index != last {
            self.unindex(last);
        }
        self.data.values.swap_remove(index);
        if index != last {
            self.index(index);
        }
    }

    fn index(&mut self, index: usize) {
        let entry = &self.data.values[index];
        self.by_hash.entry(entry.hash()).or_default().push(index);
        self.by_owner
            .entry(entry.owner().into())
            .or_default()
            .push(index);
        self.expiration.insert((entry.expires_at(), index));
        self.popularity.insert((entry.hits(), index));
    }

    fn unindex(&mut self, index: usize) {
        let entry = &self.data.values[index];
        let hash = entry.hash();
        let bucket = self.by_hash.get_mut(&hash).expect("indexed hash");
        bucket.retain(|&candidate| candidate != index);
        if bucket.is_empty() {
            self.by_hash.remove(&hash);
        }
        let bucket = self.by_owner.get_mut(entry.owner()).expect("indexed owner");
        bucket.retain(|&candidate| candidate != index);
        if bucket.is_empty() {
            self.by_owner.remove(entry.owner());
        }
        self.expiration.remove(&(entry.expires_at(), index));
        self.popularity.remove(&(entry.hits(), index));
    }
}

#[cfg(test)]
mod tests;
