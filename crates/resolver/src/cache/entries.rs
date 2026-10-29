//! DNS-policy entry projections; custom engines never instantiate native indexes.
use crate::cache::store::{CacheEntry, CacheStore};
use std::{
    hash::{BuildHasher, Hash, RandomState},
    ops::{Deref, DerefMut},
    time::Instant,
};
pub(crate) struct EntryData<E> {
    pub(crate) values: Vec<E>,
}
pub(crate) enum CacheEntries<E> {
    Native(CacheStore<E>),
    View {
        data: EntryData<E>,
        hasher: RandomState,
        accesses: Vec<crate::CacheEntryKey>,
        removals: Vec<crate::CacheEntryKey>,
    },
}
impl<E> Deref for CacheEntries<E> {
    type Target = EntryData<E>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Native(x) => x.data(),
            Self::View { data, .. } => data,
        }
    }
}
impl<E> DerefMut for CacheEntries<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Native(x) => x.data_mut(),
            Self::View { data, .. } => data,
        }
    }
}
impl<E: CacheEntry> CacheEntries<E> {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self::Native(CacheStore::with_capacity(capacity))
    }
    pub(crate) fn view() -> Self {
        Self::View {
            data: EntryData { values: Vec::new() },
            hasher: RandomState::new(),
            accesses: Vec::new(),
            removals: Vec::new(),
        }
    }
    pub(crate) fn restore_values(&mut self, values: Vec<E>) {
        match self {
            Self::Native(x) => x.restore_values(values),
            Self::View { data, .. } => data.values = values,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }
    pub(crate) fn hash_key(&self, key: &impl Hash) -> u64 {
        match self {
            Self::Native(x) => x.hash_key(key),
            Self::View { hasher, .. } => hasher.hash_one(key),
        }
    }
    pub(crate) fn find(&self, hash: u64, matches: impl Fn(&E) -> bool) -> Option<usize> {
        match self {
            Self::Native(x) => x.find(hash, matches),
            Self::View { data, .. } => data
                .values
                .iter()
                .position(|x| x.hash() == hash && matches(x)),
        }
    }
    pub(crate) fn owner_indices(&self, owner: &[u8], now: Instant) -> Vec<usize> {
        match self {
            Self::Native(x) => x.owner_indices(owner, now),
            Self::View { data, .. } => data
                .values
                .iter()
                .enumerate()
                .filter(|(_, x)| x.owner() == owner && x.expires_at() > now)
                .map(|(i, _)| i)
                .collect(),
        }
    }
    /// Keep native indexed slices borrowed through selection. The owned view
    /// scratch vector never enters the native caller's return representation.
    #[inline]
    pub(crate) fn with_owner_bucket<R>(
        &self,
        owner: &[u8],
        select: impl FnOnce(&[usize]) -> R,
    ) -> Option<R> {
        match self {
            Self::Native(store) => store.owner_bucket(owner).map(select),
            Self::View { .. } => self.select_view_owner(owner, select),
        }
    }
    #[cold]
    #[inline(never)]
    fn select_view_owner<R>(&self, owner: &[u8], select: impl FnOnce(&[usize]) -> R) -> Option<R> {
        let Self::View { data, .. } = self else {
            unreachable!("view selector only follows view branch")
        };
        let indices: Vec<_> = data
            .values
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.owner() == owner)
            .map(|(i, _)| i)
            .collect();
        (!indices.is_empty()).then(|| select(&indices))
    }
    pub(crate) fn touch(&mut self, index: usize) {
        match self {
            Self::Native(x) => x.touch(index),
            Self::View { data, accesses, .. } => {
                if let Some(k) = data.values[index].engine_key()
                    && !accesses.contains(&k)
                {
                    accesses.push(k)
                }
            }
        }
    }
    pub(crate) fn note_access(&mut self, index: usize) {
        if matches!(self, Self::View { .. }) {
            self.touch(index);
        }
    }
    pub(crate) fn removals(&self) -> &[crate::CacheEntryKey] {
        match self {
            Self::Native(_) => &[],
            Self::View { removals, .. } => removals,
        }
    }
    pub(crate) fn accesses(&self) -> &[crate::CacheEntryKey] {
        match self {
            Self::Native(_) => &[],
            Self::View { accesses, .. } => accesses,
        }
    }
    pub(crate) fn modify(&mut self, index: usize, change: impl FnOnce(&mut E)) {
        match self {
            Self::Native(x) => x.modify(index, change),
            Self::View { data, .. } => change(&mut data.values[index]),
        }
    }
    pub(crate) fn insert(&mut self, entry: E, capacity: usize, now: Instant) {
        match self {
            Self::Native(x) => x.insert(entry, capacity, now),
            Self::View { data, .. } => data.values.push(entry),
        }
    }
    pub(crate) fn remove_expired(&mut self, now: Instant) {
        if let Self::Native(x) = self {
            x.remove_expired(now)
        }
    }
    pub(crate) fn remove_earliest(&mut self) {
        if let Self::Native(x) = self {
            x.remove_earliest()
        }
    }
    pub(crate) fn remove_indices(&mut self, mut indices: Vec<usize>) {
        if let Self::Native(store) = self {
            store.remove_indices(indices);
            return;
        }
        indices.sort_unstable();
        indices.dedup();
        for i in indices.into_iter().rev() {
            self.remove(i)
        }
    }
    pub(crate) fn is_view(&self) -> bool {
        matches!(self, Self::View { .. })
    }
    /// Same authenticated data renewed under its original still-live context:
    /// extraction is not a mandatory DNS invalidation if admission is declined.
    pub(crate) fn remove_renewal(&mut self, index: usize) {
        match self {
            Self::Native(store) => store.remove(index),
            Self::View { data, .. } => {
                data.values.swap_remove(index);
            }
        }
    }
    pub(crate) fn remove(&mut self, index: usize) {
        match self {
            Self::Native(x) => x.remove(index),
            Self::View { data, removals, .. } => {
                if let Some(key) = data.values[index].engine_key()
                    && !removals.contains(&key)
                {
                    removals.push(key);
                }
                data.values.swap_remove(index);
            }
        }
    }
}
