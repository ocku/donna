//! A caller-owned indexed algorithm using only Donna's exported engine contract.
use super::resolver_api::{
    CacheCategory, CacheEngine, CacheEntryFamily, CacheEntryKey, CacheMutation, CacheMutationBatch,
    CacheRead, CacheReadPlan, CacheReadResult, CacheReadSet, SealedCacheEntry,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

type Families = HashMap<CacheEntryFamily, BTreeMap<Vec<u8>, SealedCacheEntry>>;
#[derive(Default)]
struct Namespace {
    revision: u64,
    families: Families,
}

#[derive(Default)]
pub struct Provider {
    values: Mutex<HashMap<Vec<u8>, Namespace>>,
    pub no_store: AtomicBool,
    pub corrupt: AtomicBool,
    pub read_delay_ms: AtomicUsize,
    pub apply_delay_ms: AtomicUsize,
    pub evict_on_access: AtomicBool,
    pub conflicts: AtomicUsize,
    pub puts: Mutex<HashMap<CacheCategory, usize>>,
    pub accesses: Mutex<HashMap<CacheEntryKey, usize>>,
    pub read_keys: Mutex<Vec<Vec<CacheEntryKey>>>,
    pub applies: AtomicUsize,
}

impl Provider {
    pub fn clear(&self) {
        for state in self.values.lock().unwrap().values_mut() {
            state.families.clear();
            state.revision = state.revision.checked_add(1).unwrap();
        }
    }
    pub fn entries(&self) -> Vec<SealedCacheEntry> {
        self.values
            .lock()
            .unwrap()
            .values()
            .flat_map(|s| s.families.values())
            .flat_map(|f| f.values().cloned())
            .collect()
    }
    pub fn replace_entry(&self, entry: SealedCacheEntry) {
        let mut values = self.values.lock().unwrap();
        assert_eq!(values.len(), 1);
        let state = values.values_mut().next().unwrap();
        state
            .families
            .entry(entry.key.family.clone())
            .or_default()
            .insert(entry.key.discriminator.clone(), entry);
        state.revision = state.revision.checked_add(1).unwrap();
    }
    pub fn namespace_count(&self) -> usize {
        self.values.lock().unwrap().len()
    }
    pub fn put_count(&self, category: CacheCategory) -> usize {
        self.puts
            .lock()
            .unwrap()
            .get(&category)
            .copied()
            .unwrap_or(0)
    }
}

fn families(read: &CacheRead) -> Vec<CacheEntryFamily> {
    match read {
        CacheRead::Exact(key) => vec![key.family.clone()],
        CacheRead::OwnerFamily(family) => vec![family.clone()],
        CacheRead::DenialCandidates(_) => vec![],
        CacheRead::Ancestors(family) => {
            let mut result = vec![];
            let mut owner = family.owner.as_slice();
            loop {
                result.push(CacheEntryFamily {
                    owner: owner.to_vec(),
                    ..family.clone()
                });
                let Some(&length) = owner.first() else { break };
                if length == 0 {
                    break;
                }
                owner = &owner[usize::from(length) + 1..];
            }
            result
        }
    }
}

impl CacheEngine for Provider {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: Option<&'a [u8]>,
        plan: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            let delay = self.read_delay_ms.swap(0, Ordering::SeqCst);
            if delay != 0 {
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            }
            let result = {
                let mut values = self.values.lock().unwrap();
                let state = values.entry(namespace.to_vec()).or_default();
                let revision = state.revision.to_be_bytes();
                if expected.is_some_and(|old| old != revision) {
                    return Ok(CacheReadResult::Conflict);
                }
                let mut entries = vec![];
                let mut seen = HashSet::new();
                let mut bytes = 0usize;
                for read in &plan.reads {
                    for family in families(read) {
                        let Some(bucket) = state.families.get(&family) else {
                            continue;
                        };
                        for entry in bucket.values() {
                            if let CacheRead::Exact(key) = read
                                && entry.key != *key
                            {
                                continue;
                            }
                            if !seen.insert(entry.key.clone()) {
                                continue;
                            }
                            bytes = bytes
                                .checked_add(entry.key.encode()?.len() + entry.value.len() + 24)
                                .ok_or_else(|| io::Error::other("provider size overflow"))?;
                            if entries.len() == plan.maximum_entries || bytes > plan.maximum_bytes {
                                return Err(io::Error::other("complete read exceeds bound"));
                            }
                            let mut entry = entry.clone();
                            if self.corrupt.load(Ordering::Relaxed)
                                && let Some(byte) = entry.value.first_mut()
                            {
                                *byte ^= 1;
                            }
                            entries.push(entry);
                        }
                    }
                }
                self.read_keys
                    .lock()
                    .unwrap()
                    .push(entries.iter().map(|e| e.key.clone()).collect());
                CacheReadResult::Read(CacheReadSet {
                    revision: revision.to_vec(),
                    entries,
                })
            };
            Ok(result)
        })
    }
    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        batch: &'a CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let delay = self.apply_delay_ms.swap(0, Ordering::SeqCst);
            if delay != 0 {
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            }
            if self
                .conflicts
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Ok(None);
            }
            let mut values = self.values.lock().unwrap();
            let state = values.entry(namespace.to_vec()).or_default();
            if expected != state.revision.to_be_bytes() {
                return Ok(None);
            }
            self.applies.fetch_add(1, Ordering::Relaxed);
            for mutation in &batch.mutations {
                match mutation {
                    CacheMutation::Remove(key) => {
                        if let Some(bucket) = state.families.get_mut(&key.family) {
                            bucket.remove(&key.discriminator);
                        }
                    }
                    CacheMutation::Put(entry) => {
                        *self
                            .puts
                            .lock()
                            .unwrap()
                            .entry(entry.key.family.category)
                            .or_default() += 1;
                        if !self.no_store.load(Ordering::Relaxed) {
                            state
                                .families
                                .entry(entry.key.family.clone())
                                .or_default()
                                .insert(entry.key.discriminator.clone(), entry.clone());
                        }
                    }
                    CacheMutation::Access(key) => {
                        if self.evict_on_access.load(Ordering::Relaxed)
                            && let Some(bucket) = state.families.get_mut(&key.family)
                        {
                            bucket.remove(&key.discriminator);
                        }
                        *self
                            .accesses
                            .lock()
                            .unwrap()
                            .entry(key.clone())
                            .or_default() += 1;
                    }
                }
            }
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| io::Error::other("revision exhausted"))?;
            Ok(Some(state.revision.to_be_bytes().to_vec()))
        })
    }
}
