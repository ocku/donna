//! A targeted entry store shared by resolver persistence and fault tests.
use crate::{
    CacheEngine, CacheEntryFamily, CacheEntryKey, CacheMutation, CacheMutationBatch, CacheRead,
    CacheReadPlan, CacheReadResult, CacheReadSet, SealedCacheEntry,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

type StoredEntries = HashMap<Vec<u8>, (u64, HashMap<CacheEntryKey, SealedCacheEntry>)>;

#[derive(Default)]
pub(in crate::resolver) struct Backend {
    pub(super) values: Mutex<StoredEntries>,
    pub(super) conflicts: AtomicUsize,
    pub(super) unavailable: AtomicBool,
}

fn families(read: &CacheRead) -> Vec<CacheEntryFamily> {
    match read {
        CacheRead::Exact(key) => vec![key.family.clone()],
        CacheRead::OwnerFamily(family) => vec![family.clone()],
        CacheRead::DenialCandidates(_) => vec![],
        CacheRead::Ancestors(family) => {
            let mut result = Vec::new();
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

impl CacheEngine for Backend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: Option<&'a [u8]>,
        plan: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            if self.unavailable.load(Ordering::Relaxed) {
                return Err(io::Error::other("engine unavailable"));
            }
            let result = {
                let values = self.values.lock().unwrap();
                let state = values.get(namespace);
                let revision = state.map_or(0, |(revision, _)| *revision).to_be_bytes();
                if expected.is_some_and(|expected| expected != revision) {
                    return Ok(CacheReadResult::Conflict);
                }
                let mut entries = Vec::new();
                let mut seen = HashSet::new();
                let mut bytes = 0usize;
                for read in &plan.reads {
                    for family in families(read) {
                        for entry in state.into_iter().flat_map(|(_, entries)| entries.values()) {
                            if entry.key.family != family
                                || matches!(read, CacheRead::Exact(key) if entry.key != *key)
                                || !seen.insert(entry.key.clone())
                            {
                                continue;
                            }
                            bytes = bytes
                                .checked_add(entry.weight as usize)
                                .ok_or_else(|| io::Error::other("entry size overflow"))?;
                            if entries.len() == plan.maximum_entries || bytes > plan.maximum_bytes {
                                return Err(io::Error::other("complete read exceeds bound"));
                            }
                            entries.push(entry.clone());
                        }
                    }
                }
                CacheReadResult::Read(CacheReadSet {
                    revision: revision.to_vec(),
                    entries,
                })
            };
            // Independent resolvers can race on the same generation.
            tokio::task::yield_now().await;
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
            if self
                .conflicts
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Ok(None);
            }
            let mut values = self.values.lock().unwrap();
            let current = values.get(namespace).map_or(0, |(revision, _)| *revision);
            if current.to_be_bytes() != expected {
                return Ok(None);
            }
            let (revision, entries) = values.entry(namespace.to_vec()).or_default();
            for mutation in &batch.mutations {
                match mutation {
                    CacheMutation::Put(entry) => {
                        entries.insert(entry.key.clone(), entry.clone());
                    }
                    CacheMutation::Remove(key) => {
                        entries.remove(key);
                    }
                    CacheMutation::Access(_) => {}
                }
            }
            *revision = revision.checked_add(1).unwrap();
            Ok(Some(revision.to_be_bytes().to_vec()))
        })
    }
}
