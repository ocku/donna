//! Application-owned indexed cache with atomic namespace revisions.

#[cfg(test)]
mod tests;

use resolver::{
    CacheEngine, CacheEntryFamily, CacheMutation, CacheMutationBatch, CacheRead, CacheReadPlan,
    CacheReadResult, CacheReadSet, SealedCacheEntry,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

const ENTRY_METADATA_BYTES: usize = size_of::<i128>() + size_of::<u64>();

#[derive(Default)]
struct Namespace {
    revision: u64,
    families: HashMap<CacheEntryFamily, BTreeMap<Vec<u8>, SealedCacheEntry>>,
}

#[derive(Default)]
pub struct ApplicationCache {
    values: Mutex<HashMap<Vec<u8>, Namespace>>,
    pub unavailable: AtomicBool,
}

impl ApplicationCache {
    fn available(&self) -> io::Result<()> {
        if self.unavailable.load(Ordering::Relaxed) {
            return Err(io::Error::other("application cache unavailable"));
        }
        Ok(())
    }
}

fn families(read: &CacheRead) -> io::Result<Vec<CacheEntryFamily>> {
    match read {
        CacheRead::Exact(key) => Ok(vec![key.family.clone()]),
        CacheRead::OwnerFamily(family) => Ok(vec![family.clone()]),
        CacheRead::DenialCandidates(_) => Ok(vec![]),
        CacheRead::Ancestors(family) => {
            let mut result = vec![];
            let mut owner = family.owner.as_slice();
            loop {
                result.push(CacheEntryFamily {
                    owner: owner.to_vec(),
                    ..family.clone()
                });
                match owner.first() {
                    Some(0) if owner.len() == 1 => return Ok(result),
                    Some(length) if (1..=63).contains(length) => {
                        owner = owner.get(usize::from(*length) + 1..).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid cache owner")
                        })?;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid cache owner",
                        ));
                    }
                }
            }
        }
    }
}

impl CacheEngine for ApplicationCache {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            self.available()?;
            let mut values = self
                .values
                .lock()
                .map_err(|_| io::Error::other("cache lock poisoned"))?;
            let state = values.entry(namespace.to_vec()).or_default();
            let revision = state.revision.to_be_bytes();
            if expected_revision.is_some_and(|expected| expected != revision) {
                return Ok(CacheReadResult::Conflict);
            }
            let mut entries = vec![];
            let mut seen = HashSet::new();
            let mut bytes = 0usize;
            for read in &plan.reads {
                for family in families(read)? {
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
                            .checked_add(entry.key.encode()?.len())
                            .and_then(|size| size.checked_add(entry.value.len()))
                            .and_then(|size| size.checked_add(ENTRY_METADATA_BYTES))
                            .ok_or_else(|| io::Error::other("cache read size overflow"))?;
                        if entries.len() >= plan.maximum_entries || bytes > plan.maximum_bytes {
                            return Err(io::Error::other("complete cache read exceeds limit"));
                        }
                        entries.push(entry.clone());
                    }
                }
            }
            Ok(CacheReadResult::Read(CacheReadSet {
                revision: revision.to_vec(),
                entries,
            }))
        })
    }

    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: &'a [u8],
        batch: &'a CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            self.available()?;
            let mut values = self
                .values
                .lock()
                .map_err(|_| io::Error::other("cache lock poisoned"))?;
            let state = values.entry(namespace.to_vec()).or_default();
            if expected_revision != state.revision.to_be_bytes() {
                return Ok(None);
            }
            let revision = state
                .revision
                .checked_add(1)
                .ok_or_else(|| io::Error::other("cache revision exhausted"))?;
            for mutation in &batch.mutations {
                match mutation {
                    CacheMutation::Put(entry) => {
                        state
                            .families
                            .entry(entry.key.family.clone())
                            .or_default()
                            .insert(entry.key.discriminator.clone(), entry.clone());
                    }
                    CacheMutation::Remove(key) => {
                        if let Some(bucket) = state.families.get_mut(&key.family) {
                            bucket.remove(&key.discriminator);
                        }
                    }
                    CacheMutation::Access(_) => {}
                }
            }
            state.revision = revision;
            Ok(Some(revision.to_be_bytes().to_vec()))
        })
    }
}
