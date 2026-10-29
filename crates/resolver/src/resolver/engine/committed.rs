//! Reselect the provider's retained state after an atomic commit.
use super::*;
use crate::{CacheEntryKey, CacheMutation, CacheMutationBatch, CacheReadSet};

impl<T: Transport> Resolver<T> {
    pub(super) async fn engine_read_committed(
        &self,
        config: &CacheEngineConfig,
        binding: &[u8],
        namespace: &[u8],
        committed: &[u8],
        all: &CacheReadPlan,
        batch: &CacheMutationBatch,
    ) -> io::Result<Box<Self>> {
        let mut expected = Some(committed);
        for _ in 0..config.conflict_retries {
            match config.engine.read(namespace, expected, all).await? {
                CacheReadResult::Conflict => {
                    expected = None;
                    tokio::task::yield_now().await;
                }
                CacheReadResult::Read(set) => {
                    if expected.is_some_and(|r| r != set.revision) {
                        return Err(invalid());
                    }
                    let exact_commit = set.revision == committed;
                    if exact_commit {
                        validate_removals(&set, batch)?;
                    }
                    let time = codec::TimeBase::now()?;
                    let (retained, opened) =
                        self.engine_accept_readset(config, binding, namespace, all, set, time)?;
                    let mut current = Box::new(self.engine_view());
                    current.engine_load(&opened, config, binding, time)?;
                    current.engine_effects_retained = effects_retained(&retained, batch);
                    return Ok(current);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "cache engine post-commit read conflict bound",
        ))
    }
}

fn validate_removals(set: &CacheReadSet, batch: &CacheMutationBatch) -> io::Result<()> {
    for effect in &batch.mutations {
        if let CacheMutation::Remove(key) = effect {
            let put = batch.mutations.iter().find_map(|m| match m {
                CacheMutation::Put(x) if &x.key == key => Some(x),
                _ => None,
            });
            let actual = set.entries.iter().find(|x| &x.key == key);
            if actual.is_some_and(|a| {
                put.is_none_or(|p| {
                    a.value != p.value
                        || a.expires_unix_nanos != p.expires_unix_nanos
                        || a.weight != p.weight
                })
            }) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn effects_retained(
    retained: &HashMap<CacheEntryKey, SealedCacheEntry>,
    batch: &CacheMutationBatch,
) -> bool {
    batch.mutations.iter().all(|effect| match effect {
        CacheMutation::Put(wanted) => retained.get(&wanted.key).is_some_and(|actual| {
            actual.value == wanted.value
                && actual.expires_unix_nanos == wanted.expires_unix_nanos
                && actual.weight == wanted.weight
        }),
        CacheMutation::Remove(key) => {
            !retained.contains_key(key)
                || batch
                    .mutations
                    .iter()
                    .any(|m| matches!(m,CacheMutation::Put(x) if &x.key==key))
        }
        CacheMutation::Access(_) => true,
    })
}
