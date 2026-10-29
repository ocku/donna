//! Bounded per-entry readsets: plan first, execute DNS policy once, commit once.
#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

mod codec;
mod committed;
mod context;
mod entries;
mod mutations;
mod plan;
use super::Resolver;
use crate::{
    CacheEngineConfig, CacheEntryFamily, CacheRead, CacheReadPlan, CacheReadResult, ResolveError,
    SealedCacheEntry, cache::codec::invalid, cache::engine::MAX_REVISION_BYTES,
};
pub(super) use plan::{seeds, seeds_many, zone};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io,
};
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(super) async fn engine_transaction<R: Send>(
        &self,
        questions: &[dns::Question],
        operation: impl Fn(&Self) -> Result<R, ResolveError> + Send + Sync,
    ) -> Result<(R, Option<Box<Self>>), ResolveError> {
        let config = self.cache_engine.as_ref().expect("engine dispatcher");
        let binding: [u8; 32] = Sha256::digest(format!(
            "donna per-entry engine v1 authenticated-authority-v1 {:?}",
            self.config
        ))
        .into();
        let mut namespace = config.namespace.clone();
        namespace.extend_from_slice(b"\0donna-entry-engine-v1\0");
        namespace.extend_from_slice(&binding);
        for _ in 0..config.conflict_retries {
            let Some((revision, before, opened, seen, time)) = self
                .engine_read_complete(config, &binding, &namespace, questions)
                .await
                .map_err(ResolveError::CacheBackend)?
            else {
                continue;
            };
            let context = Box::new(self.engine_view());
            context
                .engine_load(&opened, config, &binding, time)
                .map_err(ResolveError::CacheBackend)?;
            // No user closure or policy ran during dependency discovery. All effects
            // below remain local until one complete generation-checked atomic batch.
            let result = operation(&context);
            let batch = context
                .engine_build_batch(config, &binding, &namespace, time, &before, &opened)
                .map_err(ResolveError::CacheBackend)?;
            let committed = config
                .engine
                .apply(&namespace, &revision, &batch)
                .await
                .map_err(ResolveError::CacheBackend)?;
            let Some(committed) = committed else {
                tokio::task::yield_now().await;
                continue;
            };
            if committed.is_empty() || committed.len() > MAX_REVISION_BYTES || committed == revision
            {
                return Err(ResolveError::CacheBackend(invalid()));
            }
            // Admission and eviction belong to the provider. Read its ACTUAL retained
            // result; never return a hit from our staged puts. A conflict after a
            // successful commit does not repeat the already committed policy effects.
            let all = CacheReadPlan {
                reads: seen.into_iter().map(CacheRead::OwnerFamily).collect(),
                maximum_entries: config.maximum_entries,
                maximum_bytes: config.maximum_bytes,
            };
            let current = self
                .engine_read_committed(config, &binding, &namespace, &committed, &all, &batch)
                .await
                .map_err(ResolveError::CacheBackend)?;
            return result.map(|value| (value, Some(current)));
        }
        Err(ResolveError::CacheBackend(io::Error::new(
            io::ErrorKind::WouldBlock,
            "cache engine transaction conflict bound",
        )))
    }

    async fn engine_read_complete(
        &self,
        config: &CacheEngineConfig,
        binding: &[u8],
        namespace: &[u8],
        questions: &[dns::Question],
    ) -> io::Result<Option<ReadComplete>> {
        let time = codec::TimeBase::now()?;
        let mut names = questions.to_vec();
        let mut seen = HashSet::new();
        let mut entries = HashMap::new();
        let mut opened = Vec::new();
        let mut revision: Option<Vec<u8>> = None;
        let mut bytes = 0usize;
        for _ in 0..=self.config.max_steps.max(1) {
            let mut pending = plan::pending(
                &names,
                &mut seen,
                config.maximum_entries,
                config.maximum_bytes,
            )?;
            if pending.reads.is_empty() {
                return Ok(Some((
                    revision.unwrap_or_default(),
                    entries,
                    opened,
                    seen,
                    time,
                )));
            }
            pending.maximum_entries = config
                .maximum_entries
                .checked_sub(entries.len())
                .ok_or_else(invalid)?;
            pending.maximum_bytes = config
                .maximum_bytes
                .checked_sub(bytes)
                .ok_or_else(invalid)?;
            let set = match config
                .engine
                .read(namespace, revision.as_deref(), &pending)
                .await?
            {
                CacheReadResult::Conflict => return Ok(None),
                CacheReadResult::Read(x) => x,
            };
            if revision.as_ref().is_some_and(|r| r != &set.revision) {
                return Err(invalid());
            }
            revision = Some(set.revision.clone());
            let (new, opened_new) =
                self.engine_accept_readset(config, binding, namespace, &pending, set, time)?;
            for (key, value) in new {
                bytes = bytes
                    .checked_add(value.weight as usize)
                    .ok_or_else(invalid)?;
                if entries.insert(key, value).is_some() {
                    return Err(invalid());
                }
            }
            if entries.len() > config.maximum_entries || bytes > config.maximum_bytes {
                return Err(invalid());
            }
            opened.extend(opened_new);
            let all_links: Vec<_> = opened
                .iter()
                .flat_map(|x| x.links.iter().cloned())
                .collect();
            plan::expand(
                &mut names,
                &all_links,
                usize::from(self.config.max_steps.max(1))
                    .saturating_add(questions.len())
                    .max(1),
            )?;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache engine dependency discovery bound",
        ))
    }

    fn engine_accept_readset(
        &self,
        config: &CacheEngineConfig,
        binding: &[u8],
        namespace: &[u8],
        plan: &CacheReadPlan,
        set: crate::CacheReadSet,
        time: codec::TimeBase,
    ) -> io::Result<(
        HashMap<crate::CacheEntryKey, SealedCacheEntry>,
        Vec<codec::OpenEntry>,
    )> {
        if set.revision.is_empty()
            || set.revision.len() > MAX_REVISION_BYTES
            || set.entries.len() > plan.maximum_entries
        {
            return Err(invalid());
        }
        let mut bytes = 0usize;
        let mut entries = HashMap::new();
        let mut opened = Vec::new();
        for entry in set.entries {
            let weight = entry
                .key
                .encode()?
                .len()
                .checked_add(entry.value.len())
                .and_then(|x| x.checked_add(codec::ENTRY_METADATA_BYTES))
                .ok_or_else(invalid)?;
            bytes = bytes.checked_add(weight).ok_or_else(invalid)?;
            if bytes > plan.maximum_bytes
                || !plan.reads.iter().any(|p| plan::matches(&entry.key, p))
            {
                return Err(invalid());
            }
            let row = codec::open(&entry, config, binding, namespace, time)?;
            if entries.insert(entry.key.clone(), entry).is_some() {
                return Err(invalid());
            }
            opened.push(row);
        }
        Ok((entries, opened))
    }
}

type ReadComplete = (
    Vec<u8>,
    HashMap<crate::CacheEntryKey, SealedCacheEntry>,
    Vec<codec::OpenEntry>,
    HashSet<CacheEntryFamily>,
    codec::TimeBase,
);
