//! Build and bound a transaction's staged mutations before provider callbacks.
use super::*;
use crate::{CacheEntryKey, CacheMutation, CacheMutationBatch};

// A replacement can remove, put, and access a key; allow one prior invalidation.
const MAX_MUTATIONS_PER_ENTRY: usize = 4;
const KEY_MUTATION_OVERHEAD_BYTES: usize = 16;

impl<T: Transport> Resolver<T> {
    pub(super) fn engine_build_batch(
        &self,
        config: &CacheEngineConfig,
        binding: &[u8],
        namespace: &[u8],
        time: codec::TimeBase,
        before: &HashMap<CacheEntryKey, SealedCacheEntry>,
        opened: &[codec::OpenEntry],
    ) -> io::Result<CacheMutationBatch> {
        let rows = self.engine_capture(config, binding, time)?;
        let mut batch = CacheMutationBatch::default();
        let mut after = HashSet::new();
        let replacements = self.engine_replacements();
        for row in rows {
            if !after.insert(row.key.clone()) {
                return Err(invalid());
            }
            let same = opened
                .iter()
                .find(|x| x.key == row.key)
                .is_some_and(|old| old.body == row.body)
                && before
                    .get(&row.key)
                    .is_some_and(|x| x.expires_unix_nanos == row.expiry_wall);
            if !same {
                if before.contains_key(&row.key) && replacements.contains(&row.key) {
                    batch.mutations.push(CacheMutation::Remove(row.key.clone()));
                }
                batch.mutations.push(CacheMutation::Put(codec::seal(
                    row, config, binding, namespace, time,
                )?));
            }
        }
        for key in before.keys() {
            if !after.contains(key) {
                batch.mutations.push(CacheMutation::Remove(key.clone()));
            }
        }
        for key in self.engine_accesses() {
            batch.mutations.push(CacheMutation::Access(key));
        }
        if batch.mutations.len()
            > config
                .maximum_entries
                .saturating_mul(MAX_MUTATIONS_PER_ENTRY)
        {
            return Err(invalid());
        }
        batch.mutations.iter().try_fold(0usize, |total, mutation| {
            let bytes = match mutation {
                CacheMutation::Put(entry) => {
                    usize::try_from(entry.weight).map_err(|_| invalid())?
                }
                CacheMutation::Remove(key) | CacheMutation::Access(key) => key
                    .encode()?
                    .len()
                    .checked_add(KEY_MUTATION_OVERHEAD_BYTES)
                    .ok_or_else(invalid)?,
            };
            total
                .checked_add(bytes)
                .filter(|n| *n <= config.maximum_bytes)
                .ok_or_else(invalid)
        })?;

        Ok(batch)
    }
}
