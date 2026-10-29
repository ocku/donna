use super::{Resolver, codec, plan::CATEGORIES};
use crate::{
    CacheCategory, CacheEngineConfig,
    cache::codec::{CapturedEntry, invalid},
};
use std::{collections::HashSet, io};
use transport::Transport;
impl<T: Transport> Resolver<T> {
    pub(super) fn engine_capture(
        &self,
        config: &CacheEngineConfig,
        binding: &[u8],
        time: codec::TimeBase,
    ) -> io::Result<Vec<CapturedEntry>> {
        let mut out = codec::writer(config, binding, time)?;
        out.capture_entries();
        self.positive_cache.encode_entries(&mut out)?;
        self.negative_cache.encode_entries(&mut out)?;
        self.delegation_cache.encode_entries(&mut out)?;
        self.bad_cache.encode_entries(&mut out)?;
        self.failure_cache.encode_entries(&mut out)?;
        self.authenticated_zones
            .encode_entries(&mut out, &config.key_identities)?;
        let rows = out.take_entries();
        if rows.len() > config.maximum_entries {
            return Err(invalid());
        }
        Ok(rows)
    }
    pub(super) fn engine_load(
        &self,
        rows: &[codec::OpenEntry],
        config: &CacheEngineConfig,
        binding: &[u8],
        time: codec::TimeBase,
    ) -> io::Result<()> {
        for category in CATEGORIES {
            let selected: Vec<_> = rows
                .iter()
                .filter(|x| x.key.family.category == category)
                .collect();
            let mut out = codec::writer(config, binding, time)?;
            out.count(selected.len())?;
            for row in selected {
                out.raw(&row.body)?;
            }
            let mut input = codec::reader(&out.bytes, config, binding, time)?;
            match category {
                CacheCategory::Positive => self.positive_cache.decode_entries(&mut input)?,
                CacheCategory::Negative => self.negative_cache.decode_entries(&mut input)?,
                CacheCategory::Delegation => self.delegation_cache.decode_entries(&mut input)?,
                CacheCategory::Bad => self.bad_cache.decode_entries(&mut input)?,
                CacheCategory::Failure => self.failure_cache.decode_entries(&mut input)?,
                CacheCategory::AuthenticatedKeys => self
                    .authenticated_zones
                    .decode_entries(&mut input, &config.key_identities)?,
            }
            if !input.finished() {
                return Err(invalid());
            }
        }
        // A valid outer seal is not permission for a different inner typed key.
        for row in self.engine_capture(config, binding, time)? {
            if !rows.iter().any(|x| x.key == row.key) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn engine_replacements(&self) -> HashSet<crate::CacheEntryKey> {
        // These are explicit DNS-data/key/route invalidations from policy, not
        // generic metadata updates or provider capacity/retention decisions.
        let mut out = HashSet::new();
        for keys in [
            self.positive_cache.engine_removals(),
            self.negative_cache.engine_removals(),
            self.delegation_cache.engine_removals(),
            self.authenticated_zones.engine_removals(),
        ] {
            out.extend(keys)
        }
        out
    }
    pub(super) fn engine_accesses(&self) -> Vec<crate::CacheEntryKey> {
        let mut out = HashSet::new();
        for keys in [
            self.positive_cache.engine_accesses(),
            self.negative_cache.engine_accesses(),
            self.delegation_cache.engine_accesses(),
            self.bad_cache.engine_accesses(),
            self.failure_cache.engine_accesses(),
            self.authenticated_zones.engine_accesses(),
        ] {
            out.extend(keys)
        }
        out.into_iter().collect()
    }
}
