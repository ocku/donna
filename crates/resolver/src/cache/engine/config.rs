use super::CacheEngine;
use std::{io, sync::Arc};

const MAX_NAMESPACE_BYTES: usize = 256;
const DEFAULT_MAXIMUM_ENTRIES: usize = 1_024;
const DEFAULT_MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_CONFLICT_RETRIES: usize = 32;
const MAX_READ_ENTRIES: usize = 65_536;
const MIN_READ_BYTES: usize = 1_024;
const MAX_READ_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONFLICT_RETRIES: usize = 1_024;

/// Selects a replaceable per-entry engine and authenticates its opaque values.
/// Keep the secret outside the provider; sharing policy/namespace/secret permits
/// persistent reuse without making provider metadata a trust decision.
#[derive(Clone)]
pub struct CacheEngineConfig {
    pub(crate) engine: Arc<dyn CacheEngine>,
    pub(crate) namespace: Vec<u8>,
    pub(crate) secret: [u8; 32],
    pub(crate) maximum_entries: usize,
    pub(crate) maximum_bytes: usize,
    pub(crate) conflict_retries: usize,
    pub(crate) key_identities: Arc<super::KeyIdentities>,
}

impl CacheEngineConfig {
    /// Configures a per-entry provider. Defaults to 1024 returned entries, 16 MiB,
    /// and 32 conflict retries. Capacity zero in ResolverConfig skips all I/O.
    pub fn new(
        engine: Arc<dyn CacheEngine>,
        namespace: impl Into<Vec<u8>>,
        secret: [u8; 32],
    ) -> io::Result<Self> {
        let namespace = namespace.into();
        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES || secret == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid cache engine namespace or secret",
            ));
        }
        Ok(Self {
            engine,
            namespace,
            secret,
            maximum_entries: DEFAULT_MAXIMUM_ENTRIES,
            maximum_bytes: DEFAULT_MAXIMUM_BYTES,
            conflict_retries: DEFAULT_CONFLICT_RETRIES,
            key_identities: Default::default(),
        })
    }

    /// Sets bounded per-readset work, independently of provider capacity/eviction.
    pub fn with_read_limits(mut self, entries: usize, bytes: usize) -> io::Result<Self> {
        if !(1..=MAX_READ_ENTRIES).contains(&entries)
            || !(MIN_READ_BYTES..=MAX_READ_BYTES).contains(&bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid cache engine read limits",
            ));
        }
        self.maximum_entries = entries;
        self.maximum_bytes = bytes;
        Ok(self)
    }

    /// Bounds optimistic retries; each retry re-runs only internal DNS policy.
    /// Provider callbacks run through read/apply, never a replayed user closure.
    pub fn with_conflict_retries(mut self, retries: usize) -> io::Result<Self> {
        if !(1..=MAX_CONFLICT_RETRIES).contains(&retries) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid cache engine retry count",
            ));
        }
        self.conflict_retries = retries;
        Ok(self)
    }
}
