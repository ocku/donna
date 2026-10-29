//! Per-entry cache algorithms supplied by applications, independently of storage.
//!
//! Providers own indexes, admission, retention and eviction. Donna authenticates
//! entry contents and enforces DNS coherence, provenance and absolute lifetimes.
//! A provider may discard puts or retain an existing value when only metadata
//! changes, but must atomically execute explicit DNS invalidations/removals. Successful
//! revisions cover absent keys/families and must never be reused (including ABA).
use std::{
    collections::HashMap,
    io,
    sync::{Mutex, Weak},
};

// Weak references preserve identity for live selections without retaining keys.
pub(crate) type KeyIdentities = Mutex<HashMap<[u8; 32], Weak<dns::AuthenticatedDnskeySet>>>;

pub(crate) const MAX_REVISION_BYTES: usize = 256;

mod config;
mod key;
pub use config::CacheEngineConfig;
pub use key::{CacheCategory, CacheEntryFamily, CacheEntryKey};

/// An indexed bounded lookup. Ancestors includes the supplied owner and root.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CacheRead {
    /// One complete canonical entry identity.
    Exact(CacheEntryKey),
    /// All retained entries of this category at one owner and class.
    OwnerFamily(CacheEntryFamily),
    /// Complete owner families at the owner and every literal DNS parent.
    Ancestors(CacheEntryFamily),
    /// Optional future denial index hint; unsupported providers return no hints.
    /// Results are candidates only and never establish authenticated DNS data.
    DenialCandidates(CacheEntryFamily),
}
/// Limits apply to the entire response, before allocation by the provider.
#[derive(Clone, Debug)]
pub struct CacheReadPlan {
    /// Predicates whose returned families must be complete, not truncated.
    pub reads: Vec<CacheRead>,
    /// Maximum number of retained entries in the returned readset.
    pub maximum_entries: usize,
    /// Maximum sum of encoded key, metadata and sealed value bytes.
    pub maximum_bytes: usize,
}
/// Public index metadata is authenticated by Donna before it is used.
#[derive(Clone, Debug)]
pub struct SealedCacheEntry {
    /// Canonical category, owner/class and entry discriminator.
    pub key: CacheEntryKey,
    /// Core-authenticated payload; providers cannot manufacture trust or TTLs.
    pub value: Vec<u8>,
    /// Original expiry, in signed Unix nanoseconds; never renew on a read.
    pub expires_unix_nanos: i128,
    /// Core-issued bounded storage weight, authenticated with the payload.
    pub weight: u64,
}
/// A consistent targeted lookup, not a full namespace snapshot.
#[derive(Clone, Debug)]
pub struct CacheReadSet {
    /// Non-reusable namespace generation token, at most 256 bytes.
    pub revision: Vec<u8>,
    /// Only entries matching requested predicates, bounded by the read plan.
    pub entries: Vec<SealedCacheEntry>,
}
/// A read at an expected generation must not mix states from different commits.
#[derive(Clone, Debug)]
pub enum CacheReadResult {
    /// Complete results at one consistent generation.
    Read(CacheReadSet),
    /// The expected generation changed; Donna retries boundedly.
    Conflict,
}
/// Staged effects from one complete DNS-policy operation.
#[derive(Clone, Debug)]
pub enum CacheMutation {
    /// Provider admission/retention may decline this otherwise valid value.
    Put(SealedCacheEntry),
    /// Mandatory coherent invalidation; execute even if a put is declined.
    Remove(CacheEntryKey),
    /// Optional access accounting, emitted only after the readset is complete.
    Access(CacheEntryKey),
}
/// One atomic collection spanning all six categories.
#[derive(Clone, Debug, Default)]
pub struct CacheMutationBatch {
    /// Apply all removals/puts/accesses against the expected generation.
    pub mutations: Vec<CacheMutation>,
}
/// Technology-neutral targeted cache algorithms with atomic namespace revisions.
///
/// Reads must not invoke admission/access callbacks: those effects belong to
/// `apply`. TTL cleanup or eviction is permitted only with a generation change.
/// Missing members of a requested family must genuinely be absent at that
/// generation; silently omitting retained conflicting members is not allowed.
/// Optional denial hints may be unsupported (empty), ordinary predicates may not.
/// Rollback resistance is a provider contract; a MAC cannot prove non-rollback.
/// Providers deliberately discarding BAD/failure history disable its stateful
/// suppression/backoff behavior. A no-store engine proves replaceability, not
/// RFC9520 failure-suppression compliance; that requires an appropriate policy.
/// Custom views do not preserve native popularity/template-preparation hints.
pub trait CacheEngine: Send + Sync {
    /// Reads only the bounded requested scopes. An expected generation binds
    /// incremental reads and post-commit reselection to one coherent state.
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>>;
    /// Atomically applies a complete batch. `None` reports a conflict; `Some`
    /// returns a new non-reusable generation, even if policy discards every put.
    /// Returned generations do not imply that a particular put was retained.
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: &'a [u8],
        batch: &'a CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>>;
}
