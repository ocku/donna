//! Authoritative snapshot storage independent of the backing technology.
use std::{error::Error, fmt, ops::Deref, sync::Arc};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::zone_index::ZoneIndex;
use crate::{Zone, name::dns_name_key};

/// An error reported by a caller-provided zone store.
pub type ZoneStoreError = Box<dyn Error + Send + Sync + 'static>;

/// A coherent, immutable catalog and its opaque storage revision.
///
/// Every successful commit must produce a fresh revision, even for identical
/// catalog contents. Revisions must not be reused after deletion or restart.
/// The server passes the revision back unchanged on commit.
#[derive(Clone)]
pub struct ZoneSnapshot {
    revision: Vec<u8>,
    index: Arc<ZoneIndex>,
}

impl ZoneSnapshot {
    /// Builds a catalog from validated zones, rejecting duplicate apex/class pairs.
    ///
    /// # Errors
    /// Returns an error if two zones have the same DNS apex and class.
    pub fn new(
        revision: Vec<u8>,
        zones: impl IntoIterator<Item = Arc<Zone>>,
    ) -> Result<Self, ZoneStoreError> {
        let mut index = ZoneIndex::default();
        for zone in zones {
            let at_apex = index.by_apex.entry(dns_name_key(zone.apex())).or_default();
            if at_apex.iter().any(|old| old.class() == zone.class()) {
                return Err("duplicate apex and class in zone snapshot".into());
            }
            at_apex.push(zone);
            index.len += 1;
        }
        Ok(Self {
            revision,
            index: Arc::new(index),
        })
    }

    /// Returns the backend's opaque catalog revision.
    pub fn revision(&self) -> &[u8] {
        &self.revision
    }

    /// Iterates every immutable validated zone in this catalog.
    pub fn zones(&self) -> impl Iterator<Item = &Arc<Zone>> {
        self.index.by_apex.values().flatten()
    }
}

impl fmt::Debug for ZoneSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneSnapshot")
            .field("revision", &self.revision)
            .field("zone_count", &self.index.len)
            .finish()
    }
}

/// Supplies coherent authoritative catalogs and atomic durable publication.
///
/// Implementations may use any backing technology. Reads must return a coherent
/// snapshot across all zones, including CNAME targets and cohosted delegations.
/// `compare_exchange` must atomically compare the catalog revision and durably
/// publish *all* replacement zones, returning `false` without changing anything
/// on conflict. A successful commit must be visible to subsequent snapshots.
/// Errors must not report an uncommitted operation as successful; adapters must
/// resolve ambiguous transaction outcomes before returning success.
///
/// Backend calls never run under Donna's global zone lock. Server-owned commits
/// continue if the requesting client disconnects. When this backend is selected,
/// it replaces the built-in zone map and owns update durability; the built-in
/// [`super::UpdatePersistence`] callback applies only to built-in storage.
pub trait ZoneStore: fmt::Debug + Send + Sync {
    /// Loads one coherent catalog.
    ///
    /// # Errors
    /// Returns a storage or validation error; queries then receive SERVFAIL.
    fn snapshot<'future>(
        &'future self,
    ) -> transport::BoxFuture<'future, Result<ZoneSnapshot, ZoneStoreError>>;

    /// Atomically publishes a replacement catalog if `expected_revision` is current.
    ///
    /// # Errors
    /// Returns a storage error. A revision conflict is `Ok(false)`.
    fn compare_exchange<'future>(
        &'future self,
        expected_revision: &'future [u8],
        zones: &'future [Arc<Zone>],
    ) -> transport::BoxFuture<'future, Result<bool, ZoneStoreError>>;
}

#[derive(Clone)]
pub(super) enum ZoneStorage {
    BuiltIn(Arc<RwLock<ZoneIndex>>),
    External(Arc<dyn ZoneStore>),
}

pub(super) enum ZoneRead<'a> {
    BuiltIn(RwLockReadGuard<'a, ZoneIndex>),
    External(ZoneSnapshot),
}
impl Deref for ZoneRead<'_> {
    type Target = ZoneIndex;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::BuiltIn(guard) => guard,
            Self::External(snapshot) => &snapshot.index,
        }
    }
}
impl ZoneStorage {
    pub(super) async fn read(&self) -> Result<ZoneRead<'_>, ZoneStoreError> {
        match self {
            Self::BuiltIn(zones) => Ok(ZoneRead::BuiltIn(zones.read().await)),
            Self::External(store) => Ok(ZoneRead::External(store.snapshot().await?)),
        }
    }
    pub(super) fn try_read(&self) -> Option<ZoneRead<'_>> {
        match self {
            Self::BuiltIn(zones) => zones.try_read().ok().map(ZoneRead::BuiltIn),
            Self::External(_) => None,
        }
    }
    pub(super) async fn write(&self) -> RwLockWriteGuard<'_, ZoneIndex> {
        match self {
            Self::BuiltIn(zones) => zones.write().await,
            Self::External(_) => unreachable!("external publications use compare_exchange"),
        }
    }
}

#[cfg(test)]
mod tests;
