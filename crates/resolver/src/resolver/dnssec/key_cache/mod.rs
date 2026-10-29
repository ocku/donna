//! Trusted chain material, isolated from raw iterative answers and CD traffic.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use dns::{AuthenticatedDnskeySet, ClassType, DomainName};
use tokio::sync::Mutex as AsyncMutex;

use crate::{cache::entries::CacheEntries, cache::store::CacheEntry, name::packed_key};

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_GATES: usize = 1024;
mod codec;

#[derive(Clone, Copy)]
pub(super) struct ValidationTime {
    pub(super) instant: Instant,
    pub(super) unix: u32,
}

impl ValidationTime {
    pub(super) fn now() -> Self {
        // Sample monotonic time first, before any network acquisition.
        let instant = Instant::now();
        Self {
            instant,
            unix: super::records::unix_time(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct ZoneKey {
    pub(super) zone: DomainName,
    pub(super) class: ClassType,
    pub(super) anchor: DomainName,
}

#[derive(Clone, Copy)]
pub(super) struct AuthenticatedLifetime {
    pub(super) ttl: u32,
    pub(super) started: ValidationTime,
    pub(super) deadline: Instant,
    pub(super) valid_until: u32,
}

pub(super) struct CachedZone {
    pub(super) keys: Arc<AuthenticatedDnskeySet>,
    pub(super) ttl: u32,
    pub(super) deadline: Instant,
    pub(super) valid_until: u32,
}

struct Entry {
    hash: u64,
    owner: Box<[u8]>,
    key: ZoneKey,
    keys: Arc<AuthenticatedDnskeySet>,
    started: ValidationTime,
    lifetime: u32,
    expires_at: Instant,
    refresh_after: Instant,
    signature_expiration: u32,
    hits: u32,
}

impl CacheEntry for Entry {
    fn engine_key(&self) -> Option<crate::CacheEntryKey> {
        Some(crate::CacheEntryKey {
            family: crate::CacheEntryFamily {
                category: crate::CacheCategory::AuthenticatedKeys,
                owner: self.owner.to_vec(),
                class: self.key.class.value(),
            },
            discriminator: crate::name::packed_key(&self.key.anchor).to_vec(),
        })
    }

    fn hash(&self) -> u64 {
        self.hash
    }
    fn owner(&self) -> &[u8] {
        &self.owner
    }
    fn expires_at(&self) -> Instant {
        self.expires_at
    }
    fn hits(&self) -> u32 {
        self.hits
    }
    fn set_hits(&mut self, hits: u32) {
        self.hits = hits;
    }
}

impl Entry {
    fn remaining(&self, now: ValidationTime) -> Option<u32> {
        let monotonic_age = now.instant.checked_duration_since(self.started.instant)?;
        let wall_age = now.unix.wrapping_sub(self.started.unix);
        // Handle the 32-bit DNSSEC time wrap, but reject backwards wall time
        // and large clock changes. Never trust a signature outside the interval
        // bounded when the complete chain was actually authenticated.
        if wall_age >= self.lifetime
            || u64::from(wall_age).abs_diff(monotonic_age.as_secs()) > 1
            || self.expires_at <= now.instant
        {
            return None;
        }
        Some(
            (self.expires_at - now.instant)
                .as_secs()
                .min(u64::from(self.lifetime - wall_age)) as u32,
        )
    }
}

pub(in crate::resolver) struct AuthenticatedZoneCache {
    entries: Mutex<CacheEntries<Entry>>,
    gates: Mutex<HashMap<ZoneKey, Weak<AsyncMutex<()>>>>,
    capacity: usize,
    gate_capacity: usize,
}

impl AuthenticatedZoneCache {
    pub(in crate::resolver) fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(CacheEntries::with_capacity(capacity.min(16))),
            gates: Mutex::new(HashMap::new()),
            capacity,
            gate_capacity: capacity,
        }
    }

    pub(super) fn get(&self, key: &ZoneKey, now: ValidationTime) -> Option<CachedZone> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let hash = entries.hash_key(key);
        let index = entries.find(hash, |entry| entry.key == *key)?;
        let Some(ttl) = entries.values[index].remaining(now) else {
            entries.remove(index);
            return None;
        };
        entries.touch(index);
        Some(CachedZone {
            keys: Arc::clone(&entries.values[index].keys),
            ttl,
            deadline: entries.values[index].expires_at,
            valid_until: entries.values[index].signature_expiration,
        })
    }

    /// Only a successful authenticated chain may call this admission boundary.
    pub(super) fn insert_bounded(
        &self,
        key: ZoneKey,
        keys: Arc<AuthenticatedDnskeySet>,
        lifetime: AuthenticatedLifetime,
        maximum: Duration,
    ) {
        let AuthenticatedLifetime {
            ttl,
            started,
            deadline: inherited_deadline,
            valid_until,
        } = lifetime;
        let signature_ttl = valid_until.wrapping_sub(started.unix);
        if signature_ttl >= (1_u32 << 31) {
            return;
        }
        if !key.zone.eq_dns(keys.zone())
            || key.class != keys.class()
            || !key.zone.is_descendant_of(&key.anchor)
        {
            return;
        }
        let lifetime = u64::from(ttl)
            .min(u64::from(signature_ttl))
            .min(maximum.as_secs())
            .min(i32::MAX as u64) as u32;
        if self.capacity == 0 {
            return;
        }
        if lifetime == 0 {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let hash = entries.hash_key(&key);
            if let Some(index) = entries.find(hash, |entry| entry.key == key) {
                entries.remove(index);
            }
            return;
        }
        let Some(expires_at) = started
            .instant
            .checked_add(Duration::from_secs(u64::from(lifetime)))
        else {
            return;
        };
        let now = ValidationTime::now();
        let mut entry = Entry {
            hash: 0,
            owner: packed_key(&key.zone),
            key,
            keys,
            started,
            lifetime,
            expires_at: expires_at.min(inherited_deadline),
            refresh_after: now.instant,
            signature_expiration: valid_until,
            hits: 0,
        };
        // Acquisition time has already consumed the original chain lifetime.
        if entry.remaining(now).is_none() {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entry.hash = entries.hash_key(&entry.key);
        if let Some(index) = entries.find(entry.hash, |previous| previous.key == entry.key) {
            entry.refresh_after = entry.refresh_after.max(entries.values[index].refresh_after);
            let renewal = entries.is_view() && {
                let old = &entries.values[index];
                let old_records = old.keys.records();
                let new_records = entry.keys.records();
                old.remaining(now).is_some()
                    && old_records.len() == new_records.len()
                    && old_records
                        .iter()
                        .all(|r| new_records.iter().any(|n| r.eq_dns(n)))
                    && new_records
                        .iter()
                        .all(|r| old_records.iter().any(|n| r.eq_dns(n)))
            };
            if renewal {
                entries.remove_renewal(index);
            } else {
                entries.remove(index);
            }
        }
        entries.insert(entry, self.capacity, now.instant);
    }

    #[cfg(test)]
    pub(super) fn insert(
        &self,
        key: ZoneKey,
        keys: Arc<AuthenticatedDnskeySet>,
        ttl: u32,
        started: ValidationTime,
        maximum: Duration,
    ) {
        let deadline = started
            .instant
            .checked_add(Duration::from_secs(u64::from(ttl)))
            .unwrap_or(started.instant);
        let valid_until = keys.signature_expiration();
        self.insert_bounded(
            key,
            keys,
            AuthenticatedLifetime {
                ttl,
                started,
                deadline,
                valid_until,
            },
            maximum,
        );
    }

    /// Serializes acquisition for one zone without holding a global lock
    /// across awaits. Weak gates do not retain completed work or key material.
    pub(super) fn gate(&self, key: &ZoneKey) -> Option<Arc<AsyncMutex<()>>> {
        if self.gate_capacity == 0 {
            return None;
        }
        let mut gates = self.gates.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(gate) = gates.get(key).and_then(Weak::upgrade) {
            return Some(gate);
        }
        if gates.len() >= self.gate_capacity.min(MAX_GATES) {
            gates.retain(|_, gate| gate.strong_count() != 0);
            if gates.len() >= self.gate_capacity.min(MAX_GATES) {
                return None;
            }
        }
        let gate = Arc::new(AsyncMutex::new(()));
        gates.insert(key.clone(), Arc::downgrade(&gate));
        Some(gate)
    }

    /// Nonmutating post-await check. No retained lease means fresh network
    /// acquisition may proceed even if an engine declined our metadata write.
    pub(super) fn refresh_pending(
        &self,
        key: &ZoneKey,
        used: &Arc<AuthenticatedDnskeySet>,
        now: ValidationTime,
    ) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let hash = entries.hash_key(key);
        entries
            .find(hash, |entry| entry.key == *key)
            .is_some_and(|index| {
                let entry = &entries.values[index];
                Arc::ptr_eq(&entry.keys, used)
                    && entry.remaining(now).is_some()
                    && entry.refresh_after > now.instant
            })
    }

    pub(super) fn allow_refresh(
        &self,
        key: &ZoneKey,
        used: &Arc<AuthenticatedDnskeySet>,
        now: ValidationTime,
    ) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let hash = entries.hash_key(key);
        let Some(index) = entries.find(hash, |entry| entry.key == *key) else {
            return false;
        };
        let entry = &mut entries.values[index];
        if !Arc::ptr_eq(&entry.keys, used)
            || entry.refresh_after > now.instant
            || entry.remaining(now).is_none()
        {
            return false;
        }
        entry.refresh_after = now
            .instant
            .checked_add(REFRESH_INTERVAL)
            .unwrap_or(entry.expires_at);
        true
    }
}

#[cfg(test)]
mod tests;
