//! Bounded parent-refresh coordination; never serves expired delegation data.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct RefreshLease {
    pub(super) token: u64,
    pub(super) expires_at: Instant,
    pub(super) failed: bool,
}

impl DelegationCache {
    pub(crate) fn owns_refresh(
        &self,
        zone: &dns::DomainName,
        class: dns::ClassType,
        cd: bool,
        token: u64,
    ) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = super::DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        entries.find(hash, |e| e.key == key).is_some_and(|index| {
            entries.values[index].refresh[usize::from(cd)].is_some_and(|lease| {
                lease.token == token
                    && !lease.failed
                    && lease.expires_at > std::time::Instant::now()
            })
        })
    }

    pub(crate) fn claim_refresh(
        &self,
        zone: &DomainName,
        class: ClassType,
        checking_disabled: bool,
        ttl: Duration,
    ) -> Option<u64> {
        let token = rand::random();
        if self.capacity == 0 {
            return Some(token);
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove_expired(now);
        let key = DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        let slot = usize::from(checking_disabled);
        if let Some(index) = entries.find(hash, |e| e.key == key) {
            if entries.values[index].refresh[slot].is_some_and(|r| r.expires_at > now) {
                return None;
            }
            entries.modify(index, |e| {
                e.refresh[slot] = Some(RefreshLease {
                    token,
                    expires_at: now + ttl.clamp(Duration::from_secs(1), Duration::from_secs(300)),
                    failed: false,
                })
            });
        } else {
            let mut refresh = [None; 2];
            refresh[slot] = Some(RefreshLease {
                token,
                expires_at: now + ttl.clamp(Duration::from_secs(1), Duration::from_secs(300)),
                failed: false,
            });
            entries.insert(
                Entry {
                    key,
                    hash,
                    zone: zone.clone(),
                    candidates: vec![],
                    name_servers: vec![],
                    expires_at: now,
                    hits: 0,
                    refresh,
                },
                self.capacity,
                now,
            );
        }
        Some(token)
    }

    pub(crate) fn refresh_status(
        &self,
        zone: &DomainName,
        class: ClassType,
        checking_disabled: bool,
    ) -> Option<bool> {
        let now = Instant::now();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        entries
            .find(hash, |e| e.key == key)
            .and_then(|index| entries.values[index].refresh[usize::from(checking_disabled)])
            .filter(|r| r.expires_at > now)
            .map(|r| r.failed)
    }

    pub(crate) fn start_refresh(
        &self,
        zone: &DomainName,
        class: ClassType,
        checking_disabled: bool,
        token: u64,
        ttl: Duration,
    ) -> bool {
        if self.capacity == 0 {
            return true;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        let slot = usize::from(checking_disabled);
        let Some(index) = entries.find(hash, |e| e.key == key) else {
            return false;
        };
        let Some(lease) = entries.values[index].refresh[slot] else {
            return false;
        };
        if lease.token != token || lease.failed {
            return false;
        }
        entries.modify(index, |e| {
            e.refresh[slot] = Some(RefreshLease {
                token,
                expires_at: now + ttl.clamp(Duration::from_secs(1), Duration::from_secs(300)),
                failed: false,
            })
        });
        true
    }

    pub(crate) fn finish_refresh_failure(
        &self,
        zone: &DomainName,
        class: ClassType,
        checking_disabled: bool,
        token: u64,
        ttl: Duration,
    ) {
        if self.capacity == 0 {
            return;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        let slot = usize::from(checking_disabled);
        let Some(index) = entries.find(hash, |e| e.key == key) else {
            return;
        };
        let Some(lease) = entries.values[index].refresh[slot] else {
            return;
        };
        if lease.token != token || lease.failed {
            return;
        }
        entries.modify(index, |e| {
            e.refresh[slot] = Some(RefreshLease {
                token,
                expires_at: now + ttl.clamp(Duration::from_secs(1), Duration::from_secs(300)),
                failed: true,
            })
        });
    }

    pub(crate) fn refresh_succeeded(
        &self,
        zone: &DomainName,
        class: ClassType,
        checking_disabled: bool,
        owner: Option<u64>,
        child_availability: bool,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = DelegationKey::new(zone, class);
        let hash = entries.hash_key(&key);
        if let Some(index) = entries.find(hash, |e| e.key == key)
            && entries.values[index].refresh[usize::from(checking_disabled)]
                .is_some_and(|r| (child_availability && r.failed) || owner == Some(r.token))
        {
            entries.modify(index, |e| e.refresh[usize::from(checking_disabled)] = None);
        }
    }

    pub(crate) fn failed_without_routes(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> bool {
        self.with_closest_state(question, |entry, now| {
            if entry.expires_at > now {
                return Some(false);
            }
            entry.refresh[usize::from(checking_disabled)]
                .filter(|r| r.failed && r.expires_at > now)
                .map(|_| true)
        })
        .unwrap_or(false)
    }
}
