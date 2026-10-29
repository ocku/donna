use super::*;

/// A bounded mDNS cache implementing cache-flush and goodbye grace periods.
pub struct MdnsCache {
    capacity: usize,
    entries: Vec<CachedRecord>,
}

struct CachedRecord {
    record: ResourceRecord,
    inserted_at: Instant,
    expires_at: Instant,
}

impl MdnsCache {
    /// Creates a cache retaining at most `capacity` records.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Vec::new(),
        }
    }

    /// Applies one received packet atomically, preserving multiple unique
    /// records announced together while aging replaced data for one second.
    pub fn insert_packet(&mut self, records: &[MdnsRecord], now: Instant) {
        self.entries.retain(|entry| entry.expires_at > now);
        let grace = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        for incoming in records.iter().filter(|record| record.cache_flush) {
            for cached in &mut self.entries {
                if same_rrset(&cached.record, &incoming.record)
                    && !cached.record.eq_dns(&incoming.record)
                    && now.saturating_duration_since(cached.inserted_at) > Duration::from_secs(1)
                {
                    cached.expires_at = cached.expires_at.min(grace);
                }
            }
        }
        for incoming in records {
            if let Some(cached) = self
                .entries
                .iter_mut()
                .find(|cached| cached.record.eq_dns(&incoming.record))
            {
                cached.inserted_at = now;
                cached.expires_at = if incoming.record.ttl == 0 {
                    grace
                } else {
                    expiry(now, incoming.record.ttl)
                };
                cached.record.ttl = incoming.record.ttl;
                continue;
            }
            if self.capacity == 0 {
                continue;
            }
            if self.entries.len() == self.capacity {
                let victim = self
                    .entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(index, _)| index)
                    .expect("a full mDNS cache contains an entry");
                self.entries.swap_remove(victim);
            }
            self.entries.push(CachedRecord {
                record: incoming.record.clone(),
                inserted_at: now,
                expires_at: if incoming.record.ttl == 0 {
                    grace
                } else {
                    expiry(now, incoming.record.ttl)
                },
            });
        }
    }

    /// Returns unexpired records with their remaining TTLs.
    pub fn records(&mut self, now: Instant) -> Vec<ResourceRecord> {
        self.entries.retain(|entry| entry.expires_at > now);
        self.entries
            .iter()
            .map(|entry| {
                let mut record = entry.record.clone();
                record.ttl = entry
                    .expires_at
                    .saturating_duration_since(now)
                    .as_secs()
                    .min(u64::from(u32::MAX)) as u32;
                record
            })
            .collect()
    }
}

fn expiry(now: Instant, ttl: u32) -> Instant {
    now.checked_add(Duration::from_secs(u64::from(ttl)))
        .unwrap_or(now)
}

fn same_rrset(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    left.name.eq_dns(&right.name) && left.rtype == right.rtype && left.class == right.class
}
