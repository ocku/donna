use super::*;
use crate::{
    cache::codec::{Reader, Writer, invalid},
    cache::engine::KeyIdentities,
};
use dns::QClassType;
use std::io;

impl AuthenticatedZoneCache {
    pub(crate) fn engine_removals(&self) -> Vec<crate::CacheEntryKey> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .removals()
            .to_vec()
    }
    pub(crate) fn engine_accesses(&self) -> Vec<crate::CacheEntryKey> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accesses()
            .to_vec()
    }
    pub(crate) fn for_engine_coordination(capacity: usize) -> Self {
        let mut x = Self::for_engine(0);
        x.gate_capacity = capacity;
        x
    }
    pub(crate) fn for_engine(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(crate::cache::entries::CacheEntries::view()),
            gates: Mutex::new(HashMap::new()),
            gate_capacity: capacity.min(MAX_GATES),
        }
    }

    pub(crate) fn encode_entries(
        &self,
        out: &mut Writer<'_>,
        identities: &KeyIdentities,
    ) -> io::Result<()> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        out.count(entries.values.len())?;
        let mut identities = identities.lock().unwrap_or_else(|e| e.into_inner());
        identities.retain(|_, weak| weak.strong_count() > 0);
        for entry in &entries.values {
            out.begin_entry(entry, &[])?;
            out.wire(&dns::Question {
                qname: entry.key.zone.clone(),
                qtype: dns::QueryType::DNSKEY,
                qclass: QClassType::Class(entry.key.class),
            })?;
            out.wire(&entry.key.anchor)?;
            let bytes = entry
                .keys
                .export_cache_material(out.secret, out.binding)
                .map_err(|_| invalid())?;
            identities.insert(
                bytes[bytes.len() - 32..]
                    .try_into()
                    .map_err(|_| invalid())?,
                Arc::downgrade(&entry.keys),
            );
            out.blob(&bytes)?;
            out.instant(entry.started.instant)?;
            out.u32(entry.started.unix)?;
            out.u32(entry.lifetime)?;
            out.instant(entry.expires_at)?;
            out.instant(entry.refresh_after)?;
            out.u32(entry.signature_expiration)?;
            out.u32(entry.hits)?;
            out.end_entry()?;
        }
        Ok(())
    }
    pub(crate) fn decode_entries(
        &self,
        input: &mut Reader<'_>,
        identities: &KeyIdentities,
    ) -> io::Result<()> {
        let count = input.items(self.capacity, 137)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        let now = ValidationTime::now();
        // Retain identity only while key material is selected by an active
        // operation. Dropping an arbitrary active identity would make unchanged
        // keys appear to be a rollover and bypass the required refresh attempt.
        // This map retains no keys; its size tracks live selections plus this
        // bounded readset, rather than arbitrary prior names.
        identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, weak| weak.strong_count() > 0);
        for _ in 0..count {
            let question = input.question()?;
            let QClassType::Class(class) = question.qclass else {
                return Err(invalid());
            };
            let key = ZoneKey {
                zone: question.qname,
                class,
                anchor: input.name()?,
            };
            let bytes = input.blob(65_583)?;
            let restored = AuthenticatedDnskeySet::import_cache_material(
                bytes,
                input.secret,
                input.binding,
                now.unix,
            );
            let started = ValidationTime {
                instant: input.instant()?,
                unix: input.u32()?,
            };
            let lifetime = input.u32()?;
            let expires_at = input.instant()?;
            let refresh_after = input.instant()?;
            let signature_expiration = input.u32()?;
            let hits = input.u32()?;
            // Expired chain material is harmlessly dropped. It never receives
            // a fresh lifetime or a new authentication event during restore.
            let Some(restored) = restored else {
                if expires_at > now.instant {
                    return Err(invalid());
                }
                continue;
            };
            if !key.zone.eq_dns(restored.zone())
                || key.class != restored.class()
                || !key.zone.is_descendant_of(&key.anchor)
            {
                return Err(invalid());
            }
            let identity: [u8; 32] = bytes[bytes.len() - 32..]
                .try_into()
                .map_err(|_| invalid())?;
            let mut identities = identities.lock().unwrap_or_else(|e| e.into_inner());
            let keys = identities
                .get(&identity)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| Arc::new(restored));
            identities.insert(identity, Arc::downgrade(&keys));
            let entry = Entry {
                hash: entries.hash_key(&key),
                owner: packed_key(&key.zone),
                key,
                keys,
                started,
                lifetime,
                expires_at,
                refresh_after,
                signature_expiration,
                hits,
            };
            if entry.remaining(now).is_some() {
                values.push(entry);
            }
        }
        entries.restore_values(values);
        Ok(())
    }
}
