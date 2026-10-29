use super::*;
use crate::cache::codec::{Reader, Writer, invalid, question_from_codes};
use std::io;

impl DelegationCache {
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
    pub(crate) fn for_engine(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(crate::cache::entries::CacheEntries::view()),
        }
    }

    pub(crate) fn encode_entries(&self, out: &mut Writer<'_>) -> io::Result<()> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        out.count(entries.values.len())?;
        for entry in &entries.values {
            out.begin_entry(entry, &[])?;
            out.wire(&question_from_codes(
                &entry.key.zone,
                2,
                entry.key.class.value(),
            )?)?;
            out.wire(&entry.zone)?;
            out.instant(entry.expires_at)?;
            out.u32(entry.hits)?;
            for lease in entry.refresh {
                out.flag(lease.is_some())?;
                if let Some(lease) = lease {
                    out.raw(&lease.token.to_be_bytes())?;
                    out.instant(lease.expires_at)?;
                    out.flag(lease.failed)?;
                }
            }
            out.count(entry.candidates.len())?;
            for (address, expires_at) in &entry.candidates {
                out.blob(address.to_string().as_bytes())?;
                out.instant(*expires_at)?;
            }
            out.count(entry.name_servers.len())?;
            for name in &entry.name_servers {
                out.wire(name)?;
            }
            out.end_entry()?;
        }
        Ok(())
    }
    pub(crate) fn decode_entries(&self, input: &mut Reader<'_>) -> io::Result<()> {
        let count = input.items(self.capacity, 44)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let question = input.question()?;
            let QClassType::Class(class) = question.qclass else {
                return Err(invalid());
            };
            let zone = input.name()?;
            if !zone.eq_dns(&question.qname) {
                return Err(invalid());
            }
            let key = DelegationKey::new(&zone, class);
            let expires_at = input.instant()?;
            let hits = input.u32()?;
            let mut refresh = [None; 2];
            for slot in &mut refresh {
                if input.flag()? {
                    let token =
                        u64::from_be_bytes(input.raw(8)?.try_into().map_err(|_| invalid())?);
                    let expires_at = input.instant()?;
                    if expires_at.saturating_duration_since(Instant::now())
                        > Duration::from_secs(300)
                    {
                        return Err(invalid());
                    }
                    *slot = Some(RefreshLease {
                        token,
                        expires_at,
                        failed: input.flag()?,
                    });
                }
            }
            let candidates = (0..input.count(65_535)?)
                .map(|_| {
                    let address = std::str::from_utf8(input.blob(64)?)
                        .map_err(|_| invalid())?
                        .parse()
                        .map_err(|_| invalid())?;
                    Ok((address, input.instant()?))
                })
                .collect::<io::Result<Vec<_>>>()?;
            let name_servers = (0..input.count(65_535)?)
                .map(|_| input.name())
                .collect::<io::Result<Vec<_>>>()?;
            if name_servers.is_empty()
                && (expires_at > Instant::now() || refresh.iter().all(Option::is_none))
            {
                return Err(invalid());
            }
            values.push(Entry {
                hash: entries.hash_key(&key),
                key,
                zone,
                candidates,
                name_servers,
                expires_at,
                hits,
                refresh,
            });
        }
        entries.restore_values(values);
        Ok(())
    }
}
