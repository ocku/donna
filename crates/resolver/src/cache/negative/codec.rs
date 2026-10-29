use super::*;
use crate::cache::codec::{Reader, Writer, invalid, question_from_codes};
use std::io;

impl NegativeCache {
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
            let (qname, qtype, class, name_error) = match &entry.key {
                NegativeKey::Name { qname, class } => (qname, 1, *class, true),
                NegativeKey::Type {
                    qname,
                    qtype,
                    class,
                } => (qname, *qtype, *class, false),
            };
            out.flag(name_error)?;
            out.wire(&question_from_codes(qname, qtype, class.value())?)?;
            out.instant(entry.expires_at)?;
            out.u32(entry.hits)?;
            out.flag(entry.authoritative)?;
            out.flag(entry.authenticated)?;
            out.count(entry.authorities.len())?;
            for cached in entry.authorities.iter() {
                out.wire(&cached.record)?;
                out.instant(cached.expires_at)?;
            }
            out.end_entry()?;
        }
        Ok(())
    }
    pub(crate) fn decode_entries(&self, input: &mut Reader<'_>) -> io::Result<()> {
        let count = input.items(self.capacity, 56)?;
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let name_error = input.flag()?;
            let question = input.question()?;
            let QClassType::Class(class) = question.qclass else {
                return Err(invalid());
            };
            let key = if name_error {
                NegativeKey::name(&question.qname, class)
            } else {
                NegativeKey::qtype(&question.qname, question.qtype.value(), class)
            };
            let expires_at = input.instant()?;
            let hits = input.u32()?;
            let authoritative = input.flag()?;
            let authenticated = input.flag()?;
            let records = (0..input.items(65_535, 31)?)
                .map(|_| {
                    Ok(CachedAuthority {
                        record: input.record()?,
                        expires_at: input.instant()?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            if records.is_empty() {
                return Err(invalid());
            }
            values.push(Entry {
                hash: entries.hash_key(&key),
                key,
                authorities: Arc::new(NegativeRecords {
                    records,
                    composed: OnceLock::new(),
                    denial_keys: Mutex::new(None),
                }),
                rcode: if name_error {
                    RCode::NameError
                } else {
                    RCode::Ok
                },
                authoritative,
                authenticated,
                expires_at,
                hits,
                prepared: [const { OnceLock::new() }; 2],
            });
        }
        entries.restore_values(values);
        Ok(())
    }
}
