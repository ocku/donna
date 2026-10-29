//! Conservative complete-message cache admission and expiry.
use super::*;
use dns::IntoWire;

impl<T: Transport> Forwarder<T> {
    fn key(&self, request: &Message) -> Option<Vec<u8>> {
        if self.capacity == 0
            || request
                .additionals
                .iter()
                .any(|r| r.rtype != RecordType::OPT)
        {
            return None;
        }
        if request
            .edns()
            .ok()
            .flatten()
            .is_some_and(|e| !e.options.is_empty())
        {
            return None;
        }
        let mut message = request.clone();
        message.headers.id = 0;
        // AD is a request signal and must participate in cache identity.
        message.into_wire().ok()
    }

    pub(super) fn cached(&self, request: &Message) -> Option<Message> {
        let key = self.key(request)?;
        let mut cache = self.cache.lock().unwrap();
        let entry = cache.get(&key)?;
        let elapsed = entry.inserted.elapsed();
        if elapsed >= entry.lifetime {
            cache.remove(&key);
            return None;
        }
        let mut response = entry.message.clone();
        for r in response
            .answers
            .iter_mut()
            .chain(&mut response.authorities)
            .chain(&mut response.additionals)
        {
            if r.rtype != RecordType::OPT {
                r.ttl = r.ttl.saturating_sub(elapsed.as_secs() as u32);
            }
        }
        correlate(&mut response, request);
        Some(response)
    }

    pub(super) fn remember(&self, request: &Message, response: &Message) {
        let Some(key) = self.key(request) else {
            return;
        };
        if response.headers.tc
            || !matches!(response.headers.rcode, RCode::Ok | RCode::NameError)
            || response.extended_rcode() > 15
            || response
                .additionals
                .iter()
                .any(|r| r.rtype == RecordType::TSIG)
        {
            return;
        }
        let records = response
            .answers
            .iter()
            .chain(&response.authorities)
            .chain(&response.additionals)
            .filter(|r| r.rtype != RecordType::OPT);
        let Some(mut ttl) = records.map(|r| u64::from(r.ttl)).min() else {
            return;
        };
        ttl = ttl.min(self.max_ttl);
        if let Some(negative_ttl) = response.negative_cache_ttl() {
            ttl = ttl.min(u64::from(negative_ttl)).min(self.max_negative_ttl);
        }
        // Do not retain AD beyond any RRSIG expiration, even if a peer sent
        // an excessive TTL. A clock failure disables admission.
        if response.headers.ad {
            let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
                return;
            };
            for r in response.answers.iter().chain(&response.authorities) {
                if let RData::RRSIG(sig) = &r.rdata {
                    ttl =
                        ttl.min(u64::from(sig.signature_expiration).saturating_sub(now.as_secs()));
                }
            }
        }
        if ttl == 0 {
            return;
        }
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= self.capacity {
            cache.retain(|_, e| e.inserted.elapsed() < e.lifetime);
            if cache.len() >= self.capacity
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.inserted)
                    .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        let mut message = response.clone();
        for r in message
            .answers
            .iter_mut()
            .chain(&mut message.authorities)
            .chain(&mut message.additionals)
        {
            if r.rtype != RecordType::OPT {
                r.ttl = r.ttl.min(ttl as u32);
            }
        }
        cache.insert(
            key,
            Cached {
                message,
                inserted: Instant::now(),
                lifetime: Duration::from_secs(ttl),
            },
        );
    }
}
