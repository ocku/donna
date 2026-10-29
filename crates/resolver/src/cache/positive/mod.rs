mod codec;
mod policy;
mod rrset_comparison;
mod selected;
mod storage;
pub(crate) use selected::{ComposedPositive, SelectedPositive, SelectionIdentity};

use std::{
    collections::{HashMap, hash_map::Entry as MapEntry},
    hash::{BuildHasher, Hash, Hasher, RandomState},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use tracing::{debug, instrument, warn};

use dns::{Message, Question, RecordType, ResourceRecord};

#[cfg(test)]
use dns::{Headers, OpCode, RCode};

use crate::name::PackedName;
pub(crate) use policy::query_types_overlap;
use policy::{PackedResponse, cacheable_question, is_cacheable, requested_answers, response_ttl};
use storage::{CacheKey, Entries, Entry, OwnerData};

pub(crate) struct PositiveCache {
    capacity: usize,
    key_hasher: RandomState,
    entries: Mutex<Entries>,
    // A false value proves no authenticated DNAME has been admitted. It may
    // remain true after eviction, but never hides a live cache entry.
    maybe_authenticated_dname: AtomicBool,
}

pub(crate) enum CachedPositiveUdp {
    Encoded(dns::wire::EncodedReply),
    Message(Message),
}

impl PositiveCache {
    /// Creates a cache holding at most `capacity` complete positive responses.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            key_hasher: RandomState::new(),
            entries: Mutex::new(Entries::with_capacity(capacity)),
            maybe_authenticated_dname: AtomicBool::new(false),
        }
    }

    /// Returns a response for `query` when it is still fresh.
    ///
    /// The cached reply's transaction-specific header fields and question are
    /// rebuilt from `query`, so cached data cannot leak another client's ID or
    /// recursion-desired bit.
    #[instrument(
        level = "debug",
        skip(self, query),
        fields(transaction_id = query.headers.id, question_count = query.questions.len())
    )]
    #[cfg(test)]
    pub(crate) fn get(&self, query: &Message) -> Option<Message> {
        let Some(question) = cacheable_question(query) else {
            debug!("cache lookup skipped for a non-cacheable question");
            return None;
        };
        self.get_inner(question, &query.headers)
    }

    /// Returns a response for the resolver's standard query shape.
    ///
    /// This avoids constructing a throwaway [`Message`] for internal cache
    /// lookups. Resolver queries always use the default query header fields.
    pub(crate) fn get_question(&self, question: &Question) -> Option<Message> {
        self.get_inner(question, &dns::Headers::default())
    }

    /// Retains immutable admitted data after the cache mutex is released.
    /// The lookup, expiry check and popularity touch are identical to get_question.
    pub(crate) fn select_question(&self, question: &Question) -> Option<SelectedPositive> {
        self.with_entry(question, SelectedPositive::new)
    }

    /// Rechecks transaction provenance without counting a second client use.
    pub(crate) fn retain_question(
        &self,
        question: &Question,
        identity: &selected::SelectionIdentity,
    ) -> Option<SelectedPositive> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let index = self.find_question(&entries, question)?;
        let now = Instant::now();
        if entries.values[index].expires_at <= now {
            return None;
        }
        let selected = SelectedPositive::new(&entries.values[index], now);
        selected.matches_identity(identity).then_some(selected)
    }

    fn get_inner(&self, question: &Question, query_headers: &dns::Headers) -> Option<Message> {
        self.with_entry(question, |entry, now| {
            entry.response.to_message(
                question,
                query_headers,
                entry.expires_at.saturating_duration_since(now),
                entry.authenticated,
            )
        })
    }

    pub(crate) fn get_udp(
        &self,
        request: &Message,
        maximum: usize,
        validating: bool,
    ) -> Option<CachedPositiveUdp> {
        let [question] = request.questions.as_slice() else {
            return None;
        };
        // Variant selection is only a hint. The checked renderer still validates
        // the complete request and its OPT before returning an encoded reply.
        let dnssec_ok = matches!(request.additionals.as_slice(),
            [opt] if opt.rtype == RecordType::OPT && opt.ttl & 0x8000 != 0);
        self.with_entry(question, |entry, now| {
            // Two bounded lazy variants: DNSSEC retained and client-filtered.
            // The latter also serves classic DNS by omitting the final OPT.
            let prepared = entry.prepared[usize::from(dnssec_ok)].get_or_init(|| {
                if entry.response.answers.len() + entry.response.authorities.len() > 64 {
                    return None;
                }
                let mut prototype = entry.response.to_message(
                    question,
                    &dns::Headers::default(),
                    entry.expires_at.saturating_duration_since(now),
                    entry.authenticated,
                );
                prototype.headers.rd = true;
                prototype.headers.ra = true;
                let retain = |record: &ResourceRecord| {
                    crate::response::requested_dnssec_record(
                        record.rtype,
                        Some(question.qtype.value()),
                        dnssec_ok,
                    )
                };
                prototype.answers.retain(retain);
                prototype.authorities.retain(retain);
                prototype.additionals.push(
                    dns::Edns {
                        dnssec_ok,
                        ..dns::Edns::default()
                    }
                    .into_record(),
                );
                dns::wire::PreparedPositiveReply::from_message(&prototype)
                    .ok()
                    .flatten()
                    .map(Box::new)
            });
            let now = Instant::now();
            if entry.expires_at <= now {
                return None;
            }
            let remaining = entry.expires_at.saturating_duration_since(now);
            let ttl = remaining.as_secs().min(u64::from(u32::MAX)) as u32;
            if let Some(prepared) = prepared
                && let Some(reply) = prepared.render(request, ttl, maximum, validating)
            {
                return Some(CachedPositiveUdp::Encoded(reply));
            }
            Some(CachedPositiveUdp::Message(entry.response.to_message(
                question,
                &dns::Headers::default(),
                remaining,
                entry.authenticated,
            )))
        })
        .flatten()
    }

    fn with_entry<R>(
        &self,
        question: &Question,
        project: impl FnOnce(&Entry, Instant) -> R,
    ) -> Option<R> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let cache_entries = entries.values.len();
        let Some(index) = self.find_question(&entries, question) else {
            debug!(cache_entries, "DNS response cache miss");
            return None;
        };
        if entries.values[index].expires_at <= now {
            debug!(cache_entries, "DNS response cache entry expired");
            entries.remove(index);
            return None;
        }
        entries.touch(index);
        let entry = &entries.values[index];
        let response = project(entry, now);
        debug!(cache_entries, hits = entry.hits, "DNS response cache hit");
        Some(response)
    }

    fn find_question(&self, entries: &Entries, question: &Question) -> Option<usize> {
        let fallback = || entries.find_question(self.hash_question(question), question);
        if question.is_wire_canonical() {
            let packed = PackedName::new(&question.qname);
            return entries
                .with_owner_bucket(packed.as_ref(), |bucket| {
                    if bucket.len() <= 8 {
                        bucket.iter().copied().find(|&index| {
                            let key = &entries.values[index].key;
                            key.qtype == u16::from(question.qtype)
                                && key.qclass == question.qclass.value()
                        })
                    } else {
                        fallback()
                    }
                })
                .flatten();
        }
        // Noncanonical enum spellings retain the existing full hash/equality.
        fallback()
    }

    /// Stores the requested answer path from a cacheable reply.
    ///
    /// `max_ttl` bounds the entry lifetime. Wildcard denial proofs remain in
    /// authority data; unrelated records are not retained.
    #[cfg(test)]
    pub(crate) fn insert(&self, query: &Message, reply: &Message, max_ttl: Duration) -> bool {
        self.insert_at(query, reply, max_ttl, Instant::now(), None)
    }

    #[instrument(
        level = "debug",
        skip(self, query, reply, observed_at, not_after),
        fields(
            transaction_id = query.headers.id,
            question_count = query.questions.len(),
            answer_count = reply.answers.len(),
            authority_count = reply.authorities.len(),
            additional_count = reply.additionals.len()
        )
    )]
    pub(crate) fn insert_at(
        &self,
        query: &Message,
        reply: &Message,
        max_ttl: Duration,
        observed_at: Instant,
        not_after: Option<Instant>,
    ) -> bool {
        let Some(question) = cacheable_question(query) else {
            debug!("cache store skipped for a non-cacheable question");
            return false;
        };
        if !is_cacheable(query, reply, question) || self.capacity == 0 {
            debug!(capacity = self.capacity, "DNS response is not cacheable");
            return false;
        }
        let Some((answers, direct)) = requested_answers(question, &reply.answers) else {
            debug!("DNS response contains no complete requested answer path");
            return false;
        };
        if !direct {
            debug!("composite CNAME responses are cached as independent RRsets");
            return false;
        }
        let authoritative = reply.headers.aa;
        let authorities = crate::response::wildcard_proofs(reply, &answers);
        let mut selected = Message {
            headers: reply.headers.clone(),
            questions: vec![question.clone()],
            answers,
            authorities,
            additionals: Vec::new(),
        };
        if authoritative {
            normalize_rrset_ttls(&mut selected.answers);
        }
        if selected.validate_for_forwarding().is_err() {
            warn!("selected DNS response failed validation and was not cached");
            return false;
        }
        let Some(ttl) = response_ttl(&selected.answers)
            .map(|ttl| {
                response_ttl(&selected.authorities).map_or(ttl, |proof_ttl| ttl.min(proof_ttl))
            })
            .map(|ttl| ttl.min(max_ttl))
            .filter(|ttl| !ttl.is_zero())
        else {
            debug!("DNS response has no positive effective TTL and was not cached");
            return false;
        };
        let owner_data = owner_data(question, &selected.answers);
        let response = Arc::new(PackedResponse::from_records(
            selected.answers,
            selected.authorities,
        ));
        let now = Instant::now();
        let Some(mut expires_at) = observed_at.checked_add(ttl) else {
            return false;
        };
        if let Some(not_after) = not_after {
            expires_at = expires_at.min(not_after);
        }
        if expires_at <= now {
            return false;
        }
        let key = CacheKey::new(question);
        let hash = self.hash_question(question);
        let entry = Entry {
            hash,
            expires_at,
            hits: 0,
            authoritative,
            authenticated: reply.headers.ad,
            owner_data,
            key,
            response,
            prepared: [const { OnceLock::new() }; 2],
        };

        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // The thread may have waited for this lock past the packet deadline.
        // Never let an already-expired insertion evict a live entry.
        let now = Instant::now();
        if expires_at <= now {
            return false;
        }
        entries.remove_expired(now);
        let accepted = entries.insert(entry, self.capacity);
        if accepted {
            if question.qtype.value() == u16::from(RecordType::DNAME) && reply.headers.ad {
                self.maybe_authenticated_dname
                    .store(true, Ordering::Release);
            }
            debug!(
                cache_entries = entries.values.len(),
                ttl_seconds = ttl.as_secs(),
                "DNS response cached"
            );
        } else {
            debug!("lower-trust DNS response did not replace cached response");
        }
        accepted
    }

    pub(crate) fn may_have_authenticated_dname(&self) -> bool {
        self.maybe_authenticated_dname.load(Ordering::Acquire)
    }

    /// Reports whether positive data conflicts with NXDOMAIN.
    pub(crate) fn has_name(&self, question: &Question) -> bool {
        let key = CacheKey::new(question);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(Instant::now());
        entries.has_name(&key)
    }

    /// Reports whether positive data conflicts with NODATA.
    pub(crate) fn has_nodata_conflict(&self, question: &Question) -> bool {
        let key = CacheKey::new(question);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(Instant::now());
        entries.has_nodata_conflict(&key)
    }

    /// Removes all positive data at the question's owner and class.
    pub(crate) fn remove_name(&self, question: &Question) {
        let key = CacheKey::new(question);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(Instant::now());
        entries.remove_name(&key);
    }

    /// Removes exact-type and CNAME data contradicted by NODATA.
    pub(crate) fn remove_nodata_conflicts(&self, question: &Question) {
        let key = CacheKey::new(question);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.remove_expired(Instant::now());
        entries.remove_nodata_conflicts(&key);
    }

    fn hash_question(&self, question: &Question) -> u64 {
        let mut hasher = self.key_hasher.build_hasher();
        question.qname.hash(&mut hasher);
        question.qtype.hash(&mut hasher);
        question.qclass.hash(&mut hasher);
        hasher.finish()
    }
}

fn normalize_rrset_ttls(records: &mut [ResourceRecord]) {
    let mut set_indexes = HashMap::with_capacity(records.len());
    let mut minimum_ttls = Vec::with_capacity(records.len());
    let mut record_set_indexes = Vec::with_capacity(records.len());
    for record in records.iter() {
        if u16::from(record.rtype) == 46 {
            record_set_indexes.push(None);
            continue;
        }
        let next_index = minimum_ttls.len();
        let set_index = match set_indexes.entry((record.name.clone(), record.rtype, record.class)) {
            MapEntry::Occupied(entry) => *entry.get(),
            MapEntry::Vacant(entry) => {
                entry.insert(next_index);
                minimum_ttls.push(record.ttl);
                next_index
            }
        };
        minimum_ttls[set_index] = minimum_ttls[set_index].min(record.ttl);
        record_set_indexes.push(Some(set_index));
    }
    for (record, set_index) in records.iter_mut().zip(record_set_indexes) {
        if let Some(set_index) = set_index {
            record.ttl = minimum_ttls[set_index];
        }
    }
}

fn owner_data(question: &Question, answers: &[ResourceRecord]) -> OwnerData {
    if answers
        .iter()
        .any(|record| record.name.eq_dns(&question.qname) && record.rtype == RecordType::CNAME)
    {
        OwnerData::Cname
    } else if answers
        .iter()
        .any(|record| record.name.eq_dns(&question.qname) && !record.rtype.is_cname_companion())
    {
        OwnerData::Ordinary
    } else {
        OwnerData::Companion
    }
}

#[cfg(test)]
mod tests;
