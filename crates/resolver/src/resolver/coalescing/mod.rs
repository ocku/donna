use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dns::{Message, Question};
use tokio::sync::watch;

use super::{AlgorithmSignals, ResolutionOutcome, ResolutionStatsContext, Resolver};
use crate::{ResolveError, name::packed_key};
use transport::Transport;

const DISABLED_CACHE_IN_FLIGHT_CAPACITY: usize = 16;
const MAX_IN_FLIGHT_CAPACITY: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct InFlightKey {
    qname: Box<[u8]>,
    qtype: u16,
    qclass: u16,
    algorithm_signals: AlgorithmSignals,
}

impl InFlightKey {
    pub(super) fn new(question: &Question, algorithm_signals: &AlgorithmSignals) -> Self {
        Self {
            qname: packed_key(&question.qname),
            qtype: question.qtype.value(),
            qclass: question.qclass.value(),
            algorithm_signals: algorithm_signals.clone(),
        }
    }
}

type DnameSources = Arc<[super::cache::dname::traversal::CachedDnameSource]>;
type CoalescedReply = (Message, Option<Instant>, DnameSources);

#[derive(Clone)]
enum InFlightState {
    Pending,
    Succeeded(Arc<Message>, Instant, Option<Instant>, DnameSources),
    Failed,
}

/// A follower can be scheduled well after publication. Do not renew any TTL
/// when it clones the leader's reply, and do not alter OPT's TTL-encoded flags.
fn age_response(response: &mut Message, observed_at: Instant, now: Instant) {
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
        .filter(|record| record.rtype != dns::RecordType::OPT)
    {
        let expires = observed_at
            .checked_add(Duration::from_secs(u64::from(record.ttl)))
            .unwrap_or(observed_at);
        record.ttl = expires
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
    }
}

#[cfg(test)]
mod tests;

pub(super) struct InFlightEntry {
    state: watch::Sender<InFlightState>,
}

impl InFlightEntry {
    fn new() -> Self {
        let (state, _) = watch::channel(InFlightState::Pending);
        Self { state }
    }

    async fn wait(&self) -> Option<CoalescedReply> {
        let mut state = self.state.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            match current {
                InFlightState::Pending => {}
                InFlightState::Succeeded(response, observed_at, dname_deadline, sources) => {
                    // Transaction signatures authenticate the original wire
                    // message, including TTLs. Reissue instead of rewriting
                    // a signed transaction for a coalesced follower.
                    if response.additionals.iter().any(|record| {
                        record.rtype == dns::RecordType::TSIG
                            || matches!(&record.rdata, dns::RData::SIG(sig) if sig.is_sig0())
                    }) {
                        return None;
                    }
                    let mut response = (*response).clone();
                    age_response(&mut response, observed_at, Instant::now());
                    return Some((response, dname_deadline, sources));
                }
                InFlightState::Failed => return None,
            }
            if state.changed().await.is_err() {
                return None;
            }
        }
    }
}

pub(super) struct InFlightTable {
    entries: Mutex<HashMap<InFlightKey, Arc<InFlightEntry>>>,
    capacity: usize,
}

impl InFlightTable {
    pub(super) fn new(cache_capacity: usize) -> Self {
        let capacity = if cache_capacity == 0 {
            DISABLED_CACHE_IN_FLIGHT_CAPACITY
        } else {
            cache_capacity.min(MAX_IN_FLIGHT_CAPACITY)
        };
        Self {
            entries: Mutex::new(HashMap::with_capacity(capacity)),
            capacity,
        }
    }

    fn admit(&self, key: InFlightKey) -> Admission<'_> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = entries.get(&key) {
            return Admission::Follower(Arc::clone(entry));
        }
        if entries.len() >= self.capacity {
            return Admission::Bypass;
        }

        let entry = Arc::new(InFlightEntry::new());
        entries.insert(key.clone(), Arc::clone(&entry));
        Admission::Leader(InFlightLeader {
            table: self,
            key: Some(key),
            entry,
        })
    }

    #[cfg(test)]
    pub(super) fn participant_count(&self, question: &Question) -> usize {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries
            .get(&InFlightKey::new(question, &AlgorithmSignals::default()))
            .map_or(0, Arc::strong_count)
    }

    #[cfg(test)]
    pub(super) fn active_len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    fn remove_exact(&self, key: &InFlightKey, entry: &Arc<InFlightEntry>) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(key);
        }
    }
}

enum Admission<'a> {
    Leader(InFlightLeader<'a>),
    Follower(Arc<InFlightEntry>),
    Bypass,
}

struct InFlightLeader<'a> {
    table: &'a InFlightTable,
    key: Option<InFlightKey>,
    entry: Arc<InFlightEntry>,
}

impl InFlightLeader<'_> {
    fn succeed(
        mut self,
        response: &Message,
        dname_deadline: Option<Instant>,
        sources: &[super::cache::dname::traversal::CachedDnameSource],
    ) {
        let observed_at = Instant::now();
        let completed = InFlightState::Succeeded(
            Arc::new(response.clone()),
            observed_at,
            dname_deadline,
            sources.into(),
        );
        let key = self.key.take().expect("in-flight leader key is present");
        // Publish while the entry is still discoverable. Removing it first
        // creates a window in which a duplicate caller can become a leader
        // before existing followers have observed the completed result.
        self.entry.state.send_replace(completed);
        self.table.remove_exact(&key, &self.entry);
    }
}

impl Drop for InFlightLeader<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.entry.state.send_replace(InFlightState::Failed);
            self.table.remove_exact(&key, &self.entry);
        }
    }
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn resolve_coalesced(
        &self,
        question: Question,
        stats: ResolutionStatsContext,
        mut algorithm_signals: Arc<AlgorithmSignals>,
        checking_disabled: bool,
    ) -> Result<(ResolutionOutcome, bool), ResolveError> {
        Arc::make_mut(&mut algorithm_signals).checking_disabled = checking_disabled;
        loop {
            let (cached, history) = self
                .cached_resolution_failure(&question, checking_disabled)
                .await?;
            if let Some(error) = cached {
                return Err(error);
            }
            let key = InFlightKey::new(&question, &algorithm_signals);
            match self.in_flight.admit(key) {
                Admission::Leader(leader) => {
                    if let Some(stats) = stats.as_ref() {
                        stats.increment_coalesced_leaders();
                    }
                    let result = self
                        .resolve_iteratively(
                            question.clone(),
                            stats.clone(),
                            Arc::clone(&algorithm_signals),
                            true,
                        )
                        .await;
                    if let Err(error) = &result {
                        self.record_resolution_failure(&question, checking_disabled, error)
                            .await?;
                    }
                    if let Ok(outcome) = &result {
                        leader.succeed(
                            &outcome.response,
                            outcome.dname_deadline,
                            &outcome.cached_dnames,
                        );
                    }
                    return result.map(|outcome| (outcome, history));
                }
                Admission::Follower(entry) => {
                    if let Some(stats) = stats.as_ref() {
                        stats.increment_coalesced_followers();
                    }
                    let started = Instant::now();
                    let response = entry.wait().await;
                    if let Some(stats) = stats.as_ref() {
                        stats.add_coalesced_wait(started.elapsed());
                    }
                    if let Some((mut response, dname_deadline, cached_dnames)) = response {
                        response.questions = vec![question.clone()];
                        return Ok((
                            ResolutionOutcome {
                                response,
                                cache_source: None,
                                dname_deadline,
                                cached_dnames: cached_dnames.to_vec(),
                            },
                            history,
                        ));
                    }
                }
                Admission::Bypass => {
                    let result = self
                        .resolve_iteratively(question.clone(), stats, algorithm_signals, true)
                        .await;
                    if let Err(error) = &result {
                        self.record_resolution_failure(&question, checking_disabled, error)
                            .await?;
                    }
                    return result.map(|outcome| (outcome, history));
                }
            }
        }
    }
}
