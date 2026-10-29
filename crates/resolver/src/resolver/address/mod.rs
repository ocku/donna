mod family;
pub(super) use family::deferred as deferred_address_error;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use dns::{DomainName, QClassType, QueryType, Question, RData};
use tracing::debug;
use transport::Transport;

use crate::ResolveError;

use super::{AlgorithmSignals, ResolutionStatsContext, Resolver};

const MAX_NS_ADDRESS_RESOLUTION_DEPTH: usize = 16;
/// Delay before an unresolved preferred-family lookup starts its alternate.
const NAME_SERVER_FAMILY_STAGGER: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NameServerAddressFamilies {
    A,
    Aaaa,
    Both,
}

type NameServerFamilyFuture<'resolver> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, ResolveError>> + Send + 'resolver>>;

struct SuspendedFamilyLookup<'resolver> {
    future: Option<NameServerFamilyFuture<'resolver>>,
    stats: ResolutionStatsContext,
}

impl SuspendedFamilyLookup<'_> {
    async fn resume(mut self) -> Result<Vec<SocketAddr>, ResolveError> {
        self.future
            .take()
            .expect("suspended family lookup is resumed only once")
            .await
    }
}

impl Drop for SuspendedFamilyLookup<'_> {
    fn drop(&mut self) {
        if self.future.is_some()
            && let Some(stats) = &self.stats
        {
            stats.increment_canceled_name_server_family_lookups();
        }
    }
}

pub(super) struct PendingNameServer<'resolver> {
    pub(super) name: DomainName,
    pub(super) families: NameServerAddressFamilies,
    suspended: Option<SuspendedFamilyLookup<'resolver>>,
}

impl PendingNameServer<'_> {
    pub(super) fn both(name: DomainName) -> Self {
        Self::marker(name, NameServerAddressFamilies::Both)
    }

    fn marker(name: DomainName, families: NameServerAddressFamilies) -> Self {
        Self {
            name,
            families,
            suspended: None,
        }
    }

    pub(super) fn is_suspended(&self) -> bool {
        self.suspended.is_some()
    }
}

pub(super) struct NameServerAddressResolution<'resolver> {
    pub(super) addresses: Vec<SocketAddr>,
    pub(super) error: Option<ResolveError>,
    pub(super) pending_name_servers: Vec<PendingNameServer<'resolver>>,
}

impl<'resolver> NameServerAddressResolution<'resolver> {
    fn complete(
        mut addresses: Vec<SocketAddr>,
        pending_name_servers: impl IntoIterator<Item = PendingNameServer<'resolver>>,
        resolving_ns_hosts: &[DomainName],
    ) -> Self {
        addresses.sort_unstable();
        addresses.dedup();
        let pending_name_servers = pending_name_servers
            .into_iter()
            .filter(|work| {
                !resolving_ns_hosts
                    .iter()
                    .any(|resolving| resolving.eq_dns(&work.name))
            })
            .collect();
        Self {
            addresses,
            pending_name_servers,
            error: None,
        }
    }

    fn empty() -> Self {
        Self {
            addresses: Vec::new(),
            pending_name_servers: Vec::new(),
            error: None,
        }
    }
}

impl<T: Transport> Resolver<T> {
    pub(super) fn prepare_candidates(
        &self,
        candidates: &mut Vec<SocketAddr>,
        stats: &ResolutionStatsContext,
    ) {
        self.server_metrics
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .prepare_candidates(candidates, stats);
    }

    pub(super) async fn resolve_name_server_addresses<'resolver>(
        &'resolver self,
        name_servers: &[DomainName],
        resolving_ns_hosts: &[DomainName],
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
    ) -> NameServerAddressResolution<'resolver> {
        let pending = name_servers
            .iter()
            .cloned()
            .map(PendingNameServer::both)
            .collect();
        self.resolve_pending_name_server_addresses(
            pending,
            resolving_ns_hosts,
            remaining_steps,
            stats,
            algorithm_signals,
        )
        .await
    }

    pub(super) async fn resolve_pending_name_server_addresses<'resolver>(
        &'resolver self,
        pending: Vec<PendingNameServer<'resolver>>,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
    ) -> NameServerAddressResolution<'resolver> {
        if resolving_ns_hosts.len() >= MAX_NS_ADDRESS_RESOLUTION_DEPTH {
            let mut exhausted = NameServerAddressResolution::empty();
            exhausted.error = Some(ResolveError::WorkLimitExceeded);
            return exhausted;
        }

        let mut pending = pending.into_iter();
        let mut deferred_error = None;
        while let Some(work) = pending.next() {
            if resolving_ns_hosts
                .iter()
                .any(|resolving| resolving.eq_dns(&work.name))
            {
                continue;
            }
            if remaining_steps.load(Ordering::Relaxed) == 0 && !work.is_suspended() {
                return NameServerAddressResolution::complete(
                    Vec::new(),
                    pending,
                    resolving_ns_hosts,
                );
            }

            let result = self
                .resolve_name_server_work(
                    work,
                    resolving_ns_hosts,
                    Arc::clone(&remaining_steps),
                    stats.clone(),
                    Arc::clone(&algorithm_signals),
                )
                .await;
            let (addresses, deferred) = match result {
                Ok(value) => value,
                Err(error) if family::deferred(&error) => {
                    deferred_error = Some(error);
                    continue;
                }
                Err(error) => {
                    let mut failed = NameServerAddressResolution::empty();
                    failed.error = Some(error);
                    return failed;
                }
            };
            if !addresses.is_empty() {
                return NameServerAddressResolution::complete(
                    addresses,
                    deferred.into_iter().chain(pending),
                    resolving_ns_hosts,
                );
            }
        }
        let mut result = NameServerAddressResolution::complete(Vec::new(), [], resolving_ns_hosts);
        result.error = deferred_error;
        result
    }

    pub(super) async fn candidates_for(
        &self,
        question: &Question,
        checking_disabled: bool,
    ) -> Result<
        (
            DomainName,
            Vec<SocketAddr>,
            Vec<PendingNameServer<'_>>,
            bool,
        ),
        crate::ResolveError,
    > {
        let select = |context: &Self| {
            if context
                .delegation_cache
                .failed_without_routes(question, checking_disabled)
            {
                return Err(crate::ResolveError::CachedDelegationFailure);
            }
            Ok(context.delegation_cache.get(question))
        };
        let delegation = if self.uses_external_cache() && self.config.cache_capacity > 0 {
            // Routes, individual glue addresses and failure tombstones retain
            // absolute deadlines. A remote commit can outlive any of them;
            // reselect from its detached context before using the result.
            let (_, context) = self
                .cache_transaction_with_context_for(std::slice::from_ref(question), |context| {
                    Ok(select(context))
                })
                .await?;
            select(&context.expect("external transaction returns its context"))?
        } else {
            select(self)?
        };
        Ok(match delegation {
            Some(delegation) => {
                debug!(
                    qname = ?question.qname,
                    zone = ?delegation.zone,
                    candidate_count = delegation.candidates.len(),
                    name_server_count = delegation.name_servers.len(),
                    "starting from cached DNS delegation"
                );
                let pending_name_servers = delegation
                    .name_servers
                    .into_iter()
                    .map(PendingNameServer::both)
                    .collect();
                (
                    delegation.zone,
                    delegation.candidates,
                    pending_name_servers,
                    true,
                )
            }
            None => (
                DomainName::root(),
                self.config.root_servers.clone(),
                Vec::new(),
                false,
            ),
        })
    }
}

#[cfg(test)]
mod tests;
