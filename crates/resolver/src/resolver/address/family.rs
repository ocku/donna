use super::*;
use crate::{ResolveError, cache::failure::FailureKind, response::cname_restart};

pub(in crate::resolver) fn deferred(error: &ResolveError) -> bool {
    matches!(
        error,
        ResolveError::DelegationRefreshInProgress
            | ResolveError::CachedDelegationFailure
            | ResolveError::CachedNameServerFailure
    )
}
fn split(
    result: Result<Vec<SocketAddr>, ResolveError>,
) -> Result<(Vec<SocketAddr>, Option<ResolveError>), ResolveError> {
    match result {
        Ok(addresses) => Ok((addresses, None)),
        Err(error) if deferred(&error) => Ok((vec![], Some(error))),
        Err(error) => Err(error),
    }
}
fn merge<'a>(
    first: Option<ResolveError>,
    second: Result<Vec<SocketAddr>, ResolveError>,
) -> Result<(Vec<SocketAddr>, Option<PendingNameServer<'a>>), ResolveError> {
    let (addresses, error) = split(second)?;
    if addresses.is_empty()
        && let Some(error) = first.or(error)
    {
        return Err(error);
    }
    Ok((addresses, None))
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn resolve_name_server_work<'a>(
        &'a self,
        mut work: PendingNameServer<'a>,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
    ) -> Result<(Vec<SocketAddr>, Option<PendingNameServer<'a>>), ResolveError> {
        if let Some(suspended) = work.suspended.take() {
            return suspended.resume().await.map(|a| (a, None));
        }
        match work.families {
            NameServerAddressFamilies::A | NameServerAddressFamilies::Aaaa => {
                let qtype = if matches!(work.families, NameServerAddressFamilies::A) {
                    QueryType::A
                } else {
                    QueryType::AAAA
                };
                self.name_server_family_future(
                    work.name,
                    qtype,
                    resolving_ns_hosts.to_vec(),
                    remaining_steps,
                    stats,
                    algorithm_signals,
                )
                .await
                .map(|a| (a, None))
            }
            NameServerAddressFamilies::Both => {
                let name_server = work.name;
                let mut preferred = self.name_server_family_future(
                    name_server.clone(),
                    QueryType::A,
                    resolving_ns_hosts.to_vec(),
                    Arc::clone(&remaining_steps),
                    stats.clone(),
                    Arc::clone(&algorithm_signals),
                );
                let stagger = tokio::time::sleep(NAME_SERVER_FAMILY_STAGGER);
                tokio::pin!(stagger);
                tokio::select! { biased;
                    result=&mut preferred => {
                        let (addresses,error)=split(result)?;
                        if !addresses.is_empty() { return Ok((addresses,Some(PendingNameServer::marker(name_server,NameServerAddressFamilies::Aaaa)))); }
                        return merge(error,self.name_server_family_future(name_server,QueryType::AAAA,resolving_ns_hosts.to_vec(),
                            remaining_steps,stats,algorithm_signals).await);
                    }
                    ()=&mut stagger=>{}
                }
                if let Some(stats) = &stats {
                    stats.increment_name_server_family_races();
                }
                let mut alternate = self.name_server_family_future(
                    name_server.clone(),
                    QueryType::AAAA,
                    resolving_ns_hosts.to_vec(),
                    remaining_steps,
                    stats.clone(),
                    Arc::clone(&algorithm_signals),
                );
                tokio::select! { biased;
                    result=&mut preferred=>{
                        let (addresses,error)=split(result)?;
                        if addresses.is_empty() { merge(error,alternate.await) } else {
                            Ok((addresses,Some(PendingNameServer { name:name_server,families:NameServerAddressFamilies::Aaaa,
                                suspended:Some(SuspendedFamilyLookup { future:Some(alternate),stats }) })))
                        }
                    }
                    result=&mut alternate=>{
                        let (addresses,error)=split(result)?;
                        if addresses.is_empty() { merge(error,preferred.await) } else {
                            Ok((addresses,Some(PendingNameServer { name:name_server,families:NameServerAddressFamilies::A,
                                suspended:Some(SuspendedFamilyLookup { future:Some(preferred),stats }) })))
                        }
                    }
                }
            }
        }
    }

    fn name_server_family_future<'a>(
        &'a self,
        name_server: DomainName,
        qtype: QueryType,
        resolving_ns_hosts: Vec<DomainName>,
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
    ) -> NameServerFamilyFuture<'a> {
        Box::pin(async move {
            self.resolve_name_server_family(
                name_server,
                qtype,
                resolving_ns_hosts,
                remaining_steps,
                stats,
                algorithm_signals,
            )
            .await
        })
    }

    async fn resolve_name_server_family(
        &self,
        name_server: DomainName,
        qtype: QueryType,
        mut resolving_ns_hosts: Vec<DomainName>,
        remaining_steps: Arc<AtomicUsize>,
        stats: ResolutionStatsContext,
        algorithm_signals: Arc<AlgorithmSignals>,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        if remaining_steps.load(Ordering::Relaxed) == 0 {
            return Err(ResolveError::WorkLimitExceeded);
        }
        resolving_ns_hosts.push(name_server.clone());
        let address_question = Question {
            qname: name_server.clone(),
            qtype,
            // NS RR class does not identify its contact protocol family (RFC1035§3.3.11).
            qclass: QClassType::Class(dns::ClassType::IN),
        };
        if let Some(stats) = &stats {
            stats.increment_name_server_lookups();
        }
        let cd = algorithm_signals.checking_disabled;
        let outcome = match Box::pin(self.resolve_inner(
            address_question.clone(),
            resolving_ns_hosts,
            remaining_steps,
            stats,
            algorithm_signals,
            false,
        ))
        .await
        {
            Ok(outcome) => outcome,
            Err(error) if FailureKind::from_error(&error).is_none() => return Err(error),
            Err(error) => {
                self.record_resolution_failure(&address_question, cd, &error)
                    .await?;
                return Ok(vec![]);
            }
        };
        self.clear_resolved_failure(&address_question, cd).await?;
        let owner = cname_restart(&outcome.response.answers, &address_question)
            .ok()
            .flatten()
            .map(|(_, target)| target)
            .unwrap_or(name_server);
        Ok(outcome
            .response
            .answers
            .iter()
            .filter_map(|record| {
                if record.class != dns::ClassType::IN || !record.name.eq_dns(&owner) {
                    return None;
                }
                match (&record.rdata, qtype) {
                    (RData::A(a), QueryType::A) => Some(SocketAddr::from((*a, 53))),
                    (RData::AAAA(a), QueryType::AAAA) => Some(SocketAddr::from((*a, 53))),
                    _ => None,
                }
            })
            .collect())
    }
}
