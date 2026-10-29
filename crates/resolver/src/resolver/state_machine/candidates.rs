use super::*;

impl<T: Transport> Resolver<T> {
    pub(super) async fn prepare_resolution_candidates<'resolver>(
        &'resolver self,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: &Arc<AtomicUsize>,
        stats: &ResolutionStatsContext,
        state: &mut ResolutionState<'resolver>,
    ) -> Result<(), ResolveError> {
        if state.candidates.is_empty() && !state.pending_name_servers.is_empty() {
            self.prepare_delegation_recovery(state).await?;
            let names = std::mem::take(&mut state.pending_name_servers);
            let resolution = self
                .resolve_pending_name_server_addresses(
                    names,
                    resolving_ns_hosts,
                    Arc::clone(remaining_steps),
                    stats.clone(),
                    Arc::clone(&state.algorithm_signals),
                )
                .await;
            state.candidates = resolution.addresses;
            if let Some(error) = resolution.error {
                if matches!(error, ResolveError::CachedNameServerFailure) && state.zone_attempted {
                    // Known candidates actually failed; cached NS dependencies do
                    // not erase that fresh remote evidence or renew their own TTL.
                } else if crate::resolver::address::deferred_address_error(&error) {
                    state.deferred_address_error.get_or_insert(error);
                } else {
                    return Err(error);
                }
            }
            state.pending_name_servers = resolution.pending_name_servers;
            self.prepare_candidates(&mut state.candidates, stats);
        }
        if state.candidates.is_empty()
            && state.restart_from_root
            && self.permit_ancestor_refresh(state).await?
        {
            debug!("cached or learned DNS delegation was exhausted; restarting at root hints");
            state.current_delegation_zone = DomainName::root();
            state.zone_attempted = false;
            state.candidates = self.config.root_servers.clone();
            self.prepare_candidates(&mut state.candidates, stats);
            state.restart_from_root = false;
            state.reachable_dns_error = false;
        }
        if state.candidates.is_empty() {
            if let Some(error) = state.deferred_address_error.take() {
                return Err(error);
            }
            self.finish_failed_delegation_recovery(state).await?;
            debug!("DNS resolution exhausted candidate servers");
            return Err(if state.cname_loop_seen {
                ResolveError::CnameLoop
            } else if state.reachable_dns_error {
                ResolveError::TemporaryServerFailure
            } else {
                ResolveError::NoReachableServer
            });
        }
        Ok(())
    }
}
