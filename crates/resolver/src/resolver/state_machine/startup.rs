use super::*;

impl<T: Transport> Resolver<T> {
    pub(super) async fn seed_resolution(
        &self,
        question: &Question,
        address_lookup: bool,
        checking_disabled: bool,
        cache_allowed: bool,
    ) -> Result<ControlFlow<ResolutionOutcome, ResolutionSeed>, ResolveError> {
        if !cache_allowed {
            return Ok(ControlFlow::Continue(ResolutionSeed {
                active_question: question.clone(),
                cname_answers: Vec::new(),
                cname_authorities: Vec::new(),
                cname_names: NameSet::from_name(&question.qname),
            }));
        }
        let ns_failure_cd = address_lookup.then_some(checking_disabled);
        match self
            .cached_resolution_backend(
                question,
                question.clone(),
                Vec::new(),
                Vec::new(),
                NameSet::from_name(&question.qname),
                ns_failure_cd,
            )
            .await?
        {
            CachedResolution::Negative(_) => {
                unreachable!("negative encoding requires explicit UDP request context")
            }
            CachedResolution::Positive(selected) => Ok(ControlFlow::Break(ResolutionOutcome {
                response: selected.into_message(),
                cache_source: Some(ResolutionCacheSource::Positive),
                dname_deadline: None,
                cached_dnames: Vec::new(),
            })),
            CachedResolution::Complete { reply, source } => {
                Ok(ControlFlow::Break(ResolutionOutcome {
                    response: reply,
                    cache_source: Some(source),
                    dname_deadline: None,
                    cached_dnames: Vec::new(),
                }))
            }
            CachedResolution::Continue {
                active_question,
                cname_answers,
                cname_authorities,
                cname_names,
            } => Ok(ControlFlow::Continue(ResolutionSeed {
                active_question,
                cname_answers,
                cname_authorities,
                cname_names,
            })),
        }
    }

    pub(super) async fn prepare_resolution<'resolver>(
        &'resolver self,
        question: &Question,
        remaining_steps: &Arc<AtomicUsize>,
        stats: &ResolutionStatsContext,
        state: &mut ResolutionState<'resolver>,
    ) -> Result<Option<ResolutionOutcome>, ResolveError> {
        let observed_at = std::time::Instant::now();
        state
            .proof_deadlines
            .observe(&state.cname_answers, observed_at);
        state
            .proof_deadlines
            .observe(&state.cname_authorities, observed_at);
        if state.validated_dnames_allowed
            && let CachedDnameProgress::Complete(response) = self
                .follow_cached_dnames(CachedDnameContext {
                    original: question,
                    active: &mut state.active_question,
                    answers: &mut state.cname_answers,
                    authorities: &mut state.cname_authorities,
                    names: &mut state.cname_names,
                    deadlines: &mut state.proof_deadlines,
                    remaining: remaining_steps,
                    fresh_cut: None,
                })
                .await?
        {
            return Ok(Some(ResolutionOutcome {
                response,
                cache_source: Some(ResolutionCacheSource::Positive),
                dname_deadline: state.proof_deadlines.deadline(),
                cached_dnames: state.proof_deadlines.cached_dnames(),
            }));
        }
        if !state.cache_allowed
            && state.address_lookup
            && self
                .name_server_failure_cached(
                    &state.active_question,
                    state.algorithm_signals.checking_disabled,
                )
                .await?
        {
            return Err(ResolveError::CachedNameServerFailure);
        }
        let (zone, mut candidates, pending, restart) = self
            .candidates_for(
                &state.active_question,
                state.algorithm_signals.checking_disabled,
            )
            .await?;
        self.prepare_candidates(&mut candidates, stats);
        state.current_delegation_zone = zone;
        state.candidates = candidates;
        state.pending_name_servers = pending;
        state.restart_from_root = restart;
        state.used_cached_delegation = restart;
        Ok(None)
    }
}
