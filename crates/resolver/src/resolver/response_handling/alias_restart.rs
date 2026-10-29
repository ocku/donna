use super::*;

struct AliasChain {
    records: Vec<dns::ResourceRecord>,
    target: dns::DomainName,
    wildcard_proofs: Vec<dns::ResourceRecord>,
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn restart_response_alias<'r>(
        &'r self,
        context: ResponseContext<'_>,
        reply: Message,
        chain: (Vec<dns::ResourceRecord>, dns::DomainName, Question),
        received_at: std::time::Instant,
        state: &mut ResolutionState<'r>,
    ) -> Result<ResponseAction, ResolveError> {
        let original_question = context.original_question;
        let remaining_steps = &context.remaining_steps;
        let (chain_records, target, target_question) = chain;

        let wildcard_proofs = crate::response::wildcard_proofs(&reply, &chain_records);
        state.proof_deadlines.observe(&chain_records, received_at);
        state.proof_deadlines.observe(&wildcard_proofs, received_at);
        self.record_delegation_success(state).await?;
        state.deferred_address_error = None;
        let mut referral_reply = reply.clone();
        referral_reply.answers.clear();
        if applicable_child_delegation(
            &referral_reply,
            &target_question,
            &state.current_delegation_zone,
        )
        .is_some()
        {
            // AA applies to the retained CNAME at the parent, not to the
            // child-side referral. With the answer removed, parse the
            // authority/additional sections as the referral they carry.
            referral_reply.headers.aa = false;
        }
        let mut target_referral = referral(&referral_reply, &target_question);
        if !self
            .retain_alias_response(
                &context,
                &reply,
                AliasChain {
                    records: chain_records,
                    target,
                    wildcard_proofs,
                },
                received_at,
                state,
            )
            .await?
        {
            return Ok(ResponseAction::ContinueRound);
        }
        if state.cache_allowed
            && let Some(action) = self.cached_alias_response(original_question, state).await?
        {
            return Ok(action);
        }
        if state.validated_dnames_allowed {
            // The cached-DNAME lookup can await a remote backend. Retain
            // the prior alias and proof deadlines before that await, even
            // when this packet itself contained only an ordinary CNAME.
            state
                .proof_deadlines
                .observe(&state.cname_answers, received_at);
            state
                .proof_deadlines
                .observe(&state.cname_authorities, received_at);
            match self
                .follow_cached_dnames(CachedDnameContext {
                    original: original_question,
                    active: &mut state.active_question,
                    answers: &mut state.cname_answers,
                    authorities: &mut state.cname_authorities,
                    names: &mut state.cname_names,
                    deadlines: &mut state.proof_deadlines,
                    remaining: remaining_steps,
                    fresh_cut: target_referral.as_ref().map(|referral| &referral.zone),
                })
                .await?
            {
                CachedDnameProgress::Continue { changed: true } => {
                    // The referral describes the prior alias target, not
                    // the destination selected by the cached DNAME.
                    target_referral = None;
                }
                CachedDnameProgress::Continue { changed: false } => {}
                CachedDnameProgress::Complete(reply) => {
                    return Ok(ResponseAction::Complete {
                        reply,
                        cache_source: Some(ResolutionCacheSource::Positive),
                    });
                }
            }
        }
        self.restart_alias_candidates(&context, target_referral, received_at, state)
            .await
    }

    async fn retain_alias_response<'r>(
        &'r self,
        context: &ResponseContext<'_>,
        reply: &Message,
        chain: AliasChain,
        received_at: std::time::Instant,
        state: &mut ResolutionState<'r>,
    ) -> Result<bool, ResolveError> {
        let AliasChain {
            records: chain_records,
            target,
            wildcard_proofs,
        } = chain;
        let chain_names = chain_records
            .iter()
            .filter_map(|record| match &record.rdata {
                RData::CNAME(name) => Some(name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if chain_names
            .iter()
            .any(|name| state.cname_names.contains(name))
        {
            warn!(target = ?target, "DNS CNAME loop detected");
            state.cname_loop_seen = true;
            return Ok(false);
        }
        state.cname_names.extend(chain_names);
        debug!(target = ?target, "following DNS CNAME target");
        // RFC 1034 §5.3.3 requires caching each alias before restarting at
        // its canonical name. Negative authority data is deliberately not
        // admitted on this path.
        if state.cache_allowed {
            let mut alias_reply = reply.clone();
            alias_reply.answers = chain_records.clone();
            self.cache_positive_entries_backend_at(
                context.id,
                &alias_reply,
                &state.active_question,
                received_at,
            )
            .await?;
        }
        // Only retain the CNAME chain that caused the restart; unrelated
        // answer data is not part of the requested result.
        state.cname_authorities.extend(wildcard_proofs);
        if state.cname_answers.is_empty() {
            state.cname_answers = chain_records;
        } else if state
            .cname_answers
            .iter()
            .chain(&chain_records)
            .any(|rr| rr.rtype == RecordType::DNAME)
        {
            crate::response::append_distinct(&mut state.cname_answers, chain_records);
        } else {
            state.cname_answers.extend(chain_records);
        }
        state.active_question.qname = target;
        Ok(true)
    }

    async fn cached_alias_response<'r>(
        &'r self,
        original_question: &Question,
        state: &mut ResolutionState<'r>,
    ) -> Result<Option<ResponseAction>, ResolveError> {
        match self
            .cached_resolution_backend(
                original_question,
                state.active_question.clone(),
                std::mem::take(&mut state.cname_answers),
                std::mem::take(&mut state.cname_authorities),
                std::mem::take(&mut state.cname_names),
                state
                    .address_lookup
                    .then_some(state.algorithm_signals.checking_disabled),
            )
            .await?
        {
            CachedResolution::Negative(_) => {
                unreachable!("negative encoding requires explicit UDP request context")
            }
            CachedResolution::Positive(selected) => {
                let mut reply = selected.into_message();
                // Alias records were received before the backend
                // transaction. A slow checkout/CAS must not renew
                // them even when this chain contains no DNAME.
                let now = std::time::Instant::now();
                state.proof_deadlines.clamp_answers(&mut reply.answers, now);
                state.proof_deadlines.clamp(&mut reply.authorities, now);
                return Ok(Some(ResponseAction::Complete {
                    reply,
                    cache_source: Some(ResolutionCacheSource::Positive),
                }));
            }
            CachedResolution::Complete { mut reply, source } => {
                let now = std::time::Instant::now();
                state.proof_deadlines.clamp_answers(&mut reply.answers, now);
                state.proof_deadlines.clamp(&mut reply.authorities, now);
                return Ok(Some(ResponseAction::Complete {
                    reply,
                    cache_source: Some(source),
                }));
            }
            CachedResolution::Continue {
                active_question,
                cname_answers,
                cname_authorities,
                cname_names,
            } => {
                let observed_at = std::time::Instant::now();
                state.proof_deadlines.observe(&cname_answers, observed_at);
                state
                    .proof_deadlines
                    .observe(&cname_authorities, observed_at);
                state.active_question = active_question;
                state.cname_answers = cname_answers;
                state.cname_authorities = cname_authorities;
                state.cname_names = cname_names;
            }
        }
        Ok(None)
    }

    async fn restart_alias_candidates<'r>(
        &'r self,
        context: &ResponseContext<'_>,
        target_referral: Option<crate::protocol::Referral>,
        received_at: std::time::Instant,
        state: &mut ResolutionState<'r>,
    ) -> Result<ResponseAction, ResolveError> {
        self.check_name_server_target_failure(context.original_question, state)
            .await?;
        if let Some(target_referral) = target_referral
            && self
                .follow_referral(
                    target_referral,
                    received_at,
                    context.resolving_ns_hosts,
                    Arc::clone(&context.remaining_steps),
                    context.stats.clone(),
                    state,
                )
                .await?
        {
            return Ok(ResponseAction::RestartRound);
        }
        (
            state.current_delegation_zone,
            state.candidates,
            state.pending_name_servers,
            state.restart_from_root,
        ) = self
            .candidates_for(
                &state.active_question,
                state.algorithm_signals.checking_disabled,
            )
            .await?;
        state.zone_attempted = false;
        state.used_cached_delegation |= state.restart_from_root;
        self.prepare_candidates(&mut state.candidates, &context.stats);
        state.reachable_dns_error = false;
        Ok(ResponseAction::RestartRound)
    }
}
