use super::*;

impl<T: Transport> Resolver<T> {
    pub(super) async fn run_resolution_round<'resolver>(
        &'resolver self,
        question: &Question,
        resolving_ns_hosts: &[DomainName],
        remaining_steps: &Arc<AtomicUsize>,
        stats: &ResolutionStatsContext,
        state: &mut ResolutionState<'resolver>,
        batch: &[SocketAddr],
    ) -> Result<RoundProgress, ResolveError> {
        state.zone_attempted = true;
        let id = (self.query_id_source)();
        let request = query_with_algorithm_signals(
            id,
            &state.active_question,
            self.config.edns_udp_payload_size,
            &state.algorithm_signals,
            !self.config.trust_anchors.is_empty(),
        );
        debug!(
            ?batch,
            transaction_id = id,
            remaining_steps = remaining_steps.load(Ordering::Relaxed),
            qname = ?state.active_question.qname,
            "querying DNS servers"
        );
        if let Some(stats) = &stats {
            stats.record_response_round(batch.len());
        }
        let round_attempts = Arc::clone(&state.attempts);
        let mut round = self.exchange_round(
            batch,
            &request,
            remaining_steps,
            &round_attempts,
            stats.clone(),
        );
        loop {
            let (server, response) = match round.next_response().await {
                Ok(outcome) => outcome,
                Err(failure) => {
                    if let Some(error) = failure.fatal {
                        return Err(ResolveError::Transport(error));
                    }
                    if failure.work_exhausted {
                        return Ok(RoundProgress::WorkExhausted);
                    }
                    // RFC 1035 §7.1 counts timeout processing separately from
                    // the transmissions and any later retransmission.
                    if !failure.timed_out.is_empty() && !consume_work(remaining_steps) {
                        return Ok(RoundProgress::WorkExhausted);
                    }
                    schedule_retries(
                        &mut state.candidates,
                        &HashMap::new(),
                        failure.timed_out.into_iter().chain(failure.transient),
                        None,
                    );
                    return Ok(RoundProgress::Continue);
                }
            };

            if !is_usable_response(&response.reply, id, &state.active_question) {
                debug!(
                    %server,
                    transaction_id = id,
                    "discarding mismatched or incomplete DNS response"
                );
                continue;
            }
            match self
                .process_response(
                    ResponseContext {
                        original_question: question,
                        resolving_ns_hosts,
                        remaining_steps: Arc::clone(remaining_steps),
                        server,
                        id,
                        elapsed: response.elapsed,
                        protocol: response.protocol,
                        responsive_protocols: response.responsive_protocols,
                        stats: stats.clone(),
                    },
                    response.reply,
                    state,
                )
                .await?
            {
                ResponseAction::ContinueRound => continue,
                ResponseAction::RestartRound => return Ok(RoundProgress::Continue),
                ResponseAction::Complete {
                    reply,
                    cache_source,
                } => {
                    self.record_delegation_success(state).await?;
                    return Ok(RoundProgress::Complete(ResolutionOutcome {
                        response: reply,
                        cache_source: cache_source.or_else(|| {
                            state
                                .used_cached_delegation
                                .then_some(ResolutionCacheSource::Delegation)
                        }),
                        dname_deadline: state.proof_deadlines.deadline(),
                        cached_dnames: state.proof_deadlines.cached_dnames(),
                    }));
                }
            }
        }
    }
}
