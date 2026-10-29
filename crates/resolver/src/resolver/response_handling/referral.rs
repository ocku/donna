//! Follow referrals or complete internal name-server lookups with trusted glue.
use super::*;

impl<T: Transport> Resolver<T> {
    pub(super) async fn process_referral<'resolver>(
        &'resolver self,
        context: ResponseContext<'_>,
        mut reply: Message,
        state: &mut ResolutionState<'resolver>,
        received_at: std::time::Instant,
    ) -> Result<ResponseAction, ResolveError> {
        let ResponseContext {
            resolving_ns_hosts,
            remaining_steps,
            server,
            protocol,
            responsive_protocols,
            stats,
            ..
        } = context;
        if let Some(referral) = referral(&reply, &state.active_question) {
            if state.active_question.qtype == dns::QueryType::DS
                && referral.zone.eq_dns(&state.active_question.qname)
                && reply
                    .authorities
                    .iter()
                    .any(|record| matches!(record.rtype, RecordType::NSEC | RecordType::NSEC3))
            {
                debug!(%server, "retaining an authenticated no-DS referral");
                return Ok(ResponseAction::Complete {
                    reply,
                    cache_source: None,
                });
            }
            let resolving_active_name_server = resolving_ns_hosts
                .iter()
                .any(|name_server| name_server.eq_dns(&state.active_question.qname));
            if resolving_active_name_server {
                let glue = referral.matching_glue(&state.active_question);
                if !glue.is_empty() {
                    // This early completion path used to bypass delegation
                    // caching. Retain a referral only when it passes the same
                    // strict-progress gate as normal referral following;
                    // `matching_glue()` exposes only the in-bailiwick subset;
                    // provisional sibling-glue candidates can never complete
                    // an internal name-server lookup through this path.
                    if delegation_progresses(&state.current_delegation_zone, &referral.zone) {
                        self.insert_delegation_backend(&referral, received_at)
                            .await?;
                    }
                    debug!(
                        %server,
                        answer_count = glue.len(),
                        "using trusted glue to complete internal name-server lookup"
                    );
                    reply.answers = glue;
                    reply.authorities.clear();
                    reply.additionals.clear();
                    return Ok(ResponseAction::Complete {
                        reply,
                        cache_source: None,
                    });
                }
            }
            if self
                .follow_referral(
                    referral,
                    received_at,
                    resolving_ns_hosts,
                    remaining_steps,
                    stats,
                    state,
                )
                .await?
            {
                let mut attempts = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
                for protocol in responsive_protocols.into_iter().chain([protocol]) {
                    attempts.progressed(&state.active_question, server, protocol);
                }
                return Ok(ResponseAction::RestartRound);
            }
        } else {
            debug!(
                %server,
                rcode = ?reply.headers.rcode,
                "DNS response did not yield an answer or referral"
            );
        }
        // A server failure, malformed response, or unusable referral does
        // not prevent trying the remaining addresses in the current SLIST.
        Ok(ResponseAction::ContinueRound)
    }
}
