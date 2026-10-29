use super::*;

pub(super) struct TerminalContext<'a> {
    pub original_question: &'a Question,
    pub server: std::net::SocketAddr,
    pub id: u16,
    pub received_at: std::time::Instant,
    pub cname: Option<(Vec<dns::ResourceRecord>, dns::DomainName)>,
    pub cname_nodata_question: Option<Question>,
}

impl<T: Transport> Resolver<T> {
    pub(super) async fn complete_network_terminal<'r>(
        &'r self,
        context: TerminalContext<'_>,
        reply: Message,
        state: &mut ResolutionState<'r>,
    ) -> Result<ResponseAction, ResolveError> {
        let TerminalContext {
            original_question,
            server,
            id,
            received_at,
            cname,
            cname_nodata_question,
        } = context;

        debug!(
            %server,
            rcode = ?reply.headers.rcode,
            authoritative = reply.headers.aa,
            answer_count = reply.answers.len(),
            "received terminal DNS response"
        );
        let cname_derived_negative = cname_nodata_question.is_some()
            || (reply.headers.rcode == RCode::NameError && cname.is_some());
        let negative_question = cname_nodata_question.unwrap_or_else(|| {
            if reply.headers.rcode == RCode::NameError {
                cname
                    .as_ref()
                    .map(|(_, target)| Question {
                        qname: target.clone(),
                        ..state.active_question.clone()
                    })
                    .unwrap_or_else(|| state.active_question.clone())
            } else {
                state.active_question.clone()
            }
        });
        let negative_authoritative = reply.headers.aa
            && (!cname_derived_negative
                || delegation_covers_name(
                    &state.current_delegation_zone,
                    &negative_question.qname,
                ));
        let prior_cname_answers = std::mem::take(&mut state.cname_answers);
        let has_alias = !prior_cname_answers.is_empty() || cname.is_some();
        let terminal_reply = (!prior_cname_answers.is_empty()).then(|| reply.clone());
        if has_alias {
            state.proof_deadlines.observe(&reply.answers, received_at);
            state
                .proof_deadlines
                .observe(&reply.authorities, received_at);
        }
        let mut reply = complete_cname_response(
            reply,
            original_question,
            prior_cname_answers,
            std::mem::take(&mut state.cname_authorities),
        );
        clamp_alias_deadlines(&mut reply, has_alias, &state.proof_deadlines);
        // Insert only answer-section data selected for the requested
        // CNAME path. Auxiliary entries use actual RR types so ANY,
        // MAILA, and MAILB answers can satisfy later concrete queries.
        let selected = if !state.cache_allowed {
            None
        } else if let Some(terminal_reply) = terminal_reply {
            self.cache_cname_completed_backend_at(
                CnameCompletedCacheContext {
                    id,
                    terminal_reply: &terminal_reply,
                    terminal_question: &state.active_question,
                    reply: &reply,
                    positive_question: original_question,
                    negative_question: &negative_question,
                    negative_authoritative,
                },
                received_at,
            )
            .await?
        } else {
            self.cache_response_entries_backend_at(
                id,
                &reply,
                original_question,
                &negative_question,
                negative_authoritative,
                received_at,
            )
            .await?
        };
        let mut reply = if let Some(selected) = selected {
            selected
        } else {
            if state.cache_allowed && self.uses_external_cache() && self.config.cache_capacity != 0
            {
                super::super::backend::packet_ttl::age(
                    &mut reply,
                    received_at,
                    std::time::Instant::now(),
                );
            }
            reply
        };
        clamp_alias_deadlines(&mut reply, has_alias, &state.proof_deadlines);
        Ok(ResponseAction::Complete {
            reply,
            cache_source: None,
        })
    }
}

fn clamp_alias_deadlines(reply: &mut Message, has_alias: bool, deadlines: &ProofDeadlines) {
    if has_alias
        || reply
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::DNAME)
    {
        let now = std::time::Instant::now();
        deadlines.clamp_answers(&mut reply.answers, now);
        deadlines.clamp(&mut reply.authorities, now);
    }
}
