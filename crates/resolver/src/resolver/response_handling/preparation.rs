//! Normalize an upstream packet before admitting responsiveness or answer data.
use super::*;
use std::time::Instant;

type CnameChain = Option<(Vec<dns::ResourceRecord>, dns::DomainName)>;

pub(super) struct PreparedResponse {
    pub(super) reply: Message,
    pub(super) cname: CnameChain,
}

enum DnameDisposition {
    Continue,
    Discard,
    Overflow,
}

impl<T: Transport> Resolver<T> {
    pub(super) fn prepare_response(
        &self,
        context: &ResponseContext<'_>,
        mut reply: Message,
        state: &mut ResolutionState<'_>,
        received_at: Instant,
    ) -> Result<PreparedResponse, ResponseAction> {
        let server = context.server;
        let elapsed = context.elapsed;
        let stats = &context.stats;
        if !types::sanitize_response_edns(&mut reply, server) {
            return Err(ResponseAction::ContinueRound);
        }
        // Read the complete 12-bit RCODE while the validated OPT pseudo-record
        // is still present. Otherwise BADVERS (16), whose header nibble is
        // NOERROR, could be misclassified as a terminal NODATA response below.
        let extended_rcode = reply.extended_rcode();
        // A parent is not authoritative for Answer data whose queried owner is
        // at or below a child cut advertised in the same packet. Discard the
        // complete section before RRSet or CNAME interpretation so every
        // QTYPE, including ANY and CNAME, follows the delegation instead of
        // admitting child-side data supplied by the parent. DS at the exact
        // cut is the one parent-side exception (RFC 4035 section 2.4).
        if let Some(child_zone) = applicable_child_delegation(
            &reply,
            &state.active_question,
            &state.current_delegation_zone,
        ) {
            debug!(
                %server,
                zone = ?child_zone,
                "discarding answer data at or below a child delegation"
            );
            reply.answers.clear();
            // AA describes the parent-owned answer that was just discarded;
            // the retained NS/additional sections form a referral.
            reply.headers.aa = false;
        }
        if !normalize_response_rrsets(&mut reply, &state.active_question) {
            debug!(%server, "discarding DNS response with a malformed non-authoritative RRSet");
            return Err(ResponseAction::ContinueRound);
        }
        match self.prepare_dname_response(context, &mut reply, state, extended_rcode, received_at) {
            DnameDisposition::Continue => {}
            DnameDisposition::Discard => return Err(ResponseAction::ContinueRound),
            DnameDisposition::Overflow => {
                return Err(complete_dname_overflow(context, reply, state, received_at));
            }
        }
        // OPT is hop-by-hop transaction metadata. It is consumed for this
        // exchange and must neither enter resolver caches nor escape in the
        // caller-facing resolution result.
        reply
            .additionals
            .retain(|record| record.rtype != RecordType::OPT);
        let cname = match cname_restart(&reply.answers, &state.active_question) {
            Ok(cname) => cname,
            Err(CnameError::Loop) => {
                state.cname_loop_seen = true;
                debug!(%server, "discarding DNS response with a CNAME loop");
                return Err(ResponseAction::ContinueRound);
            }
            Err(error) => {
                debug!(%server, ?error, "discarding DNS response with malformed CNAME data");
                return Err(ResponseAction::ContinueRound);
            }
        };
        // Correlation was checked before this point. Admit responsiveness only
        // after EDNS, RRSet, and CNAME structure have also passed; semantic DNS
        // errors still prove that the server was reachable.
        self.server_metrics
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .record_success(server, elapsed, stats);
        if extended_rcode > 0x0f {
            state.reachable_dns_error = true;
            debug!(%server, extended_rcode, "received an extended DNS error response");
            return Err(ResponseAction::ContinueRound);
        }
        if reply.headers.rcode != RCode::Ok {
            state.reachable_dns_error = true;
        }

        Ok(PreparedResponse { reply, cname })
    }

    fn prepare_dname_response(
        &self,
        context: &ResponseContext<'_>,
        reply: &mut Message,
        state: &mut ResolutionState<'_>,
        extended_rcode: u16,
        received_at: Instant,
    ) -> DnameDisposition {
        let server = context.server;
        let elapsed = context.elapsed;
        let stats = &context.stats;
        if reply.answers.iter().any(|r| r.rtype == RecordType::DNAME) {
            use dname_chain::PreparedChain;
            let prepared = dname_chain::prepare_chain(
                reply,
                &state.active_question,
                &state.current_delegation_zone,
            );
            match prepared {
                Ok(PreparedChain::Redirect)
                    if reply.headers.aa && reply.headers.rcode != RCode::YXDomain => {}
                Ok(PreparedChain::Overflow(_))
                    if dname_chain::is_overflow_response(
                        reply,
                        &state.active_question,
                        &state.current_delegation_zone,
                    ) =>
                {
                    // The header's low four RCODE bits alone do not identify
                    // YXDOMAIN when an OPT carries a nonzero extended RCODE.
                    // Treat that as an upstream DNS error just as in the
                    // ordinary response path below (RFC 6891 section 6.1.3).
                    self.server_metrics
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .record_success(server, elapsed, stats);
                    if extended_rcode > 0x0f {
                        state.reachable_dns_error = true;
                        debug!(%server, extended_rcode, "received an extended DNS error response");
                        return DnameDisposition::Discard;
                    }
                    // EDNS belongs to the upstream exchange. In particular it
                    // must not escape this early-return path to a library
                    // caller or be reused for a different client transaction.
                    reply
                        .additionals
                        .retain(|record| record.rtype != RecordType::OPT);
                    // Overflow also carries a DNAME proof; capture its
                    // absolute lifetime before building the combined reply.
                    state.proof_deadlines.observe(&reply.answers, received_at);
                    state
                        .proof_deadlines
                        .observe(&reply.authorities, received_at);
                    return DnameDisposition::Overflow;
                }
                Ok(PreparedChain::NoDname)
                    if reply
                        .answers
                        .iter()
                        .filter(|r| r.rtype == RecordType::DNAME)
                        .all(|r| {
                            r.name.eq_dns(&state.active_question.qname)
                                && matches!(
                                    state.active_question.qtype,
                                    QueryType::DNAME | QueryType::ANY
                                )
                        }) => {}
                _ => {
                    debug!(%server, ?prepared, "discarding invalid or non-authoritative DNAME response");
                    return DnameDisposition::Discard;
                }
            }
        }
        if reply
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::DNAME)
        {
            state.proof_deadlines.observe(&reply.answers, received_at);
            state
                .proof_deadlines
                .observe(&reply.authorities, received_at);
        }
        DnameDisposition::Continue
    }
}

fn complete_dname_overflow(
    context: &ResponseContext<'_>,
    reply: Message,
    state: &mut ResolutionState<'_>,
    received_at: Instant,
) -> ResponseAction {
    let mut reply = complete_cname_response(
        reply,
        context.original_question,
        std::mem::take(&mut state.cname_answers),
        std::mem::take(&mut state.cname_authorities),
    );
    state.proof_deadlines.clamp(&mut reply.answers, received_at);
    state
        .proof_deadlines
        .clamp(&mut reply.authorities, received_at);
    ResponseAction::Complete {
        reply,
        cache_source: None,
    }
}
