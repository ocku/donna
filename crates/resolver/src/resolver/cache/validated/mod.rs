use dns::{Message, Question, RecordType};
use transport::Transport;

use crate::{ResolutionCacheSource, ResolveError, name::NameSet, response::cname_restart};

use super::super::{ResolutionOutcome, Resolver};
use super::{CacheTraversalContext, CachedResolution, CnameCompletedCacheContext};
mod dname_terminal;
mod nxdomain_cut;

enum CachedClientResponse {
    Message(ResolutionOutcome),
    Encoded(dns::wire::EncodedReply),
}

impl<T: Transport> Resolver<T> {
    /// Reuses admitted client answers without enabling cache reads for the
    /// unauthenticated material used during DNSSEC chain construction.
    pub(in crate::resolver) fn cached_client_response(
        &self,
        question: &Question,
    ) -> Result<Option<ResolutionOutcome>, ResolveError> {
        self.cached_client_response_with_policy(question, true)
    }

    pub(in crate::resolver) fn cached_client_response_with_policy(
        &self,
        question: &Question,
        allow_dnames: bool,
    ) -> Result<Option<ResolutionOutcome>, ResolveError> {
        Ok(self
            .cached_client_response_inner(question, None, allow_dnames)?
            .map(|outcome| match outcome {
                CachedClientResponse::Message(outcome) => outcome,
                CachedClientResponse::Encoded(_) => {
                    unreachable!("encoding requires explicit UDP context")
                }
            }))
    }

    pub(in crate::resolver) fn cached_client_response_udp(
        &self,
        request: &Message,
        maximum: usize,
    ) -> Result<Option<transport::ImmediateUdpResponse>, ResolveError> {
        Ok(self
            .cached_client_response_inner(
                &request.questions[0],
                Some((request, maximum)),
                !request.headers.cd,
            )?
            .map(|outcome| match outcome {
                CachedClientResponse::Message(outcome) => {
                    transport::ImmediateUdpResponse::Message(outcome.response)
                }
                CachedClientResponse::Encoded(reply) => {
                    transport::ImmediateUdpResponse::Encoded(reply)
                }
            }))
    }

    fn cached_client_response_inner(
        &self,
        question: &Question,
        udp: Option<(&Message, usize)>,
        allow_dnames: bool,
    ) -> Result<Option<CachedClientResponse>, ResolveError> {
        let validating = !self.config.trust_anchors.is_empty();
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let positive = if let Some((request, maximum)) = udp {
            match self.positive_cache.get_udp(request, maximum, validating) {
                Some(crate::cache::positive::CachedPositiveUdp::Encoded(reply)) => {
                    return Ok(Some(CachedClientResponse::Encoded(reply)));
                }
                Some(crate::cache::positive::CachedPositiveUdp::Message(response)) => {
                    Some(response)
                }
                None => None,
            }
        } else {
            self.positive_cache.get_question(question)
        };
        if let Some(mut response) = positive {
            response.headers.ad &= validating;
            return Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                response,
                cache_source: Some(ResolutionCacheSource::Positive),
                dname_deadline: None,
                cached_dnames: Vec::new(),
            })));
        }
        // Admission removes every same-owner/class negative when a CNAME is
        // accepted, and every conflicting CNAME when a negative is accepted.
        // This shortcut therefore cannot hide an admitted alias.
        if let Some((request, maximum)) = udp {
            if let Some(hit) = self.negative_cache.get_udp(request, maximum, validating) {
                let mut response = match hit {
                    crate::cache::negative::CachedNegativeUdp::Encoded {
                        mut reply,
                        implicit_referral,
                    } => {
                        if !implicit_referral {
                            return Ok(Some(CachedClientResponse::Encoded(reply)));
                        }
                        let mut nameservers = smallvec::SmallVec::<[dns::ResourceRecord; 4]>::new();
                        self.delegation_cache
                            .append_referral_records(question, &mut nameservers);
                        if reply.append_name_servers(&nameservers) {
                            return Ok(Some(CachedClientResponse::Encoded(reply)));
                        }
                        // Decode only this already selected reply for uncommon
                        // oversized/irregular NS additions. No second cache hit.
                        let mut response = reply
                            .into_message()
                            .map_err(transport::TransportError::Decode)?;
                        response.authorities.extend(nameservers);
                        response
                    }
                    crate::cache::negative::CachedNegativeUdp::Message(mut response) => {
                        self.append_implicit_referral(&mut response, question);
                        response
                    }
                };
                response.headers.ad &= validating;
                return Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                    response,
                    cache_source: Some(ResolutionCacheSource::Negative),
                    dname_deadline: None,
                    cached_dnames: Vec::new(),
                })));
            }
        } else if let Some(mut response) = self.negative_cache.get(question) {
            self.append_implicit_referral(&mut response, question);
            response.headers.ad &= validating;
            return Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                response,
                cache_source: Some(ResolutionCacheSource::Negative),
                dname_deadline: None,
                cached_dnames: Vec::new(),
            })));
        }
        // With trust anchors configured, iterative lookup never admits data;
        // these components passed the outer validation/admission boundary.
        // Unsigned components use the same bounded traversal and policy lock.
        match self.cached_resolution_locked(
            question,
            question.clone(),
            Vec::new(),
            Vec::new(),
            NameSet::from_name(&question.qname),
            CacheTraversalContext {
                direct_checked: true,
                borrow_negative: udp.is_some(),
            },
        )? {
            CachedResolution::Negative(selected) => {
                // Coherent selection and cache effects are complete. Immutable
                // query-owned selections allow checked encoding without either lock.
                drop(_policy);
                if let Some((request, maximum)) = udp
                    && let Some(reply) = selected.encode_udp(request, maximum, validating)
                {
                    return Ok(Some(CachedClientResponse::Encoded(reply)));
                }
                let mut response = selected.into_message();
                response.headers.ad &= validating;
                Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                    response,
                    cache_source: Some(ResolutionCacheSource::Negative),
                    dname_deadline: None,
                    cached_dnames: Vec::new(),
                })))
            }
            CachedResolution::Positive(selected) => {
                if let Some((request, maximum)) = udp
                    && let Some(reply) = selected.encode_udp(request, maximum, validating)
                {
                    return Ok(Some(CachedClientResponse::Encoded(reply)));
                }
                let mut response = selected.into_message();
                response.headers.ad &= validating;
                Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                    response,
                    cache_source: Some(ResolutionCacheSource::Positive),
                    dname_deadline: None,
                    cached_dnames: Vec::new(),
                })))
            }
            CachedResolution::Complete { mut reply, source } => {
                reply.headers.ad &= validating;
                Ok(Some(CachedClientResponse::Message(ResolutionOutcome {
                    response: reply,
                    cache_source: Some(source),
                    dname_deadline: None,
                    cached_dnames: Vec::new(),
                })))
            }
            CachedResolution::Continue {
                active_question,
                cname_answers,
                cname_authorities,
                ..
            } => {
                // Keep ordinary exact/CNAME/negative precedence. Partial aliases
                // retain the existing iterative path and its validation context.
                if validating
                    && allow_dnames
                    && active_question.qname.eq_dns(&question.qname)
                    && active_question.qtype == question.qtype
                    && active_question.qclass == question.qclass
                    && cname_answers.is_empty()
                    && cname_authorities.is_empty()
                {
                    if let Some(reply) = self.cached_authenticated_dname_reply(question, udp) {
                        return Ok(Some(reply));
                    }
                    drop(_policy);
                    return Ok(self.cached_authenticated_nxdomain_cut(question, udp));
                }
                Ok(None)
            }
        }
    }

    /// Admits a validated negative at its canonical owner while retaining
    /// aliases independently. Composition cleared AA for the caller, but the
    /// secure denial proof authenticates the canonical negative independently
    /// of that packet's AA bit. Insecure data does not gain authoritative rank.
    #[cfg(test)]
    pub(in crate::resolver) fn cache_validated_response(
        &self,
        response: &Message,
        question: &Question,
    ) {
        self.cache_validated_response_with_dnames(
            response,
            question,
            &[],
            std::time::Instant::now(),
            None,
            &[],
        );
    }

    pub(in crate::resolver) fn cache_validated_response_with_dnames(
        &self,
        response: &Message,
        question: &Question,
        secure_dnames: &[super::super::dnssec::ValidatedDname],
        observed_at: std::time::Instant,
        authenticated_deadline: Option<std::time::Instant>,
        sources: &[super::super::cache::dname::traversal::CachedDnameSource],
    ) {
        self.cache_validated_dnames(response, question, secure_dnames, observed_at, sources);
        self.cache_validated_dname_terminal(
            response,
            question,
            observed_at,
            authenticated_deadline,
        );
        let id = response.headers.id;
        if response.headers.ad
            && let Ok(Some((_, target))) = cname_restart(&response.answers, question)
            && matches!(
                response.headers.rcode,
                dns::RCode::Ok | dns::RCode::NameError
            )
            && !response.answers.iter().any(|rr| {
                rr.name.eq_dns(&target)
                    && question.qclass == dns::QClassType::Class(rr.class)
                    && rr.rtype != RecordType::RRSIG
            })
        {
            let terminal_question = Question {
                qname: target.clone(),
                ..question.clone()
            };
            let mut terminal = response.clone();
            terminal.headers.aa = true;
            terminal.questions = vec![terminal_question.clone()];
            terminal.answers.retain(|rr| rr.name.eq_dns(&target));
            self.cache_cname_completed_response_entries(CnameCompletedCacheContext {
                id,
                terminal_reply: &terminal,
                terminal_question: &terminal_question,
                reply: response,
                positive_question: question,
                negative_question: &terminal_question,
                negative_authoritative: true,
            });
        } else {
            self.cache_response_entries(id, response, question, question, response.headers.aa);
        }
    }
}
