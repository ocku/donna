mod client;
mod cname;
pub(super) mod dname;
mod implicit_referral;
mod negative;
mod positive;
#[cfg(test)]
mod test_helpers;
mod validated;

pub(super) use dname::CachedDname;

#[derive(Clone, Copy)]
pub(super) struct CacheTiming {
    pub(super) observed_at: std::time::Instant,
    pub(super) not_after: Option<std::time::Instant>,
}

use cname::{cached_cname, simple_cname_target};
use positive::{AliasSelections, PositiveResponse, materialize_aliases};

use dns::{Message, QueryType, Question, RCode, RData, RecordType};
use tracing::debug;
use transport::Transport;

use crate::{
    ResolutionCacheSource, ResolveError,
    name::NameSet,
    protocol::query,
    response::{CnameError, complete_cname_response, has_requested_answer, positive_cache_entries},
};

use super::Resolver;

#[derive(Default)]
struct CacheTraversalContext {
    direct_checked: bool,
    borrow_negative: bool,
}

pub(super) enum CachedResolution {
    Negative(negative::NegativeResponse),
    Positive(PositiveResponse),
    Complete {
        reply: Message,
        source: ResolutionCacheSource,
    },
    Continue {
        active_question: Question,
        cname_answers: Vec<dns::ResourceRecord>,
        cname_authorities: Vec<dns::ResourceRecord>,
        cname_names: NameSet,
    },
}

#[derive(Clone, Copy)]
pub(super) struct CnameCompletedCacheContext<'a> {
    pub(super) id: u16,
    pub(super) terminal_reply: &'a Message,
    pub(super) terminal_question: &'a Question,
    pub(super) reply: &'a Message,
    pub(super) positive_question: &'a Question,
    pub(super) negative_question: &'a Question,
    pub(super) negative_authoritative: bool,
}

impl<T: Transport> Resolver<T> {
    pub(super) fn cache_positive_entries_at(
        &self,
        id: u16,
        reply: &Message,
        question: &Question,
        observed_at: std::time::Instant,
        not_after: Option<std::time::Instant>,
    ) {
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.cache_positive_entries_locked(id, reply, question, observed_at, not_after);
    }

    pub(super) fn cache_response_entries(
        &self,
        id: u16,
        reply: &Message,
        positive_question: &Question,
        negative_question: &Question,
        negative_authoritative: bool,
    ) -> Option<Message> {
        self.cache_response_entries_at(
            id,
            reply,
            positive_question,
            negative_question,
            negative_authoritative,
            CacheTiming {
                observed_at: std::time::Instant::now(),
                not_after: None,
            },
        )
    }

    pub(super) fn cache_response_entries_at(
        &self,
        id: u16,
        reply: &Message,
        positive_question: &Question,
        negative_question: &Question,
        negative_authoritative: bool,
        timing: CacheTiming,
    ) -> Option<Message> {
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        self.cache_negative_entry_locked(
            reply,
            negative_question,
            negative_authoritative,
            timing.observed_at,
            timing.not_after,
        );

        self.cache_positive_entries_locked(
            id,
            reply,
            positive_question,
            timing.observed_at,
            timing.not_after,
        )
    }

    /// Caches a terminal packet before adding CNAMEs collected from earlier
    /// packets, then caches the complete caller-facing answer path.
    ///
    /// CNAME composition deliberately clears AA because the terminal server
    /// need not be authoritative for aliases answered by earlier servers. The
    /// pristine packet must therefore be admitted first so its direct target
    /// data retains its actual trust, including authoritative negative proof.
    pub(super) fn cache_cname_completed_response_entries(
        &self,
        context: CnameCompletedCacheContext<'_>,
    ) -> Option<Message> {
        self.cache_cname_completed_response_entries_at(context, std::time::Instant::now(), None)
    }

    pub(super) fn cache_cname_completed_response_entries_at(
        &self,
        context: CnameCompletedCacheContext<'_>,
        observed_at: std::time::Instant,
        not_after: Option<std::time::Instant>,
    ) -> Option<Message> {
        let CnameCompletedCacheContext {
            id,
            terminal_reply,
            terminal_question,
            reply,
            positive_question,
            negative_question,
            negative_authoritative,
        } = context;
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        self.cache_negative_entry_locked(
            terminal_reply,
            negative_question,
            negative_authoritative,
            observed_at,
            not_after,
        );
        self.cache_positive_entries_locked(
            id,
            terminal_reply,
            terminal_question,
            observed_at,
            not_after,
        );
        self.cache_positive_entries_locked(id, reply, positive_question, observed_at, not_after)
    }

    fn cache_negative_entry_locked(
        &self,
        reply: &Message,
        negative_question: &Question,
        negative_authoritative: bool,
        observed_at: std::time::Instant,
        not_after: Option<std::time::Instant>,
    ) {
        // A DNAME-derived negative must never be attributed to its existing
        // alias name. Until the DNAME path can be cached with its proof,
        // accept negatives only from a separately selected terminal reply.
        if reply.answers.iter().any(|r| r.rtype == RecordType::DNAME)
            && reply.answers.iter().any(|r| r.rtype == RecordType::CNAME)
        {
            return;
        }
        let negative_scope = match reply.headers.rcode {
            RCode::NameError => Some(true),
            RCode::Ok if !has_requested_answer(&reply.answers, negative_question) => Some(false),
            _ => None,
        };
        if let Some(nxdomain) = negative_scope {
            let positive_conflict = if nxdomain {
                self.positive_cache.has_name(negative_question)
            } else {
                self.positive_cache.has_nodata_conflict(negative_question)
            };
            if (negative_authoritative || !positive_conflict)
                && self.negative_cache.insert_at(
                    negative_question,
                    reply,
                    negative_authoritative,
                    // RFC 2308 §5 recommends a separately tunable negative
                    // limit that is never greater than the positive limit.
                    self.config.max_negative_ttl.min(self.config.max_ttl),
                    observed_at,
                    not_after,
                )
            {
                if nxdomain {
                    self.positive_cache.remove_name(negative_question);
                } else {
                    self.positive_cache
                        .remove_nodata_conflicts(negative_question);
                }
            }
        }
    }

    fn cache_positive_entries_locked(
        &self,
        id: u16,
        reply: &Message,
        question: &Question,
        observed_at: std::time::Instant,
        not_after: Option<std::time::Instant>,
    ) -> Option<Message> {
        let mut selected = None;
        for (cache_question, cache_reply) in positive_cache_entries(reply, question) {
            let requested = cache_question.qname.eq_dns(&question.qname)
                && cache_question.qtype == question.qtype
                && cache_question.qclass == question.qclass;
            let cname = cache_reply.answers.iter().any(|record| {
                record.name.eq_dns(&cache_question.qname) && record.rtype == RecordType::CNAME
            });
            if !cache_reply.headers.aa
                && self.negative_cache.has_authoritative_positive_conflict(
                    &cache_question,
                    &cache_reply.answers,
                    cname,
                )
            {
                continue;
            }
            if self.positive_cache.insert_at(
                &query(id, &cache_question, self.config.edns_udp_payload_size),
                &cache_reply,
                self.config.max_ttl,
                observed_at,
                not_after,
            ) {
                self.negative_cache.remove_positive_conflicts(
                    &cache_question,
                    &cache_reply.answers,
                    cname,
                );
            }
            if requested {
                selected = Some(cache_reply);
            }
        }
        selected
    }

    pub(super) fn cached_resolution(
        &self,
        original_question: &Question,
        active_question: Question,
        cname_answers: Vec<dns::ResourceRecord>,
        cname_authorities: Vec<dns::ResourceRecord>,
        cname_names: NameSet,
        ns_failure_cd: Option<bool>,
    ) -> Result<CachedResolution, ResolveError> {
        let _policy = self
            .cache_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let selected = self.cached_resolution_locked(
            original_question,
            active_question,
            cname_answers,
            cname_authorities,
            cname_names,
            CacheTraversalContext::default(),
        )?;
        if let (
            Some(cd),
            CachedResolution::Continue {
                active_question, ..
            },
        ) = (ns_failure_cd, &selected)
            && (self.failure_cache.get(original_question, cd).is_some()
                || self.failure_cache.get(active_question, cd).is_some())
        {
            return Err(ResolveError::CachedNameServerFailure);
        }
        Ok(selected)
    }

    /// The caller holds the policy lock throughout direct checks and alias
    /// traversal, so a checked initial owner need not be probed twice.
    fn cached_resolution_locked(
        &self,
        original_question: &Question,
        mut active_question: Question,
        mut cname_answers: Vec<dns::ResourceRecord>,
        mut cname_authorities: Vec<dns::ResourceRecord>,
        mut cname_names: NameSet,
        context: CacheTraversalContext,
    ) -> Result<CachedResolution, ResolveError> {
        let mut direct_checked = context.direct_checked;
        let max_cached_hops = usize::from(self.config.max_steps).max(1);
        let mut cached_hops = 0_usize;
        let mut aliases_authenticated = true;
        let mut selected_aliases = AliasSelections::new();

        loop {
            if !direct_checked
                && let Some(terminal) = self.positive_cache.select_question(&active_question)
            {
                debug!("DNS resolution served from positive cache");
                let question = if cname_answers.is_empty() && selected_aliases.is_empty() {
                    active_question
                } else {
                    original_question.clone()
                };
                return Ok(CachedResolution::Positive(PositiveResponse {
                    terminal,
                    aliases: selected_aliases,
                    prefix_answers: cname_answers,
                    prefix_authorities: cname_authorities,
                    question,
                    aliases_authenticated,
                }));
            }

            if !matches!(active_question.qtype, QueryType::CNAME | QueryType::ANY) {
                let cname_question = Question {
                    qtype: QueryType::CNAME,
                    ..active_question.clone()
                };
                if let Some(selected) = self.positive_cache.select_question(&cname_question) {
                    if let Some(target) = simple_cname_target(selected.answers(), &active_question)
                    {
                        let target = target.map_err(|_| ResolveError::CnameLoop)?;
                        cached_hops = cached_hops.saturating_add(1);
                        if cached_hops > max_cached_hops {
                            return Err(ResolveError::WorkLimitExceeded);
                        }
                        if !cname_names.insert(target.clone()) {
                            return Err(ResolveError::CnameLoop);
                        }
                        aliases_authenticated &= selected.authenticated;
                        selected_aliases.push(selected);
                        active_question.qname = target;
                        direct_checked = false;
                        continue;
                    }
                    // An unusual selected shape retains the original parser,
                    // without another cache lookup or popularity touch.
                    materialize_aliases(
                        &mut selected_aliases,
                        &mut cname_answers,
                        &mut cname_authorities,
                    );
                    let reply = selected.into_message(&cname_question);
                    match cached_cname(reply, &active_question) {
                        Ok(Some(chain)) => {
                            let chain_records = chain.answers;
                            let target = chain.target;
                            let hop_count = chain_records
                                .iter()
                                .filter(|record| matches!(record.rdata, RData::CNAME(_)))
                                .count();
                            cached_hops = cached_hops.saturating_add(hop_count);
                            if cached_hops > max_cached_hops {
                                return Err(ResolveError::WorkLimitExceeded);
                            }
                            for record in &chain_records {
                                if let RData::CNAME(target) = &record.rdata
                                    && !cname_names.insert(target.clone())
                                {
                                    return Err(ResolveError::CnameLoop);
                                }
                            }
                            aliases_authenticated &= chain.authenticated;
                            debug!(target = ?target, "following cached DNS CNAME target");
                            if cname_authorities.is_empty() {
                                cname_authorities = chain.authorities;
                            } else {
                                cname_authorities.extend(chain.authorities);
                            }
                            if cname_answers.is_empty() {
                                cname_answers = chain_records;
                            } else {
                                cname_answers.extend(chain_records);
                            }
                            active_question.qname = target;
                            direct_checked = false;
                            continue;
                        }
                        Err(CnameError::Loop) => return Err(ResolveError::CnameLoop),
                        Ok(None)
                        | Err(
                            CnameError::MultipleTargets
                            | CnameError::CoexistingData
                            | CnameError::InvalidDname,
                        ) => {}
                    }
                }
            }

            if !direct_checked
                && context.borrow_negative
                && cname_answers.is_empty()
                && cname_authorities.is_empty()
                && !selected_aliases.is_empty()
            {
                if let Some(selected) = self.negative_cache.select(&active_question) {
                    let mut nameservers = smallvec::SmallVec::new();
                    if !(selected.authenticated && aliases_authenticated)
                        && !selected
                            .authorities()
                            .any(|(record, _)| record.rtype == RecordType::NS)
                    {
                        self.delegation_cache
                            .append_referral_records(&active_question, &mut nameservers);
                    }
                    debug!("DNS resolution served from negative cache");
                    return Ok(CachedResolution::Negative(negative::NegativeResponse {
                        selected,
                        aliases: selected_aliases,
                        nameservers,
                        question: original_question.clone(),
                        terminal_question: active_question,
                        aliases_authenticated,
                    }));
                }
            } else if !direct_checked
                && let Some(mut reply) = self.negative_cache.get(&active_question)
            {
                materialize_aliases(
                    &mut selected_aliases,
                    &mut cname_answers,
                    &mut cname_authorities,
                );
                reply.headers.ad &= aliases_authenticated;
                self.append_implicit_referral(&mut reply, &active_question);
                debug!("DNS resolution served from negative cache");
                return Ok(CachedResolution::Complete {
                    reply: complete_cname_response(
                        reply,
                        original_question,
                        cname_answers,
                        cname_authorities,
                    ),
                    source: ResolutionCacheSource::Negative,
                });
            }
            materialize_aliases(
                &mut selected_aliases,
                &mut cname_answers,
                &mut cname_authorities,
            );
            return Ok(CachedResolution::Continue {
                active_question,
                cname_answers,
                cname_authorities,
                cname_names,
            });
        }
    }
}
