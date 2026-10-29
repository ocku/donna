//! External transactions never hold a lock or snapshot across upstream I/O.
mod cached_hit;
pub(super) mod packet_ttl;

use super::Resolver;
use crate::ResolveError;
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(super) async fn cache_select_for<R: Send>(
        &self,
        questions: &[dns::Question],
        select: impl Fn(&Self) -> Result<R, ResolveError> + Send + Sync,
    ) -> Result<R, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return select(self);
        }
        let (_, context) = self
            .cache_transaction_with_context_for(questions, |c| Ok(select(c)))
            .await?;
        select(&context.expect("external cache returns committed view"))
    }
    pub(super) async fn cache_transaction_for<R: Send>(
        &self,
        questions: &[dns::Question],
        operation: impl Fn(&Self) -> Result<R, ResolveError> + Send + Sync,
    ) -> Result<R, ResolveError> {
        self.cache_transaction_with_context_for(questions, operation)
            .await
            .map(|(x, _)| x)
    }
    pub(super) async fn cache_transaction_with_context_for<R: Send>(
        &self,
        questions: &[dns::Question],
        operation: impl Fn(&Self) -> Result<R, ResolveError> + Send + Sync,
    ) -> Result<(R, Option<Box<Self>>), ResolveError> {
        // The existing zero-capacity contract disables every persistent cache,
        // including remote I/O, rather than making DNS depend on an unused store.
        if self.config.cache_capacity == 0 {
            return operation(self).map(|result| (result, None));
        }
        if self.cache_engine.is_some() {
            // Allocate the large external state machine only after selecting
            // engine mode; native ready futures retain their small frame.
            return Box::pin(self.engine_transaction(questions, operation)).await;
        }
        operation(self).map(|result| (result, None))
    }

    #[cfg(test)]
    pub(super) async fn cache_validated_response_backend(
        &self,
        response: &dns::Message,
        question: &dns::Question,
    ) -> Result<(), ResolveError> {
        self.cache_transaction_for(&super::engine::seeds(response, question), |context| {
            context.cache_validated_response(response, question);
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    pub(super) async fn cache_validated_response_with_dnames_backend(
        &self,
        response: &dns::Message,
        question: &dns::Question,
        validation: &super::dnssec::ValidationOutcome,
    ) -> Result<(), ResolveError> {
        self.cache_validated_response_with_sources_backend(response, question, validation, &[])
            .await
    }

    pub(super) async fn cache_validated_response_with_sources_backend(
        &self,
        response: &dns::Message,
        question: &dns::Question,
        validation: &super::dnssec::ValidationOutcome,
        sources: &[super::cache::dname::traversal::CachedDnameSource],
    ) -> Result<(), ResolveError> {
        if !self.uses_external_cache() {
            self.cache_validated_response_with_dnames(
                response,
                question,
                &validation.secure_dnames,
                std::time::Instant::now(),
                validation.cache_deadline(response),
                sources,
            );
            self.seed_negative_validation_cache(response, question, validation);
            return Ok(());
        }
        self.cache_transaction_for(&super::engine::seeds(response, question), |context| {
            let mut current = response.clone();
            validation.recheck(&mut current)?;
            context.cache_validated_response_with_dnames(
                &current,
                question,
                &validation.secure_dnames,
                std::time::Instant::now(),
                validation.cache_deadline(&current),
                sources,
            );
            context.seed_negative_validation_cache(&current, question, validation);
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    pub(super) async fn cached_dname_backend(
        &self,
        question: &dns::Question,
    ) -> Result<Option<super::cache::CachedDname>, ResolveError> {
        self.cached_dname_with_cut_backend(question, None).await
    }

    pub(super) async fn cached_dname_with_cut_backend(
        &self,
        question: &dns::Question,
        fresh_cut: Option<&dns::DomainName>,
    ) -> Result<Option<super::cache::CachedDname>, ResolveError> {
        if self.config.cache_capacity == 0
            || (!self.uses_external_cache() && !self.positive_cache.may_have_authenticated_dname())
        {
            return Ok(None);
        }
        Ok(self
            .cache_select_for(std::slice::from_ref(question), |context| {
                Ok(context.select_cached_dname_with_cut(question, fresh_cut))
            })
            .await?
            .filter(|selection| selection.selection.is_live()))
    }

    pub(super) async fn cached_resolution_backend(
        &self,
        original: &dns::Question,
        active: dns::Question,
        answers: Vec<dns::ResourceRecord>,
        authorities: Vec<dns::ResourceRecord>,
        names: crate::name::NameSet,
        ns_failure_cd: Option<bool>,
    ) -> Result<super::cache::CachedResolution, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return self.cached_resolution(
                original,
                active,
                answers,
                authorities,
                names,
                ns_failure_cd,
            );
        }
        let select = |context: &Self| {
            context.cached_resolution(
                original,
                active.clone(),
                answers.clone(),
                authorities.clone(),
                names.clone(),
                ns_failure_cd,
            )
        };
        // A cached loop or name-server failure can expire during the CAS just
        // like a positive hit. Commit its effects, then recheck it afterwards.
        let (_, context) = self
            .cache_transaction_with_context_for(&[original.clone(), active.clone()], |context| {
                Ok(select(context))
            })
            .await?;
        // The iterative path also crosses the CAS await: repeat the selection
        // locally so cached aliases and negative answers cannot be used after
        // their absolute deadlines. Earlier network-hop deadlines remain owned
        // by the caller and are still checked when the response is composed.
        select(&context.expect("external transaction returns its context"))
    }

    #[cfg(test)]
    pub(super) async fn cache_positive_entries_backend(
        &self,
        id: u16,
        reply: &dns::Message,
        question: &dns::Question,
    ) -> Result<(), ResolveError> {
        self.cache_positive_entries_backend_at(id, reply, question, std::time::Instant::now())
            .await
    }

    pub(super) async fn cache_positive_entries_backend_at(
        &self,
        id: u16,
        reply: &dns::Message,
        question: &dns::Question,
        observed_at: std::time::Instant,
    ) -> Result<(), ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            self.cache_positive_entries_at(id, reply, question, observed_at, None);
            return Ok(());
        }
        self.cache_transaction_for(&super::engine::seeds(reply, question), |context| {
            context.cache_positive_entries_at(id, reply, question, observed_at, None);
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    pub(super) async fn cache_response_entries_backend(
        &self,
        id: u16,
        reply: &dns::Message,
        positive: &dns::Question,
        negative: &dns::Question,
        authoritative: bool,
    ) -> Result<Option<dns::Message>, ResolveError> {
        self.cache_response_entries_backend_at(
            id,
            reply,
            positive,
            negative,
            authoritative,
            std::time::Instant::now(),
        )
        .await
    }

    pub(super) async fn cache_response_entries_backend_at(
        &self,
        id: u16,
        reply: &dns::Message,
        positive: &dns::Question,
        negative: &dns::Question,
        authoritative: bool,
        observed_at: std::time::Instant,
    ) -> Result<Option<dns::Message>, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return Ok(self.cache_response_entries_at(
                id,
                reply,
                positive,
                negative,
                authoritative,
                super::cache::CacheTiming {
                    observed_at,
                    not_after: None,
                },
            ));
        }
        let selected = self
            .cache_transaction_for(
                &super::engine::seeds_many(reply, &[positive, negative]),
                |context| {
                    Ok(context.cache_response_entries_at(
                        id,
                        reply,
                        positive,
                        negative,
                        authoritative,
                        super::cache::CacheTiming {
                            observed_at,
                            not_after: None,
                        },
                    ))
                },
            )
            .await?;
        Ok(selected.map(|mut current| {
            packet_ttl::age(&mut current, observed_at, std::time::Instant::now());
            current
        }))
    }

    pub(super) async fn cache_cname_completed_backend_at(
        &self,
        context: super::cache::CnameCompletedCacheContext<'_>,
        observed_at: std::time::Instant,
    ) -> Result<Option<dns::Message>, ResolveError> {
        if !self.uses_external_cache() || self.config.cache_capacity == 0 {
            return Ok(self.cache_cname_completed_response_entries_at(context, observed_at, None));
        }
        let selected = self
            .cache_transaction_for(
                &super::engine::seeds_many(
                    context.reply,
                    &[
                        context.positive_question,
                        context.negative_question,
                        context.terminal_question,
                    ],
                ),
                |caches| {
                    Ok(
                        caches.cache_cname_completed_response_entries_at(
                            context,
                            observed_at,
                            None,
                        ),
                    )
                },
            )
            .await?;
        Ok(selected.map(|mut current| {
            packet_ttl::age(&mut current, observed_at, std::time::Instant::now());
            current
        }))
    }

    pub(super) async fn insert_delegation_backend(
        &self,
        referral: &crate::protocol::Referral,
        observed_at: std::time::Instant,
    ) -> Result<(), ResolveError> {
        self.cache_transaction_for(
            &[super::engine::zone(&referral.zone, referral.class)],
            |context| {
                context
                    .delegation_cache
                    .insert_at(referral, context.config.max_ttl, observed_at);
                Ok(())
            },
        )
        .await
    }

    pub(super) async fn bad_contains_backend(
        &self,
        question: &dns::Question,
    ) -> Result<bool, ResolveError> {
        self.cache_select_for(std::slice::from_ref(question), |context| {
            Ok(context.bad_cache.contains(question))
        })
        .await
    }

    pub(super) async fn record_bad_backend(
        &self,
        question: &dns::Question,
    ) -> Result<(), ResolveError> {
        self.cache_transaction_for(std::slice::from_ref(question), |context| {
            context
                .bad_cache
                .record_failure(question, context.config.max_bad_ttl);
            Ok(())
        })
        .await
    }
}
