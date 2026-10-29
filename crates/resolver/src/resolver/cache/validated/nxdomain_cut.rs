//! RFC8020 authenticated cuts; sibling interval synthesis remains separate.
use super::{
    CacheTraversalContext, CachedClientResponse, CachedResolution, ResolutionOutcome, Resolver,
};
use crate::name::NameSet;
use dns::{Message, QueryType, Question, RCode};
use transport::Transport;

impl<T: Transport> Resolver<T> {
    pub(super) fn cached_authenticated_nxdomain_cut(
        &self,
        question: &Question,
        udp: Option<(&Message, usize)>,
    ) -> Option<CachedClientResponse> {
        let (source, selected) = {
            let _policy = self.cache_policy.lock().unwrap_or_else(|e| e.into_inner());
            if !self.nxdomain_cut_question_unanswered(question) {
                return None;
            }
            let (source, selected) = self.negative_cache.select_name_error_ancestor(question)?;
            if !self.nxdomain_cut_namespace_live(question, &source) {
                return None;
            }
            (source, selected)
        };
        if !selected.is_live() || selected.rcode != RCode::NameError {
            return None;
        }
        let mut response = selected.materialize(question);
        // Full target-specific proof selection and signature/key/time checks
        // execute without holding the publication policy mutex.
        let context = self.validate_cached_name_error(&response, question, &selected)?;
        context.project_authorities(&mut response);
        let _policy = self.cache_policy.lock().unwrap_or_else(|e| e.into_inner());
        let live = || {
            self.negative_cache.retains_name_error(&source, &selected)
                && self.cached_denial_context_live(&context)
        };
        if !live()
            || !self.nxdomain_cut_question_unanswered(question)
            || !self.nxdomain_cut_namespace_live(question, &source)
        {
            return None;
        }
        let remaining = selected
            .deadline()
            .min(context.deadline())
            .saturating_duration_since(std::time::Instant::now())
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        for record in &mut response.authorities {
            record.ttl = record.ttl.min(remaining);
        }
        self.append_implicit_referral(&mut response, question);
        if let Some((request, maximum)) = udp {
            let authorities: smallvec::SmallVec<[(&dns::ResourceRecord, u32); 8]> =
                response.authorities.iter().map(|rr| (rr, rr.ttl)).collect();
            let encoded = dns::wire::EncodedReply::recursive_negative(
                request,
                &[],
                &authorities,
                true,
                true,
                maximum,
            )
            .ok()
            .flatten();
            if let Some(encoded) = encoded {
                return live().then_some(CachedClientResponse::Encoded(encoded));
            }
        }
        live().then_some(CachedClientResponse::Message(ResolutionOutcome {
            response,
            cache_source: Some(crate::ResolutionCacheSource::Negative),
            dname_deadline: None,
            cached_dnames: Vec::new(),
        }))
    }

    fn nxdomain_cut_question_unanswered(&self, question: &Question) -> bool {
        matches!(self.cached_resolution_locked(question, question.clone(), Vec::new(), Vec::new(),
            NameSet::from_name(&question.qname), CacheTraversalContext::default()),
            Ok(CachedResolution::Continue { active_question, cname_answers, .. })
            if cname_answers.is_empty() && active_question.qname.eq_dns(&question.qname))
    }

    fn nxdomain_cut_namespace_live(&self, question: &Question, source: &Question) -> bool {
        if self.select_cached_dname_locked(question, None).is_some() {
            return false;
        }
        let lookup = Question {
            qtype: QueryType::A,
            ..question.clone()
        };
        !self
            .delegation_cache
            .get(&lookup)
            .is_some_and(|cut| cut.zone.is_descendant_of(&source.qname))
    }
}
