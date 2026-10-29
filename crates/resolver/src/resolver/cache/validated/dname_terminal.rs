//! Reuse independently admitted terminal RRsets without storing derived aliases.
use dns::{Headers, Message, Question, RCode, RData, RecordType, ResourceRecord};
use smallvec::SmallVec;
use std::{ops::Range, time::Instant};
use transport::Transport;

use super::{
    CacheTraversalContext, CachedClientResponse, CachedResolution, ResolutionOutcome, Resolver,
};
use crate::{
    ResolutionCacheSource,
    cache::positive::{SelectedPositive, SelectionIdentity},
    name::NameSet,
    response::cname_restart,
};

struct DnameProof {
    records: Range<usize>,
    selection: SelectedPositive,
}

impl<T: Transport> Resolver<T> {
    /// Only the completed validator supplies this absolute admission bound.
    pub(super) fn cache_validated_dname_terminal(
        &self,
        response: &Message,
        question: &Question,
        observed_at: Instant,
        authenticated_deadline: Option<Instant>,
    ) {
        let Some(deadline) = authenticated_deadline.filter(|end| *end > Instant::now()) else {
            return;
        };
        if self.config.cache_capacity == 0
            || self.config.trust_anchors.is_empty()
            || !response.headers.ad
            || response.headers.rcode != RCode::Ok
            || !response
                .answers
                .iter()
                .any(|rr| rr.rtype == RecordType::DNAME)
        {
            return;
        }
        let Ok(Some((_, target))) = cname_restart(&response.answers, question) else {
            return;
        };
        let terminal = Question {
            qname: target,
            ..question.clone()
        };
        let mut projected = Message {
            headers: Headers {
                aa: false,
                rd: false,
                ..response.headers.clone()
            },
            questions: vec![terminal.clone()],
            answers: response
                .answers
                .iter()
                .filter(|rr| {
                    rr.name.eq_dns(&terminal.qname)
                        && terminal.qclass == dns::QClassType::Class(rr.class)
                })
                .cloned()
                .collect(),
            authorities: response.authorities.clone(),
            additionals: Vec::new(),
        };
        if projected.answers.is_empty() {
            return;
        }
        // Existing projection selects only requested data, matching RRSIGs and
        // wildcard proofs, and applies the ordinary conflict/eviction policy.
        projected.headers.rcode = RCode::Ok;
        self.cache_positive_entries_at(
            response.headers.id,
            &projected,
            &terminal,
            observed_at,
            Some(deadline),
        );
    }

    /// Called under cache_policy; no selection or identity survives this call.
    pub(super) fn cached_authenticated_dname_reply(
        &self,
        original: &Question,
        udp: Option<(&Message, usize)>,
    ) -> Option<CachedClientResponse> {
        if !self.positive_cache.may_have_authenticated_dname()
            || matches!(original.qtype, dns::QueryType::CNAME | dns::QueryType::ANY)
        {
            return None;
        }
        let mut active = original.clone();
        let mut names = NameSet::from_name(&active.qname);
        let mut prefix = Vec::new();
        let mut proofs = SmallVec::<[DnameProof; 4]>::new();
        let max_hops = usize::from(self.config.max_steps).max(1);
        while let Some(cached) = self.select_cached_dname_locked(&active, None) {
            if proofs.len() >= max_hops || !cached.selection.is_live() {
                return None;
            }
            let target = cached.target.ok()?;
            if !names.insert(target.clone()) {
                return None;
            }
            let ttl = cached.selection.ttl();
            let start = prefix.len();
            prefix.extend(cached.selection.answers().iter().cloned().map(|mut rr| {
                rr.ttl = rr.ttl.min(ttl);
                rr
            }));
            let class = match active.qclass {
                dns::QClassType::Class(class) => class,
                _ => return None,
            };
            prefix.push(ResourceRecord {
                name: active.qname.clone(),
                rtype: RecordType::CNAME,
                class,
                ttl,
                rdata: RData::CNAME(target.clone()),
            });
            proofs.push(DnameProof {
                records: start..prefix.len(),
                selection: cached.selection,
            });
            active.qname = target;
        }
        if proofs.is_empty() {
            return None;
        }
        let CachedResolution::Positive(mut selected) = self
            .cached_resolution_locked(
                original,
                active,
                prefix,
                Vec::new(),
                names,
                CacheTraversalContext::default(),
            )
            .ok()?
        else {
            return None;
        };
        if !selected.aliases_authenticated || !selected.terminal.authenticated {
            return None;
        }
        let hops = selected
            .prefix_answers
            .iter()
            .chain(selected.aliases.iter().flat_map(|a| a.answers()))
            .filter(|rr| rr.rtype == RecordType::CNAME)
            .count();
        if hops > max_hops {
            return None;
        }
        for proof in &proofs {
            if !proof.selection.is_live() || proof.records.end > selected.prefix_answers.len() {
                return None;
            }
            let ttl = proof.selection.ttl();
            for rr in &mut selected.prefix_answers[proof.records.clone()] {
                rr.ttl = rr.ttl.min(ttl);
            }
        }
        let identities: SmallVec<[SelectionIdentity; 8]> = selected
            .aliases
            .iter()
            .chain(std::iter::once(&selected.terminal))
            .map(SelectedPositive::identity)
            .collect();
        let live = || {
            proofs.iter().all(|p| p.selection.is_live())
                && identities.iter().all(|i| i.is_live(Instant::now()))
        };
        if !live() {
            return None;
        }
        let (answers, authorities) = selected.records();
        if !self.cached_dnssec_context_live(answers.iter().chain(&authorities).map(|(rr, _)| *rr)) {
            return None;
        }
        drop((answers, authorities));
        if let Some((request, maximum)) = udp
            && let Some(encoded) = selected.encode_udp(request, maximum, true)
        {
            let (answers, authorities) = selected.records();
            return (live()
                && self.cached_dnssec_context_live(
                    answers.iter().chain(&authorities).map(|(rr, _)| *rr),
                ))
            .then_some(CachedClientResponse::Encoded(encoded));
        }
        let response = selected.into_message();
        if !live()
            || !self
                .cached_dnssec_context_live(response.answers.iter().chain(&response.authorities))
        {
            return None;
        }
        Some(CachedClientResponse::Message(ResolutionOutcome {
            response,
            cache_source: Some(ResolutionCacheSource::Positive),
            dname_deadline: None,
            cached_dnames: Vec::new(),
        }))
    }
}
