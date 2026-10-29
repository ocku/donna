//! Follow only authenticated DNAME cache entries in the outer client flow.
use std::sync::atomic::AtomicUsize;

use dns::{
    Headers, Message, QClassType, QueryType, Question, RCode, RData, RecordType, ResourceRecord,
};
use transport::Transport;

use crate::resolver::{Resolver, response_handling::ProofDeadlines};
use crate::{ResolveError, name::NameSet, response::consume_work};

/// Weak transaction provenance never extends the source cache object's life.
#[derive(Clone)]
pub(in crate::resolver) struct CachedDnameSource {
    pub(in crate::resolver) question: Question,
    pub(in crate::resolver) identity: crate::cache::positive::SelectionIdentity,
}

pub(in crate::resolver) struct CachedDnameContext<'a> {
    pub(in crate::resolver) original: &'a Question,
    pub(in crate::resolver) active: &'a mut Question,
    pub(in crate::resolver) answers: &'a mut Vec<ResourceRecord>,
    pub(in crate::resolver) authorities: &'a mut Vec<ResourceRecord>,
    pub(in crate::resolver) names: &'a mut NameSet,
    pub(in crate::resolver) deadlines: &'a mut ProofDeadlines,
    pub(in crate::resolver) remaining: &'a AtomicUsize,
    pub(in crate::resolver) fresh_cut: Option<&'a dns::DomainName>,
}

pub(in crate::resolver) enum CachedDnameProgress {
    Continue { changed: bool },
    Complete(Message),
}

impl<T: Transport> Resolver<T> {
    pub(in crate::resolver) async fn follow_cached_dnames(
        &self,
        context: CachedDnameContext<'_>,
    ) -> Result<CachedDnameProgress, ResolveError> {
        let CachedDnameContext {
            original,
            active,
            answers,
            authorities,
            names,
            deadlines,
            remaining,
            fresh_cut,
        } = context;
        if !matches!(active.qclass, QClassType::Class(_)) {
            return Ok(CachedDnameProgress::Continue { changed: false });
        }
        let mut changed = false;
        while let Some(cached) = self
            .cached_dname_with_cut_backend(active, fresh_cut)
            .await?
        {
            if !consume_work(remaining) {
                return Err(ResolveError::WorkLimitExceeded);
            }
            // A selected entry keeps its absolute expiry while a remote CAS
            // is pending; materialize afterwards and observe before any next
            // await so later hops cannot renew its proof.
            deadlines.retain_cached_dname(CachedDnameSource {
                question: cached.question.clone(),
                identity: cached.selection.identity(),
            });
            let records = cached.selection.into_message(&cached.question).answers;
            deadlines.observe(&records, std::time::Instant::now());
            let dname = records
                .iter()
                .find(|rr| rr.rtype == RecordType::DNAME)
                .expect("cached DNAME selection contains its DNAME");
            let target = match cached.target {
                Ok(target) => target,
                Err(_) => {
                    answers.extend(records);
                    return Ok(CachedDnameProgress::Complete(finish(
                        original,
                        answers,
                        authorities,
                        deadlines,
                        RCode::YXDomain,
                    )));
                }
            };
            let synthesized = ResourceRecord {
                name: active.qname.clone(),
                rtype: RecordType::CNAME,
                class: dname.class,
                ttl: dname.ttl,
                rdata: RData::CNAME(target.clone()),
            };
            answers.extend(records);
            answers.push(synthesized);
            changed = true;
            if matches!(active.qtype, QueryType::CNAME | QueryType::ANY) {
                return Ok(CachedDnameProgress::Complete(finish(
                    original,
                    answers,
                    authorities,
                    deadlines,
                    RCode::Ok,
                )));
            }
            if !names.insert(target.clone()) {
                return Err(ResolveError::CnameLoop);
            }
            active.qname = target;
        }
        Ok(CachedDnameProgress::Continue { changed })
    }
}

fn finish(
    original: &Question,
    answers: &mut Vec<ResourceRecord>,
    authorities: &mut Vec<ResourceRecord>,
    deadlines: &ProofDeadlines,
    rcode: RCode,
) -> Message {
    let now = std::time::Instant::now();
    deadlines.clamp(answers, now);
    deadlines.clamp(authorities, now);
    Message {
        headers: Headers {
            qr: true,
            rcode,
            ..Headers::default()
        },
        questions: vec![original.clone()],
        answers: std::mem::take(answers),
        authorities: std::mem::take(authorities),
        additionals: Vec::new(),
    }
}
