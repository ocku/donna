//! External cache entries preserve DNAME authentication and absolute deadlines.
use super::super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use crate::{
    CacheEngine, CacheEngineConfig, CacheReadResult, ResolveError,
    resolver::tests::external_backend::Backend,
};
use dns::{
    ClassType, DnssecSecurityStatus, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use transport::BoxFuture;

#[derive(Default)]
struct DelayedBackend {
    inner: Backend,
    delay_once: AtomicBool,
    fail_once: AtomicBool,
    delay_after: AtomicUsize,
}
impl CacheEngine for DelayedBackend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            if self.fail_once.swap(false, Ordering::SeqCst) {
                return Err(io::Error::other("injected checkout failure"));
            }
            self.inner.read(namespace, expected_revision, plan).await
        })
    }
    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        revision: &'a [u8],
        bytes: &'a crate::CacheMutationBatch,
    ) -> BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let delayed_step = self
                .delay_after
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok_and(|n| n == 1);
            if self.delay_once.swap(false, Ordering::SeqCst) || delayed_step {
                tokio::time::sleep(Duration::from_millis(5100)).await;
            }
            self.inner.apply(namespace, revision, bytes).await
        })
    }
}

#[tokio::test]
async fn external_dname_restarts_fail_closed_and_expires_during_cas() {
    let (transport, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedBackend::default());
    let make = || {
        crate::Resolver::with_cache_engine(
            transport.clone(),
            config.clone(),
            CacheEngineConfig::new(backend.clone(), b"dname-external".to_vec(), [3; 32]).unwrap(),
        )
    };
    let first = make();
    let question = Question {
        qname: name(&["first", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = transport.answer.clone();
    reply.answers[0].ttl = 4;
    reply.questions = vec![question.clone()];
    reply.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 4,
        rdata: RData::CNAME(name(&["first", "new", "example"])),
    });
    assert_eq!(
        first
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    first
        .cache_validated_response_backend(&reply, &question)
        .await
        .unwrap();
    drop(first);
    let restarted = make();
    let descendant = Question {
        qname: name(&["next", "old", "example"]),
        ..question
    };
    assert!(
        restarted
            .cached_dname_backend(&descendant)
            .await
            .unwrap()
            .is_some()
    );
    backend.fail_once.store(true, Ordering::SeqCst);
    assert!(matches!(
        restarted.cached_dname_backend(&descendant).await,
        Err(ResolveError::CacheBackend(_))
    ));
    backend.delay_once.store(true, Ordering::SeqCst);
    assert!(
        restarted
            .cached_dname_backend(&descendant)
            .await
            .unwrap()
            .is_none(),
        "selection must not survive expiry during CAS"
    );
}

#[tokio::test]
async fn delayed_second_hop_does_not_renew_first_proof_or_readmit_it() {
    use super::network::Routed;
    use crate::resolver::AlgorithmSignals;
    use std::{net::Ipv4Addr, sync::Mutex};

    let (first, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["middle", "example"])),
    );
    let (second, _, _) = signed_record_fixture(
        false,
        name(&["middle", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let (terminal, _, _) = signed_record_fixture(
        false,
        name(&["one", "new", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::LOCALHOST),
    );
    let config = resolver(first.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedBackend::default());
    let routed = Routed {
        source: Arc::new(Mutex::new(first.answer.clone())),
        targets: vec![terminal.answer.clone()],
        dnskey: first.dnskey.clone(),
        requests: Arc::new(Mutex::new(Vec::new())),
        servers: Arc::new(Mutex::new(Vec::new())),
    };
    let resolver = crate::Resolver::with_cache_engine(
        routed,
        config,
        CacheEngineConfig::new(backend.clone(), b"dname-hops".to_vec(), [8; 32]).unwrap(),
    );
    let question = Question {
        qname: name(&["one", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = first.answer.clone();
    reply.answers[0].ttl = 4;
    reply.questions = vec![question.clone()];
    reply.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 4,
        rdata: RData::CNAME(name(&["one", "middle", "example"])),
    });
    reply.answers.extend(second.answer.answers);
    reply.answers.push(ResourceRecord {
        name: name(&["one", "middle", "example"]),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::CNAME(name(&["one", "new", "example"])),
    });
    reply.answers.extend(terminal.answer.answers);
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    resolver
        .cache_validated_response_backend(&reply, &question)
        .await
        .unwrap();
    backend.delay_after.store(2, Ordering::SeqCst);
    let mut outcome = resolver
        .resolve_inner(
            question.clone(),
            vec![],
            Arc::new(AtomicUsize::new(64)),
            None,
            Arc::new(AlgorithmSignals::default()),
            true,
        )
        .await
        .unwrap()
        .response;
    for record in outcome
        .answers
        .iter()
        .filter(|rr| rr.name.eq_dns(&name(&["old", "example"])) || rr.name.eq_dns(&question.qname))
    {
        assert_eq!(record.ttl, 0, "earlier proof must not regain lifetime");
    }
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut outcome)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    outcome.headers.ad = true;
    resolver
        .cache_validated_response_backend(&outcome, &question)
        .await
        .unwrap();
    assert!(
        resolver
            .cached_dname_backend(&question)
            .await
            .unwrap()
            .is_none()
    );
}
