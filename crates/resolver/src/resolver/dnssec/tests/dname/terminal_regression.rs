//! Independent component provenance checks for complete cached DNAME answers.
use super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::{SignedTransport, name},
};
use crate::resolver::Resolver;
use dns::{
    ClassType, DnssecSecurityStatus, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::{net::Ipv4Addr, time::Duration};

fn fixture() -> (Resolver<SignedTransport>, Question, Question, Message) {
    let (source, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["middle", "example"])),
    );
    let (middle, _, _) = signed_record_fixture(
        false,
        name(&["middle", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let (terminal, _, terminal_question) = signed_record_fixture(
        false,
        name(&["www", "new", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 42)),
    );
    let question = Question {
        qname: name(&["www", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let cname = |owner, target| ResourceRecord {
        name: owner,
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 300,
        rdata: RData::CNAME(target),
    };
    let mut reply = source.answer.clone();
    reply.questions = vec![question.clone()];
    reply.answers.push(cname(
        question.qname.clone(),
        name(&["www", "middle", "example"]),
    ));
    reply.answers.extend(middle.answer.answers);
    reply.answers.push(cname(
        name(&["www", "middle", "example"]),
        terminal_question.qname.clone(),
    ));
    reply.answers.extend(terminal.answer.answers);
    (resolver(source, anchor), question, terminal_question, reply)
}

async fn admit(resolver: &Resolver<SignedTransport>, question: &Question, reply: &mut Message) {
    let validation = resolver
        .validate_dnssec_response_with_deadline(question, reply, None)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Secure);
    reply.headers.ad = true;
    resolver
        .cache_validated_response_with_dnames_backend(reply, question, &validation)
        .await
        .unwrap();
}

#[tokio::test]
async fn connected_terminal_is_admitted_without_synthetic_or_unrelated_answers() {
    let (resolver, question, terminal, mut reply) = fixture();
    let (unrelated, _, other) = signed_record_fixture(
        false,
        name(&["unrelated", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 99)),
    );
    reply.answers.extend(unrelated.answer.answers);
    admit(&resolver, &question, &mut reply).await;
    let canonical = resolver
        .cached_positive_response(&terminal)
        .expect("canonical A admitted");
    assert!(canonical.headers.ad);
    assert!(
        canonical
            .answers
            .iter()
            .all(|rr| rr.name.eq_dns(&terminal.qname))
    );
    assert!(resolver.cached_positive_response(&other).is_none());
    for owner in [question.qname.clone(), name(&["www", "middle", "example"])] {
        assert!(
            resolver
                .cached_positive_response(&Question {
                    qname: owner,
                    qtype: QueryType::CNAME,
                    qclass: question.qclass,
                })
                .is_none(),
            "derived CNAME must retain DNAME provenance, not become an independent alias"
        );
    }
    let complete = resolver
        .cached_client_response(&question)
        .unwrap()
        .expect("genuine complete cache hit")
        .response;
    assert!(complete.headers.ad && !complete.headers.aa);
    assert_eq!(
        complete
            .answers
            .iter()
            .filter(|rr| rr.rtype == RecordType::DNAME)
            .count(),
        2
    );
    assert_eq!(
        complete
            .answers
            .iter()
            .filter(|rr| rr.rtype == RecordType::CNAME)
            .count(),
        2
    );
    let data: Vec<_> = complete
        .answers
        .iter()
        .filter_map(|rr| match rr.rdata {
            RData::A(address) => Some(address),
            _ => None,
        })
        .collect();
    assert_eq!(data, [Ipv4Addr::new(192, 0, 2, 42)]);
    assert!(
        resolver
            .cached_client_response_with_policy(&question, false)
            .unwrap()
            .is_none(),
        "CD policy must bypass the new complete-DNAME route"
    );
    assert!(
        resolver
            .cached_client_response_backend_with_policy(&question, false)
            .await
            .unwrap()
            .is_none(),
        "asynchronous cache reads must retain the same CD policy"
    );
    let mut cd_request = crate::protocol::query(0x4344, &question, 1232);
    cd_request.headers.rd = true;
    cd_request.headers.cd = true;
    assert!(
        resolver
            .try_resolve_cached_udp(&cd_request, 1232)
            .unwrap()
            .is_none()
    );
    let mixed = Question {
        qname: name(&["WwW", "OlD", "ExAmPlE"]),
        ..question
    };
    let reply = resolver
        .cached_client_response(&mixed)
        .unwrap()
        .expect("case-insensitive cache selection")
        .response;
    assert_eq!(reply.questions[0].qname.as_ref(), mixed.qname.as_ref());
    let first = reply
        .answers
        .iter()
        .find(|rr| rr.rtype == RecordType::CNAME && rr.name.eq_dns(&mixed.qname))
        .unwrap();
    assert_eq!(first.name.as_ref(), mixed.qname.as_ref());
    let RData::CNAME(target) = &first.rdata else {
        unreachable!()
    };
    assert_eq!(
        target.as_ref(),
        name(&["WwW", "middle", "example"]).as_ref()
    );
}

#[tokio::test]
async fn removing_any_required_component_invalidates_the_complete_cached_answer() {
    for removed in 0..3 {
        let (resolver, question, terminal, mut reply) = fixture();
        admit(&resolver, &question, &mut reply).await;
        assert!(
            resolver
                .cached_client_response(&question)
                .unwrap()
                .is_some()
        );
        let component = match removed {
            0 => Question {
                qname: name(&["old", "example"]),
                qtype: QueryType::DNAME,
                qclass: question.qclass,
            },
            1 => Question {
                qname: name(&["middle", "example"]),
                qtype: QueryType::DNAME,
                qclass: question.qclass,
            },
            _ => terminal.clone(),
        };
        resolver.positive_cache.remove_name(&component);
        assert!(
            resolver
                .cached_client_response(&question)
                .unwrap()
                .is_none(),
            "missing component {removed} must fall back"
        );
        if removed < 2 {
            assert!(
                resolver.cached_positive_response(&terminal).is_some(),
                "terminal lifetime is independent"
            );
        } else {
            assert!(
                resolver.select_cached_dname(&question).is_some(),
                "ancestor lifetime is independent"
            );
        }
    }
}

#[tokio::test]
async fn unvalidated_complete_packet_does_not_promote_its_terminal_as_authenticated() {
    let (resolver, question, terminal, mut reply) = fixture();
    assert!(!reply.headers.ad);
    // This seam also receives mixed-security/CD results. Valid-looking
    // signatures are insufficient without completed authentication provenance.
    for upstream_ad in [false, true] {
        reply.headers.ad = upstream_ad;
        resolver.cache_validated_response(&reply, &question);
        assert!(resolver.cached_positive_response(&terminal).is_none());
        assert!(
            resolver
                .cached_client_response(&question)
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn new_descendant_cut_vetoes_composition_even_when_terminal_data_is_cached() {
    let (resolver, question, terminal, mut reply) = fixture();
    admit(&resolver, &question, &mut reply).await;
    assert!(
        resolver
            .cached_client_response(&question)
            .unwrap()
            .is_some()
    );
    let address = (Ipv4Addr::LOCALHOST, 53).into();
    resolver.delegation_cache.insert(
        &crate::protocol::Referral {
            zone: question.qname.clone(),
            class: ClassType::IN,
            candidates: vec![address],
            candidate_ttls: vec![(address, Duration::from_secs(60))],
            trusted_glue: vec![],
            name_servers: vec![name(&["ns", "other"])],
            ttl: Duration::from_secs(60),
        },
        Duration::from_secs(60),
    );
    assert!(resolver.cached_positive_response(&terminal).is_some());
    assert!(
        resolver
            .cached_client_response(&question)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delayed_admission_cannot_renew_a_completed_validation_deadline() {
    let (resolver, question, terminal, mut reply) = fixture();
    for record in &mut reply.answers {
        if record.name.eq_dns(&name(&["old", "example"])) {
            record.ttl = 2;
        }
    }
    let validation = resolver
        .validate_dnssec_response_with_deadline(&question, &mut reply, None)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Secure);
    reply.headers.ad = true;
    // Simulate delayed publication after otherwise successful authentication.
    // Reusing a validation outcome must preserve its absolute acquisition cap.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    resolver
        .cache_validated_response_with_dnames_backend(&reply, &question, &validation)
        .await
        .unwrap();
    assert!(resolver.cached_positive_response(&terminal).is_none());
    assert!(
        resolver
            .cached_client_response(&question)
            .unwrap()
            .is_none()
    );
}

#[test]
fn external_commit_delay_discards_a_dname_hit_that_expires_during_publication() {
    use crate::{CacheEngine, CacheEngineConfig, CacheReadResult};
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    #[derive(Default)]
    struct DelayedCommit {
        inner: crate::resolver::tests::external_backend::Backend,
        delay: AtomicBool,
        delayed_commits: AtomicUsize,
    }
    impl CacheEngine for DelayedCommit {
        fn read<'a>(
            &'a self,
            namespace: &'a [u8],
            expected_revision: Option<&'a [u8]>,
            plan: &'a crate::CacheReadPlan,
        ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
            self.inner.read(namespace, expected_revision, plan)
        }
        fn apply<'a>(
            &'a self,
            namespace: &'a [u8],
            revision: &'a [u8],
            bytes: &'a crate::CacheMutationBatch,
        ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
            Box::pin(async move {
                if self.delay.swap(false, Ordering::SeqCst) {
                    self.delayed_commits.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(2100)).await;
                }
                self.inner.apply(namespace, revision, bytes).await
            })
        }
    }

    // An OS-thread watchdog remains responsive even if a synchronous policy
    // mutex blocks the current-thread executor. No Tokio feature changes.
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                let (base, question, terminal, mut reply) = fixture();
                for record in &mut reply.answers {
                    if record.name.eq_dns(&name(&["old", "example"])) {
                        record.ttl = 2;
                    } else if record.name.eq_dns(&terminal.qname) {
                        record.ttl = 300;
                    }
                }
                let backend = Arc::new(DelayedCommit::default());
                let resolver = Resolver::with_cache_engine(
                    (*base.transport).clone(),
                    base.config.clone(),
                    CacheEngineConfig::new(
                        backend.clone(),
                        b"dname-terminal-cas".to_vec(),
                        [0x39; 32],
                    )
                    .unwrap(),
                );
                admit(&resolver, &question, &mut reply).await;
                let initial = resolver
                    .cached_client_response_backend(&question)
                    .await
                    .unwrap()
                    .expect("complete authenticated DNAME hit before delayed commit");
                assert!(initial.response.headers.ad);
                backend.delay.store(true, Ordering::SeqCst);
                let expired = resolver
                    .cached_client_response_backend(&question)
                    .await
                    .unwrap();
                assert_eq!(backend.delayed_commits.load(Ordering::SeqCst), 1);
                assert!(
                    expired.is_none(),
                    "post-CAS selection must discard expired proof, not expose stale AD"
                );
                assert!(
                    resolver
                        .cached_client_response_backend(&question)
                        .await
                        .unwrap()
                        .is_none()
                );
            })
        }));
        runtime.shutdown_timeout(Duration::from_millis(100));
        let _ = send.send(result);
    });
    if let Err(panic) = receive
        .recv_timeout(Duration::from_secs(10))
        .expect("external DNAME cache operation exceeded bounded watchdog")
    {
        std::panic::resume_unwind(panic);
    }
}
