//! Secure DNAME provenance must survive an insecure terminal without raising AD.
mod backend;
use super::super::{
    fixtures::{insecure_fixture, resolver},
    support::{TestRng, name},
};
use dns::{
    ClassType, DnssecSecurityStatus, Headers, Message, QClassType, QueryType, Question, RData,
    RecordType, ResourceRecord,
};
use rsa::pkcs8::EncodePrivateKey;
use std::{net::SocketAddr, time::Duration};
use transport::{BoxFuture, Transport, TransportError};

#[derive(Clone)]
struct DelayedKey(super::super::support::SignedTransport);

#[derive(Default)]
struct DelayedCheckout {
    inner: crate::resolver::tests::external_backend::Backend,
    delay: std::sync::atomic::AtomicBool,
    delay_admission: std::sync::atomic::AtomicBool,
}

impl crate::CacheEngine for DelayedCheckout {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> BoxFuture<'a, std::io::Result<crate::CacheReadResult>> {
        Box::pin(async move {
            if self.delay.swap(false, std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2200)).await;
            }
            self.inner.read(namespace, expected_revision, plan).await
        })
    }
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        revision: &'a [u8],
        bytes: &'a crate::CacheMutationBatch,
    ) -> BoxFuture<'a, std::io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let touches_test_zone = bytes.mutations.iter().any(|mutation| {
                let key = match mutation {
                    crate::CacheMutation::Put(entry) => &entry.key,
                    crate::CacheMutation::Remove(key) | crate::CacheMutation::Access(key) => key,
                };
                key.family.owner.ends_with(b"\x03old\x07example\x00")
            });
            if touches_test_zone
                && self
                    .delay_admission
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                tokio::time::sleep(Duration::from_millis(5200)).await;
            }
            self.inner.apply(namespace, revision, bytes).await
        })
    }
}

#[derive(Clone)]
struct MixedTransport {
    upstream: super::super::support::InsecureTransport,
    source: Message,
}

impl Transport for MixedTransport {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            if query.questions[0]
                .qname
                .eq_dns(&name(&["www", "old", "example"]))
                && query.questions[0].qtype == QueryType::A
            {
                self.upstream.requests.lock().unwrap().push(query.clone());
                let mut response = self.source.clone();
                response.headers.id = query.headers.id;
                response.questions.clone_from(&query.questions);
                Ok(response)
            } else {
                self.upstream.exchange(server, query, timeout).await
            }
        })
    }
}

impl Transport for DelayedKey {
    fn exchange<'a>(
        &'a self,
        server: SocketAddr,
        query: &'a Message,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            if query.questions[0].qtype == QueryType::DNSKEY {
                tokio::time::sleep(Duration::from_millis(1200)).await;
            }
            self.0.exchange(server, query, timeout).await
        })
    }
}

fn mixed_answer() -> (
    super::super::support::InsecureTransport,
    ResourceRecord,
    Question,
    Message,
) {
    let (transport, anchor, _) = insecure_fixture();
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let owner = name(&["old", "example"]);
    let question = Question {
        qname: name(&["www", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let dname = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::DNAME(name(&["child", "example"])),
    };
    let now = super::super::super::unix_time();
    let signature = key
        .sign_rrset(
            std::slice::from_ref(&dname),
            &name(&["example"]),
            now.wrapping_sub(60),
            now + 3600,
        )
        .unwrap();
    let mut answers = vec![
        dname,
        ResourceRecord {
            name: owner,
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::RRSIG(signature),
        },
        ResourceRecord {
            name: question.qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 120,
            rdata: RData::CNAME(name(&["www", "child", "example"])),
        },
    ];
    answers.extend(transport.answer.answers.clone());
    let reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers,
        authorities: vec![],
        additionals: vec![],
    };
    (transport, anchor, question, reply)
}

#[test]
fn dname_placeholder_requires_a_matching_dname_rrset() {
    let (_, _, _, mut reply) = mixed_answer();
    let mut signature = reply.answers[1].clone();
    signature.ttl = 0;
    let deadline = Some(std::time::Instant::now() + Duration::from_secs(10));

    reply.answers = vec![signature.clone()];
    super::super::super::response_ttls::restore_dname_placeholder(&mut reply, deadline);
    assert_eq!(reply.answers[0].ttl, 0);

    let (_, _, _, mut reply) = mixed_answer();
    reply.answers.truncate(2);
    reply.answers[0].ttl = 0;
    reply.answers[1].ttl = 0;
    let mut wrong_owner = signature.clone();
    wrong_owner.name = name(&["other", "example"]);
    let mut wrong_class = signature;
    wrong_class.class = ClassType::CH;
    reply.answers.extend([wrong_owner, wrong_class]);
    super::super::super::response_ttls::restore_dname_placeholder(&mut reply, deadline);
    assert_eq!(
        reply.answers.iter().map(|rr| rr.ttl).collect::<Vec<_>>(),
        [1, 1, 0, 0]
    );
}

#[tokio::test]
async fn secure_dname_from_insecure_combined_answer_is_cached_without_raising_ad() {
    let (transport, anchor, question, mut reply) = mixed_answer();
    let resolver = resolver(transport, anchor);
    let validation = resolver
        .validate_dnssec_response_with_dnames(&question, &mut reply)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Insecure);
    assert_eq!(validation.secure_dnames.len(), 1);
    reply.headers.ad = false;
    resolver
        .cache_validated_response_with_dnames_backend(&reply, &question, &validation)
        .await
        .unwrap();
    let other = Question {
        qname: name(&["other", "old", "example"]),
        ..question
    };
    assert!(resolver.select_cached_dname(&other).is_some());
    assert!(!reply.headers.ad);
}

#[tokio::test]
async fn outer_resolver_admits_secure_dname_with_insecure_target_and_zero_ttl_alias() {
    let (transport, anchor, question, mut reply) = mixed_answer();
    reply.answers[2].ttl = 0;
    let requests = transport.requests.clone();
    let resolver = resolver(
        MixedTransport {
            upstream: transport,
            source: reply,
        },
        anchor,
    );
    let response = resolver.resolve(question).await.unwrap();
    assert!(!response.headers.ad);
    assert_eq!(
        response
            .answers
            .iter()
            .find(|rr| rr.rtype == RecordType::CNAME)
            .unwrap()
            .ttl,
        0
    );
    let second = Question {
        qname: name(&["other", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let before = requests.lock().unwrap().len();
    let answer = resolver.resolve(second.clone()).await.unwrap();
    assert!(answer.headers.ad);
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|q| q.questions[0].qname.eq_dns(&second.qname))
    );
}

#[tokio::test]
async fn live_subsecond_dname_is_cacheable_but_never_outlives_its_deadline() {
    let (mut transport, anchor, _) = super::super::fixtures::signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    for record in &mut transport.answer.answers {
        record.ttl = 1;
    }
    let question = Question {
        qname: name(&["www", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    transport.answer.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::CNAME(name(&["www", "new", "example"])),
    });
    let resolver = resolver(transport, anchor);
    let response = resolver.resolve(question.clone()).await.unwrap();
    assert!(response.headers.ad);
    assert_eq!(
        response
            .answers
            .iter()
            .find(|rr| rr.rtype == RecordType::CNAME)
            .unwrap()
            .ttl,
        0
    );
    let selection = resolver
        .select_cached_dname(&question)
        .expect("live subsecond proof");
    assert_eq!(selection.selection.ttl(), 0);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!selection.selection.is_live());
    assert!(resolver.select_cached_dname(&question).is_none());
}

#[tokio::test]
async fn placeholder_is_never_exposed_for_insecure_or_indeterminate_dname() {
    let (transport, anchor, _) = insecure_fixture();
    let question = Question {
        qname: name(&["www", "old", "child", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let original = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![
            ResourceRecord {
                name: name(&["old", "child", "example"]),
                rtype: RecordType::DNAME,
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::DNAME(name(&["target", "child", "example"])),
            },
            ResourceRecord {
                name: question.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 0,
                rdata: RData::CNAME(name(&["www", "target", "child", "example"])),
            },
        ],
        authorities: vec![],
        additionals: vec![],
    };
    let validating = resolver(transport.clone(), anchor);
    let mut insecure = original.clone();
    let cap = std::time::Instant::now() + Duration::from_millis(900);
    let outcome = validating
        .validate_dnssec_response_with_deadline(&question, &mut insecure, Some(cap))
        .await
        .unwrap();
    assert_eq!(outcome.status, DnssecSecurityStatus::Insecure);
    assert!(outcome.secure_dnames.is_empty());
    assert!(insecure.answers.iter().all(|record| record.ttl == 0));
    let mut config = validating.config.clone();
    config.trust_anchors.clear();
    let nonvalidating = crate::Resolver::new(transport, config);
    let mut indeterminate = original;
    let outcome = nonvalidating
        .validate_dnssec_response_with_deadline(&question, &mut indeterminate, Some(cap))
        .await
        .unwrap();
    assert_eq!(outcome.status, DnssecSecurityStatus::Indeterminate);
    assert!(outcome.secure_dnames.is_empty());
    assert!(indeterminate.answers.iter().all(|record| record.ttl == 0));
}

#[tokio::test]
async fn bogus_dname_does_not_produce_secure_provenance() {
    let (transport, anchor, question, mut reply) = mixed_answer();
    let resolver = resolver(transport, anchor);
    if let RData::RRSIG(signature) = &mut reply.answers[1].rdata {
        signature.signature[0] ^= 1;
    }
    reply.headers.ad = true; // A forged upstream AD bit is irrelevant.
    assert!(
        resolver
            .validate_dnssec_response_with_dnames(&question, &mut reply)
            .await
            .is_err()
    );
    assert!(resolver.select_cached_dname(&question).is_none());
}

#[tokio::test]
async fn valid_dname_followed_by_bogus_terminal_yields_no_admission() {
    let (transport, anchor, question, mut reply) = mixed_answer();
    let resolver = resolver(transport, anchor);
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    reply.answers[0].rdata = RData::DNAME(name(&["target", "example"]));
    reply.answers[2].rdata = RData::CNAME(name(&["www", "target", "example"]));
    reply.answers[3].name = name(&["www", "target", "example"]);
    let now = super::super::super::unix_time();
    let dname_sig = key
        .sign_rrset(
            &[reply.answers[0].clone()],
            &name(&["example"]),
            now.wrapping_sub(60),
            now + 3600,
        )
        .unwrap();
    reply.answers[1].rdata = RData::RRSIG(dname_sig);
    let mut terminal_sig = key
        .sign_rrset(
            &[reply.answers[3].clone()],
            &name(&["example"]),
            now.wrapping_sub(60),
            now + 3600,
        )
        .unwrap();
    terminal_sig.signature[0] ^= 1;
    reply.answers.push(ResourceRecord {
        name: reply.answers[3].name.clone(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::RRSIG(terminal_sig),
    });
    assert!(
        resolver
            .validate_dnssec_response_with_dnames(&question, &mut reply)
            .await
            .is_err()
    );
    assert!(resolver.select_cached_dname(&question).is_none());
}

#[tokio::test]
async fn key_acquisition_delay_cannot_renew_dname_ttl() {
    let (mut transport, anchor, _) = super::super::fixtures::signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    for record in &mut transport.answer.answers {
        record.ttl = 1;
    }
    let resolver = resolver(DelayedKey(transport), anchor);
    let question = Question {
        qname: name(&["www", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let response = resolver.resolve(question.clone()).await.unwrap();
    assert!(response.headers.ad);
    assert_eq!(
        response
            .answers
            .iter()
            .find(|rr| rr.rtype == RecordType::DNAME)
            .unwrap()
            .ttl,
        0
    );
    assert!(resolver.select_cached_dname(&question).is_none());
}
