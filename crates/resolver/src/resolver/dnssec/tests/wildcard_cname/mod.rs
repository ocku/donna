use super::support::{TestRng, name};
use crate::{ResolutionCacheSource, ResolverConfig, resolver::Resolver};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord, RsaDnssecSigningKey,
};
use rsa::pkcs8::EncodePrivateKey;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use transport::{Transport, TransportError};

mod deadlines;

#[derive(Clone)]
struct SplitTransport {
    alias: Message,
    target: Message,
    keys: Vec<Message>,
    requests: Arc<Mutex<usize>>,
}

impl Transport for SplitTransport {
    fn exchange<'future>(
        &'future self,
        _: SocketAddr,
        query: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            *self.requests.lock().unwrap() += 1;
            let q = &query.questions[0];
            let mut reply = if q.qtype == QueryType::DNSKEY {
                self.keys
                    .iter()
                    .find(|message| message.answers[0].name.eq_dns(&q.qname))
                    .unwrap()
                    .clone()
            } else if q.qname.eq_dns(&self.alias.answers[0].name) {
                self.alias.clone()
            } else {
                self.target.clone()
            };
            reply.headers.id = query.headers.id;
            reply.questions = query.questions.clone();
            Ok(reply)
        })
    }
}

fn fixture(validating: bool) -> (Resolver<SplitTransport>, Question, Arc<Mutex<usize>>) {
    fixture_with_negative(validating, None)
}

fn fixture_with_negative(
    validating: bool,
    negative: Option<dns::RCode>,
) -> (Resolver<SplitTransport>, Question, Arc<Mutex<usize>>) {
    let now = super::super::unix_time();
    let mut rng = TestRng(0x5892_1234_5678_abcd);
    let mut anchors = Vec::new();
    let mut keys = Vec::new();
    let mut signing_keys = Vec::new();
    for zone in [name(&["example"]), name(&["other"])] {
        let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let der = private.to_pkcs8_der().unwrap();
        let key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
        let anchor = ResourceRecord {
            name: zone.clone(),
            class: ClassType::IN,
            rtype: RecordType::DNSKEY,
            ttl: 300,
            rdata: RData::DNSKEY(key.dnskey().clone()),
        };
        let signature = sign(&key, &zone, &anchor, now, 300);
        keys.push(packet(vec![anchor.clone(), signature], vec![]));
        anchors.push(anchor);
        signing_keys.push(key);
    }
    let target = name(&["target", "other"]);
    let mut alias = ResourceRecord {
        name: name(&["*", "alias", "example"]),
        class: ClassType::IN,
        rtype: RecordType::CNAME,
        ttl: 300,
        rdata: RData::CNAME(target.clone()),
    };
    let mut signature = sign(&signing_keys[0], &name(&["example"]), &alias, now, 300);
    alias.name = name(&["foo", "alias", "example"]);
    signature.name = alias.name.clone();
    let proof = dns::master::MasterFile::parse(
        "*.alias.example. 300 IN NSEC z.alias.example. CNAME RRSIG NSEC",
        None,
    )
    .unwrap()
    .records
    .remove(0);
    let proof_signature = sign(&signing_keys[0], &name(&["example"]), &proof, now, 7);
    let address = ResourceRecord {
        name: target,
        class: ClassType::IN,
        rtype: RecordType::A,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let address_signature = sign(&signing_keys[1], &name(&["other"]), &address, now, 300);
    let mut terminal = packet(vec![address, address_signature], vec![]);
    if let Some(rcode) = negative {
        let records = dns::master::MasterFile::parse(
            if rcode == dns::RCode::NameError {
                "other. 300 IN SOA ns.other. hostmaster.other. 1 2 3 4 300\nother. 300 IN NSEC other. SOA NS RRSIG NSEC DNSKEY"
            } else {
                "other. 300 IN SOA ns.other. hostmaster.other. 1 2 3 4 300\ntarget.other. 300 IN NSEC z.other. RRSIG NSEC"
            },
            None,
        ).unwrap().records;
        let signatures = records
            .iter()
            .map(|record| sign(&signing_keys[1], &name(&["other"]), record, now, 300))
            .collect::<Vec<_>>();
        terminal.answers.clear();
        terminal.headers.rcode = rcode;
        terminal.authorities = records;
        terminal.authorities.extend(signatures);
    }
    let question = Question {
        qname: alias.name.clone(),
        qclass: QClassType::Class(ClassType::IN),
        qtype: QueryType::A,
    };
    let requests = Arc::new(Mutex::new(0));
    let transport = SplitTransport {
        alias: packet(vec![alias, signature], vec![proof, proof_signature]),
        target: terminal,
        keys,
        requests: Arc::clone(&requests),
    };
    let resolver = Resolver::new(
        transport,
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            trust_anchors: if validating { anchors } else { vec![] },
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    (resolver, question, requests)
}

fn sign(
    key: &RsaDnssecSigningKey,
    zone: &DomainName,
    record: &ResourceRecord,
    now: u32,
    ttl: u32,
) -> ResourceRecord {
    ResourceRecord {
        name: record.name.clone(),
        class: ClassType::IN,
        rtype: RecordType::RRSIG,
        ttl,
        rdata: RData::RRSIG(
            key.sign_rrset(
                std::slice::from_ref(record),
                zone,
                now.wrapping_sub(60),
                now + 3600,
            )
            .unwrap(),
        ),
    }
}
fn packet(answers: Vec<ResourceRecord>, authorities: Vec<ResourceRecord>) -> Message {
    Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![],
        answers,
        authorities,
        additionals: vec![],
    }
}
fn assert_proofs(response: &Message) {
    assert!(
        response
            .authorities
            .iter()
            .any(|rr| rr.rtype == RecordType::NSEC)
    );
    assert!(response.authorities.iter().any(|rr| matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(RecordType::NSEC))));
    assert!(
        response
            .answers
            .iter()
            .any(|rr| rr.rtype == RecordType::CNAME)
    );
    assert!(response.answers.iter().any(|rr| rr.rtype == RecordType::A));
}

#[tokio::test]
async fn validates_split_packet_wildcard_cname_across_zones() {
    let (resolver, question, _) = fixture(true);
    let response = resolver.resolve(question).await.unwrap();
    assert!(response.headers.ad);
    assert_proofs(&response);
    assert!(
        response
            .answers
            .iter()
            .filter(|rr| rr.rtype == RecordType::CNAME)
            .all(|rr| rr.ttl <= 7)
    );
}

#[tokio::test]
async fn cached_wildcard_cname_hops_keep_proofs_for_cached_and_network_targets() {
    for warm_target in [false, true] {
        let (resolver, question, requests) = fixture(false);
        resolver
            .resolve(Question {
                qtype: QueryType::CNAME,
                ..question.clone()
            })
            .await
            .unwrap();
        if warm_target {
            resolver
                .resolve(Question {
                    qname: name(&["target", "other"]),
                    ..question.clone()
                })
                .await
                .unwrap();
        }
        let before = *requests.lock().unwrap();
        let result = resolver.resolve_with_stats(question).await.unwrap();
        assert_proofs(result.response());
        if warm_target {
            assert_eq!(
                result.stats().final_cache_source(),
                Some(ResolutionCacheSource::Positive)
            );
            assert_eq!(*requests.lock().unwrap(), before);
        } else {
            assert_eq!(*requests.lock().unwrap(), before + 1);
        }
    }
}

#[tokio::test]
async fn direct_wildcard_cname_queries_are_secure_and_cached() {
    for qtype in [QueryType::CNAME, QueryType::ANY] {
        let (resolver, mut question, requests) = fixture(true);
        question.qtype = qtype;
        for _ in 0..2 {
            let response = resolver.resolve(question.clone()).await.unwrap();
            assert!(response.headers.ad, "{qtype:?}");
            assert!(
                response
                    .answers
                    .iter()
                    .any(|record| record.rtype == RecordType::CNAME)
            );
            assert!(
                !response
                    .answers
                    .iter()
                    .any(|record| record.rtype == RecordType::A)
            );
            assert!(
                response
                    .authorities
                    .iter()
                    .any(|record| record.rtype == RecordType::NSEC)
            );
        }
        assert_eq!(*requests.lock().unwrap(), 2, "{qtype:?}");
    }
}

#[tokio::test]
async fn validated_cname_components_serve_both_client_apis_without_network_io() {
    for negative in [None, Some(dns::RCode::Ok), Some(dns::RCode::NameError)] {
        let (resolver, question, requests) = fixture_with_negative(true, negative);
        let first = resolver.resolve(question.clone()).await.unwrap();
        assert!(first.headers.ad);
        let before = *requests.lock().unwrap();
        let hit = resolver.resolve(question.clone()).await.unwrap();
        let measured = resolver.resolve_with_stats(question.clone()).await.unwrap();
        assert_eq!(*requests.lock().unwrap(), before, "terminal {negative:?}");
        for cached in [&hit, measured.response()] {
            assert!(cached.headers.ad);
            assert_eq!(cached.headers.rcode, first.headers.rcode);
            assert_eq!(cached.questions.len(), 1);
            assert!(cached.questions[0].qname.eq_dns(&question.qname));
            assert_eq!(cached.questions[0].qtype, question.qtype);
            assert_eq!(cached.questions[0].qclass, question.qclass);
            assert!(
                cached
                    .answers
                    .iter()
                    .any(|rr| rr.rtype == RecordType::CNAME)
            );
            assert!(
                cached
                    .authorities
                    .iter()
                    .any(|rr| rr.rtype == RecordType::NSEC)
            );
            assert!(
                cached
                    .answers
                    .iter()
                    .filter(|rr| rr.rtype == RecordType::CNAME)
                    .all(|rr| rr.ttl <= 7)
            );
            if negative.is_some() {
                assert!(!cached.answers.iter().any(|rr| rr.rtype == RecordType::A));
                assert!(
                    cached
                        .authorities
                        .iter()
                        .any(|rr| rr.rtype == RecordType::SOA)
                );
            } else {
                assert!(cached.answers.iter().any(|rr| rr.rtype == RecordType::A));
            }
        }
        if negative.is_some() {
            let alias_only = resolver
                .resolve(Question {
                    qtype: QueryType::CNAME,
                    ..question.clone()
                })
                .await
                .unwrap();
            assert_eq!(alias_only.headers.rcode, dns::RCode::Ok);
            assert!(
                alias_only
                    .answers
                    .iter()
                    .any(|rr| rr.rtype == RecordType::CNAME)
            );
            let target_only = resolver
                .resolve(Question {
                    qname: name(&["target", "other"]),
                    ..question.clone()
                })
                .await
                .unwrap();
            assert!(target_only.answers.is_empty());
            assert!(target_only.headers.ad);
            assert_eq!(target_only.headers.rcode, first.headers.rcode);
            assert_eq!(*requests.lock().unwrap(), before);
        }
        assert_eq!(
            measured.stats().final_cache_source(),
            Some(if negative.is_some() {
                ResolutionCacheSource::Negative
            } else {
                ResolutionCacheSource::Positive
            })
        );
    }
}

#[tokio::test]
async fn cached_chain_ad_requires_every_alias_and_terminal_component() {
    for negative in [None, Some(dns::RCode::NameError)] {
        for downgrade_alias in [false, true] {
            let (resolver, question, requests) = fixture_with_negative(true, negative);
            resolver.resolve(question.clone()).await.unwrap();
            let component = Question {
                qname: if downgrade_alias {
                    question.qname.clone()
                } else {
                    name(&["target", "other"])
                },
                qtype: if downgrade_alias {
                    QueryType::CNAME
                } else {
                    QueryType::A
                },
                qclass: question.qclass,
            };
            let mut entry = if negative.is_some() && !downgrade_alias {
                resolver.cached_negative_response(&component).unwrap()
            } else {
                resolver.cached_positive_response(&component).unwrap()
            };
            entry.headers.ad = false;
            // Represents an independently admitted insecure component. This
            // unit test changes status without needing an unsigned delegation
            // fixture, while retaining all signed wildcard/denial material.
            if negative.is_some() && !downgrade_alias {
                entry.headers.aa = true;
            }
            resolver.cache_response_entries(0, &entry, &component, &component, entry.headers.aa);
            let before = *requests.lock().unwrap();
            let reply = resolver.resolve(question.clone()).await.unwrap();
            let measured = resolver.resolve_with_stats(question).await.unwrap();
            assert!(!reply.headers.ad);
            assert!(!measured.response().headers.ad);
            assert_eq!(*requests.lock().unwrap(), before);
        }
    }
}

#[tokio::test]
async fn insecure_composed_negative_does_not_gain_authoritative_cache_rank() {
    let (resolver, question, _) = fixture_with_negative(true, Some(dns::RCode::NameError));
    let mut response = resolver.resolve(question.clone()).await.unwrap();
    response.headers.ad = false;
    response.headers.aa = false;
    let (cold, _, _) = fixture_with_negative(true, Some(dns::RCode::NameError));
    cold.cache_validated_response(&response, &question);
    assert!(
        cold.cached_negative_response(&Question {
            qname: name(&["target", "other"]),
            ..question
        })
        .is_none()
    );
}
