//! Genuine zero-TTL DNAME proof components must not be promoted.
use super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use super::cache::network::Routed;
use dns::{ClassType, QClassType, QueryType, Question, RData, RecordType};
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

#[tokio::test]
async fn actual_zero_dname_or_signature_after_live_alias_is_not_cached() {
    for zero_index in [0, 1] {
        let (mut source, anchor, _) = signed_record_fixture(
            false,
            name(&["old", "example"]),
            QueryType::DNAME,
            RecordType::DNAME,
            RData::DNAME(name(&["new", "example"])),
        );
        source.answer.answers[zero_index].ttl = 0;
        let alias = signed_record_fixture(
            false,
            name(&["alias", "example"]),
            QueryType::A,
            RecordType::CNAME,
            RData::CNAME(name(&["www", "old", "example"])),
        )
        .0
        .answer;
        let terminal = signed_record_fixture(
            false,
            name(&["www", "new", "example"]),
            QueryType::A,
            RecordType::A,
            RData::A(Ipv4Addr::new(192, 0, 2, 9)),
        )
        .0
        .answer;
        let transport = Routed {
            source: Arc::new(Mutex::new(source.answer)),
            targets: vec![alias, terminal],
            dnskey: source.dnskey,
            requests: Arc::new(Mutex::new(Vec::new())),
            servers: Arc::new(Mutex::new(Vec::new())),
        };
        let resolver = resolver(transport, anchor);
        let question = Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let reply = resolver.resolve(question).await.unwrap();
        assert!(reply.headers.ad);
        assert!(
            reply
                .answers
                .iter()
                .filter(|rr| rr.rtype == RecordType::DNAME)
                .all(|rr| rr.ttl == 0)
        );
        let next = Question {
            qname: name(&["next", "old", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        assert!(resolver.select_cached_dname(&next).is_none());
    }
}

#[tokio::test]
async fn overflow_with_zero_dname_proof_is_not_promoted_after_live_alias() {
    let destination = dns::DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    for zero_index in [0, 1] {
        let (mut source, anchor, _) = signed_record_fixture(
            false,
            name(&["old", "example"]),
            QueryType::DNAME,
            RecordType::DNAME,
            RData::DNAME(destination.clone()),
        );
        source.answer.answers[zero_index].ttl = 0;
        source.answer.headers.rcode = dns::RCode::YXDomain;
        let alias = signed_record_fixture(
            false,
            name(&["alias", "example"]),
            QueryType::A,
            RecordType::CNAME,
            RData::CNAME(name(&["www", "old", "example"])),
        )
        .0
        .answer;
        let transport = Routed {
            source: Arc::new(Mutex::new(source.answer)),
            targets: vec![alias],
            dnskey: source.dnskey,
            requests: Arc::new(Mutex::new(Vec::new())),
            servers: Arc::new(Mutex::new(Vec::new())),
        };
        let resolver = resolver(transport, anchor);
        let question = Question {
            qname: name(&["alias", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        let reply = resolver.resolve(question).await.unwrap();
        assert_eq!(reply.headers.rcode, dns::RCode::YXDomain);
        assert!(
            reply
                .answers
                .iter()
                .filter(|rr| rr.rtype == RecordType::DNAME)
                .all(|rr| rr.ttl == 0)
        );
        let next = Question {
            qname: name(&["next", "old", "example"]),
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        };
        assert!(resolver.select_cached_dname(&next).is_none());
    }
}
