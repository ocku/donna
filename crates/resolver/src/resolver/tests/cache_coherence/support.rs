use std::{net::SocketAddr, time::Duration};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};
use transport::{Transport, TransportError};

use super::Resolver;
use crate::{ResolverConfig, protocol::query};

#[derive(Clone, Copy)]
struct UnusedTransport;


impl Transport for UnusedTransport {
    fn exchange<'future>(
        &'future self,
        _server: SocketAddr,
        _query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> { Box::pin(async move {
        Err(TransportError::Timeout)
    }) }
}

fn new_resolver() -> Resolver<UnusedTransport> {
    Resolver::new(
        UnusedTransport,
        ResolverConfig {
            cache_capacity: 16,
            ..ResolverConfig::default()
        },
    )
}

fn resolver_with_ttl_limits(
    max_ttl: Duration,
    max_negative_ttl: Duration,
) -> Resolver<UnusedTransport> {
    Resolver::new(
        UnusedTransport,
        ResolverConfig {
            cache_capacity: 16,
            max_ttl,
            max_negative_ttl,
            ..ResolverConfig::default()
        },
    )
}

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(qtype: QueryType) -> Question {
    Question {
        qname: name(&["owner", "example"]),
        qtype,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn positive(question: &Question, rtype: RecordType, rdata: RData, authoritative: bool) -> Message {
    Message {
        headers: Headers {
            id: 1,
            qr: true,
            aa: authoritative,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![ResourceRecord {
            name: question.qname.clone(),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata,
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn address(question: &Question, authoritative: bool) -> Message {
    positive(
        question,
        RecordType::A,
        RData::A("192.0.2.1".parse().unwrap()),
        authoritative,
    )
}

fn text(question: &Question, authoritative: bool) -> Message {
    positive(
        question,
        RecordType::TXT,
        RData::TXT(vec![b"coherent".to_vec()]),
        authoritative,
    )
}

fn query_type_for_record(rtype: RecordType) -> QueryType {
    match rtype {
        RecordType::A => QueryType::A,
        RecordType::MD => QueryType::MD,
        RecordType::MF => QueryType::MF,
        RecordType::MB => QueryType::MB,
        RecordType::MG => QueryType::MG,
        RecordType::MR => QueryType::MR,
        RecordType::TXT => QueryType::TXT,
        _ => unreachable!("the cache-coherence table uses only concrete aggregate members"),
    }
}

fn aggregate_rdata(rtype: RecordType) -> RData {
    let target = name(&["mail", "example"]);
    match rtype {
        RecordType::A => RData::A("192.0.2.1".parse().unwrap()),
        RecordType::MD => RData::MD(target),
        RecordType::MF => RData::MF(target),
        RecordType::MB => RData::MB(target),
        RecordType::MG => RData::MG(target),
        RecordType::MR => RData::MR(target),
        RecordType::TXT => RData::TXT(vec![b"coherent".to_vec()]),
        _ => unreachable!("the cache-coherence table uses only concrete aggregate members"),
    }
}

fn aggregate_positive(qtype: QueryType, members: &[RecordType]) -> Message {
    let aggregate_question = question(qtype);
    let mut reply = positive(
        &aggregate_question,
        members[0],
        aggregate_rdata(members[0]),
        true,
    );
    reply
        .answers
        .extend(members[1..].iter().map(|&rtype| ResourceRecord {
            name: aggregate_question.qname.clone(),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata: aggregate_rdata(rtype),
        }));
    reply
}

fn aggregate_families() -> [(QueryType, &'static [RecordType]); 3] {
    [
        (QueryType::ANY, &[RecordType::A, RecordType::TXT]),
        (QueryType::MAILA, &[RecordType::MD, RecordType::MF]),
        (
            QueryType::MAILB,
            &[RecordType::MB, RecordType::MG, RecordType::MR],
        ),
    ]
}

fn cname(question: &Question, authoritative: bool) -> Message {
    positive(
        question,
        RecordType::CNAME,
        RData::CNAME(name(&["target", "example"])),
        authoritative,
    )
}

fn negative(question: &Question, rcode: RCode, authoritative: bool) -> Message {
    Message {
        headers: Headers {
            id: 1,
            qr: true,
            aa: authoritative,
            rcode,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::SOA {
                mname: name(&["ns", "example"]),
                rname: name(&["hostmaster", "example"]),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 60,
            },
        }],
        additionals: Vec::new(),
    }
}

fn positive_hit(resolver: &Resolver<UnusedTransport>, question: &Question) -> Option<Message> {
    resolver
        .positive_cache
        .get(&query(0, question, resolver.config.edns_udp_payload_size))
}
