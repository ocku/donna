use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord, Rrsig, RsaDnssecSigningKey,
};
use rsa::pkcs8::EncodePrivateKey;

use crate::{ResolverConfig, resolver::Resolver};

use super::{
    super::unix_time,
    support::{DelegatedTransport, InsecureTransport, SignedTransport, TestRng, name},
};

pub(super) fn signed_record_fixture(
    corrupt_answer: bool,
    owner: DomainName,
    qtype: QueryType,
    rtype: RecordType,
    rdata: RData,
) -> (SignedTransport, ResourceRecord, Question) {
    let zone = name(&["example"]);
    let class = ClassType::IN;
    let mut rng = TestRng(0xfeed_face_cafe_beef);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let signing_key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let dnskey = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(signing_key.dnskey().clone()),
    };
    let answer = ResourceRecord {
        name: owner.clone(),
        rtype,
        class,
        ttl: 300,
        rdata,
    };
    let now = unix_time();
    let answer_signature = signing_key
        .sign_rrset(
            std::slice::from_ref(&answer),
            &zone,
            now.wrapping_sub(60),
            now + 3_600,
        )
        .unwrap();
    let dnskey_signature = signing_key
        .sign_rrset(
            std::slice::from_ref(&dnskey),
            &zone,
            now.wrapping_sub(60),
            now + 3_600,
        )
        .unwrap();
    let signature_record = |owner: DomainName, mut signature: Rrsig| {
        if corrupt_answer && signature.type_covered == u16::from(rtype) {
            signature.signature[0] ^= 0xff;
        }
        ResourceRecord {
            name: owner,
            rtype: RecordType::RRSIG,
            class,
            ttl: 300,
            rdata: RData::RRSIG(signature),
        }
    };
    let question = Question {
        qname: owner.clone(),
        qtype,
        qclass: QClassType::Class(class),
    };
    let base_headers = Headers {
        qr: true,
        aa: true,
        rcode: RCode::Ok,
        ..Headers::default()
    };
    let mut received_answer = answer;
    received_answer.ttl = 900;
    let answer_response = Message {
        headers: base_headers.clone(),
        questions: vec![question.clone()],
        answers: vec![received_answer, signature_record(owner, answer_signature)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let dnskey_question = Question {
        qname: zone.clone(),
        qtype: QueryType::DNSKEY,
        qclass: QClassType::Class(class),
    };
    let dnskey_response = Message {
        headers: base_headers,
        questions: vec![dnskey_question],
        answers: vec![dnskey.clone(), signature_record(zone, dnskey_signature)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    (
        SignedTransport {
            answer: answer_response,
            dnskey: dnskey_response,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        dnskey,
        question,
    )
}

pub(super) fn signed_fixture(corrupt_answer: bool) -> (SignedTransport, ResourceRecord, Question) {
    signed_record_fixture(
        corrupt_answer,
        name(&["www", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )
}

pub(super) fn resolver<T: transport::Transport>(
    transport: T,
    anchor: ResourceRecord,
) -> Resolver<T> {
    Resolver::new(
        transport,
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            trust_anchors: vec![anchor],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    )
}

pub(super) fn insecure_fixture() -> (InsecureTransport, ResourceRecord, Question) {
    insecure_delegation_fixture(false)
}

pub(super) fn insecure_delegation_fixture(
    wildcard: bool,
) -> (InsecureTransport, ResourceRecord, Question) {
    let parent = name(&["example"]);
    let child = name(&["child", "example"]);
    let owner = name(&["www", "child", "example"]);
    let class = ClassType::IN;
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let signing_key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let dnskey = ResourceRecord {
        name: parent.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(signing_key.dnskey().clone()),
    };
    let now = unix_time();
    let dnskey_signature = signing_key
        .sign_rrset(
            std::slice::from_ref(&dnskey),
            &parent,
            now.wrapping_sub(60),
            now + 3_600,
        )
        .unwrap();
    let nsec = ResourceRecord {
        name: if wildcard {
            name(&["*", "example"])
        } else {
            child.clone()
        },
        rtype: RecordType::NSEC,
        class,
        ttl: 300,
        rdata: RData::NSEC(dns::Nsec {
            next_domain_name: parent.clone(),
            type_bitmap: dns::TypeBitmap::new([
                u16::from(if wildcard {
                    RecordType::A
                } else {
                    RecordType::NS
                }),
                u16::from(RecordType::RRSIG),
                u16::from(RecordType::NSEC),
            ])
            .unwrap(),
        }),
    };
    let nsec_signature = signing_key
        .sign_rrset(
            std::slice::from_ref(&nsec),
            &parent,
            now.wrapping_sub(60),
            now + 3_600,
        )
        .unwrap();
    let signature_record = |owner: DomainName, signature: Rrsig| ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class,
        ttl: 300,
        rdata: RData::RRSIG(signature),
    };
    let question = Question {
        qname: owner.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(class),
    };
    let answer = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![ResourceRecord {
            name: owner,
            rtype: RecordType::A,
            class,
            ttl: 900,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let soa = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: child.clone(),
            rtype: RecordType::SOA,
            class,
            ttl: 300,
            rdata: RData::SOA {
                mname: name(&["ns", "child", "example"]),
                rname: name(&["hostmaster", "child", "example"]),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 300,
            },
        }],
        additionals: Vec::new(),
    };
    let ds = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![
            ResourceRecord {
                name: child.clone(),
                rtype: RecordType::NS,
                class,
                ttl: 300,
                rdata: RData::NS(name(&["ns", "child", "example"])),
            },
            signature_record(nsec.name.clone(), nsec_signature),
            nsec,
        ],
        additionals: Vec::new(),
    };
    let dnskey_response = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: vec![dnskey.clone(), signature_record(parent, dnskey_signature)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    (
        InsecureTransport {
            answer,
            soa,
            ds,
            dnskey: dnskey_response,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        dnskey,
        question,
    )
}

pub(super) fn delegated_fixture() -> (DelegatedTransport, ResourceRecord, Question) {
    let parent = name(&["example"]);
    let child = name(&["child", "example"]);
    let owner = name(&["www", "child", "example"]);
    let class = ClassType::IN;
    let make_key = |seed| {
        let mut rng = TestRng(seed);
        let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
        let der = private.to_pkcs8_der().unwrap();
        RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap()
    };
    let parent_key = make_key(0x1111_2222_3333_4444);
    let child_key = make_key(0x5555_6666_7777_8888);
    let parent_dnskey = ResourceRecord {
        name: parent.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(parent_key.dnskey().clone()),
    };
    let child_dnskey = ResourceRecord {
        name: child.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(child_key.dnskey().clone()),
    };
    let ds = ResourceRecord {
        name: child.clone(),
        rtype: RecordType::DS,
        class,
        ttl: 300,
        rdata: RData::DS(child_key.dnskey().to_ds(&child, 2).unwrap()),
    };
    let answer = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::A,
        class,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 3)),
    };
    let now = unix_time();
    let sign = |key: &RsaDnssecSigningKey, signer: &DomainName, rrset: &[ResourceRecord]| {
        key.sign_rrset(rrset, signer, now.wrapping_sub(60), now + 3_600)
            .unwrap()
    };
    let signature_record = |owner: DomainName, signature: Rrsig| ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class,
        ttl: 300,
        rdata: RData::RRSIG(signature),
    };
    let message = |answers: Vec<ResourceRecord>| Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let question = Question {
        qname: owner.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(class),
    };
    let answer_response = message(vec![
        answer.clone(),
        signature_record(owner, sign(&child_key, &child, &[answer])),
    ]);
    let ds_response = message(vec![
        ds.clone(),
        signature_record(child.clone(), sign(&parent_key, &parent, &[ds])),
    ]);
    let parent_dnskey_response = message(vec![
        parent_dnskey.clone(),
        signature_record(
            parent.clone(),
            sign(&parent_key, &parent, std::slice::from_ref(&parent_dnskey)),
        ),
    ]);
    let child_dnskey_response = message(vec![
        child_dnskey.clone(),
        signature_record(
            child.clone(),
            sign(&child_key, &child, std::slice::from_ref(&child_dnskey)),
        ),
    ]);
    (
        DelegatedTransport {
            parent,
            answer: answer_response,
            ds: ds_response,
            parent_dnskey: parent_dnskey_response,
            child_dnskey: child_dnskey_response,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        parent_dnskey,
        question,
    )
}
