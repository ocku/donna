mod aggressive;
mod alias;
mod authority;

use std::sync::{Arc, Mutex};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord, Rrsig, RsaDnssecSigningKey,
};
use rsa::pkcs8::EncodePrivateKey;

use super::{
    super::unix_time,
    support::{SignedTransport, TestRng, name},
};

pub(super) fn negative_fixture() -> (SignedTransport, ResourceRecord, Question) {
    negative_fixture_for_type(false)
}

pub(super) fn negative_ds_fixture() -> (SignedTransport, ResourceRecord, Question) {
    negative_fixture_for_type(true)
}

fn negative_fixture_for_type(ds: bool) -> (SignedTransport, ResourceRecord, Question) {
    let zone = name(&["example"]);
    let qname = name(&["missing", "example"]);
    let class = ClassType::IN;
    let mut rng = TestRng(0xabcd_ef01_2345_6789);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let dnskey = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(key.dnskey().clone()),
    };
    let soa = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::SOA,
        class,
        ttl: 300,
        rdata: RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 300,
        },
    };
    let nsec = ResourceRecord {
        name: if ds { qname.clone() } else { zone.clone() },
        rtype: RecordType::NSEC,
        class,
        ttl: 300,
        rdata: RData::NSEC(dns::Nsec {
            next_domain_name: zone.clone(),
            type_bitmap: dns::TypeBitmap::new(if ds {
                vec![
                    u16::from(RecordType::NS),
                    u16::from(RecordType::RRSIG),
                    u16::from(RecordType::NSEC),
                ]
            } else {
                vec![
                    u16::from(RecordType::NS),
                    u16::from(RecordType::SOA),
                    u16::from(RecordType::RRSIG),
                    u16::from(RecordType::NSEC),
                    u16::from(RecordType::DNSKEY),
                ]
            })
            .unwrap(),
        }),
    };
    let now = unix_time();
    let sign = |rrset: &[ResourceRecord]| {
        key.sign_rrset(rrset, &zone, now.wrapping_sub(60), now + 3_600)
            .unwrap()
    };
    let signature_record = |owner: DomainName, signature: Rrsig| ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class,
        ttl: 300,
        rdata: RData::RRSIG(signature),
    };
    let question = Question {
        qname,
        qtype: if ds { QueryType::DS } else { QueryType::A },
        qclass: QClassType::Class(class),
    };
    let negative = Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode: if ds { RCode::Ok } else { RCode::NameError },
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![
            soa.clone(),
            signature_record(zone.clone(), sign(std::slice::from_ref(&soa))),
            nsec.clone(),
            signature_record(nsec.name.clone(), sign(std::slice::from_ref(&nsec))),
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
        answers: vec![
            dnskey.clone(),
            signature_record(zone.clone(), sign(std::slice::from_ref(&dnskey))),
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    (
        SignedTransport {
            answer: negative,
            dnskey: dnskey_response,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        dnskey,
        question,
    )
}

pub(super) fn nsec3_negative_fixture() -> (SignedTransport, ResourceRecord, Question) {
    let zone = name(&["example"]);
    let qname = name(&["missing", "example"]);
    let class = ClassType::IN;
    let mut rng = TestRng(0x0ddc_0ffe_e15e_beef);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let dnskey = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::DNSKEY,
        class,
        ttl: 300,
        rdata: RData::DNSKEY(key.dnskey().clone()),
    };
    let soa = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::SOA,
        class,
        ttl: 300,
        rdata: RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 300,
        },
    };
    let ns = ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::NS,
        class,
        ttl: 300,
        rdata: RData::NS(name(&["ns", "example"])),
    };
    let chain = dns::Nsec3Chain::build(
        &zone,
        class,
        &[soa.clone(), ns, dnskey.clone()],
        dns::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
        },
        300,
        false,
        0,
    )
    .unwrap();
    let proof = chain.records()[0].clone();
    let now = unix_time();
    let sign = |rrset: &[ResourceRecord]| {
        key.sign_rrset(rrset, &zone, now.wrapping_sub(60), now + 3_600)
            .unwrap()
    };
    let signature_record = |owner: DomainName, signature: Rrsig| ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class,
        ttl: 300,
        rdata: RData::RRSIG(signature),
    };
    let question = Question {
        qname,
        qtype: QueryType::A,
        qclass: QClassType::Class(class),
    };
    let negative = Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode: RCode::NameError,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![
            soa.clone(),
            signature_record(zone.clone(), sign(std::slice::from_ref(&soa))),
            proof.clone(),
            signature_record(proof.name.clone(), sign(std::slice::from_ref(&proof))),
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
        answers: vec![
            dnskey.clone(),
            signature_record(zone.clone(), sign(std::slice::from_ref(&dnskey))),
        ],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    (
        SignedTransport {
            answer: negative,
            dnskey: dnskey_response,
            requests: Arc::new(Mutex::new(Vec::new())),
        },
        dnskey,
        question,
    )
}
