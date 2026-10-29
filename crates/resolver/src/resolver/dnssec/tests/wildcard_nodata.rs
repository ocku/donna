use std::sync::{Arc, Mutex};

use dns::{
    ClassType, Headers, Message, QClassType, QueryType, Question, RCode, RData, RecordType,
    ResourceRecord, RsaDnssecSigningKey,
};
use rsa::pkcs8::EncodePrivateKey;

use super::{
    fixtures::resolver,
    support::{SignedTransport, TestRng, name},
};
use crate::ResolutionCacheSource;

fn fixture(nsec3: bool) -> (SignedTransport, ResourceRecord, Question) {
    let zone = name(&["example"]);
    let mut rng = TestRng(0x3782_1234_5678_abcd);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1_024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let dnskey = ResourceRecord {
        name: zone.clone(),
        class: ClassType::IN,
        rtype: RecordType::DNSKEY,
        ttl: 300,
        rdata: RData::DNSKEY(key.dnskey().clone()),
    };
    let source = dns::master::MasterFile::parse("example. 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 300\n*.example. 300 IN A 192.0.2.1", None).unwrap().records;
    let mut records = if nsec3 {
        dns::Nsec3Chain::build(
            &zone,
            ClassType::IN,
            &source,
            dns::Nsec3param {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: vec![],
            },
            300,
            false,
            0,
        )
        .unwrap()
        .records()
        .to_vec()
    } else {
        dns::master::MasterFile::parse("*.example. 300 IN NSEC a.example. A RRSIG NSEC\na.example. 300 IN NSEC z.example. A RRSIG NSEC", None).unwrap().records
    };
    records.push(source[0].clone());
    let now = super::super::unix_time();
    let sign = |record: &ResourceRecord| {
        let signature = key
            .sign_rrset(
                std::slice::from_ref(record),
                &zone,
                now.wrapping_sub(60),
                now + 3600,
            )
            .unwrap();
        ResourceRecord {
            name: record.name.clone(),
            class: ClassType::IN,
            rtype: RecordType::RRSIG,
            ttl: 7,
            rdata: RData::RRSIG(signature),
        }
    };
    let signatures = records.iter().map(sign).collect::<Vec<_>>();
    records.extend(signatures);
    let headers = Headers {
        qr: true,
        aa: true,
        ..Headers::default()
    };
    let question = Question {
        qname: name(&["foo", "m", "example"]),
        qtype: QueryType::AAAA,
        qclass: QClassType::Class(ClassType::IN),
    };
    let answer = Message {
        headers: headers.clone(),
        questions: vec![question.clone()],
        answers: vec![],
        authorities: records,
        additionals: vec![],
    };
    let dnskey_response = Message {
        headers,
        questions: vec![],
        answers: vec![dnskey.clone(), sign(&dnskey)],
        authorities: vec![],
        additionals: vec![],
    };
    (
        SignedTransport {
            answer,
            dnskey: dnskey_response,
            requests: Arc::new(Mutex::new(vec![])),
        },
        dnskey,
        question,
    )
}

#[tokio::test]
async fn validates_and_caches_signed_wildcard_nodata_with_complete_proofs() {
    for nsec3 in [false, true] {
        let (transport, anchor, query) = fixture(nsec3);
        let requests = Arc::clone(&transport.requests);
        let proof_type = if nsec3 {
            RecordType::NSEC3
        } else {
            RecordType::NSEC
        };
        let resolver = resolver(transport, anchor);
        let first = resolver.resolve(query.clone()).await.unwrap();
        let hit = resolver.resolve_with_stats(query).await.unwrap();
        assert_eq!(first.headers.rcode, RCode::Ok);
        assert!(first.headers.ad);
        assert!(hit.response().headers.ad);
        assert!(first.answers.is_empty());
        assert_eq!(
            hit.stats().final_cache_source(),
            Some(ResolutionCacheSource::Negative)
        );
        assert_eq!(requests.lock().unwrap().len(), 2);
        let proofs = first
            .authorities
            .iter()
            .filter(|record| record.rtype == proof_type)
            .collect::<Vec<_>>();
        assert_eq!(proofs.len(), 2);
        for proof in proofs {
            assert!(
                hit.response()
                    .authorities
                    .iter()
                    .any(|rr| rr.rtype == proof_type && rr.name.eq_dns(&proof.name))
            );
            assert!(
                hit.response()
                    .authorities
                    .iter()
                    .any(|rr| rr.rtype == RecordType::RRSIG && rr.name.eq_dns(&proof.name))
            );
        }
        assert!(hit.response().authorities.iter().all(|rr| rr.ttl <= 7));
    }
}
