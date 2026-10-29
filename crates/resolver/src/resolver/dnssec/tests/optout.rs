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

fn fixture(kind: u8, corrupt: bool) -> (SignedTransport, ResourceRecord, Question) {
    fixture_options(kind, corrupt, true, true)
}

pub(super) fn fixture_options(
    kind: u8,
    corrupt: bool,
    optout: bool,
    nsec3: bool,
) -> (SignedTransport, ResourceRecord, Question) {
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
    let source_text = if kind == 0 {
        "example. 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 300"
    } else {
        "example. 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 300\n*.example. 300 IN A 192.0.2.1"
    };
    let source = dns::master::MasterFile::parse(source_text, None)
        .unwrap()
        .records;
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
    for record in &mut records {
        if let RData::NSEC3(nsec3) = &mut record.rdata {
            nsec3.flags = u8::from(optout);
        }
    }
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
        qtype: if kind == 1 {
            QueryType::A
        } else {
            QueryType::AAAA
        },
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut answers = Vec::new();
    if kind == 1 {
        let mut expanded = source[1].clone();
        let mut signature = sign(&expanded);
        signature.ttl = 300;
        expanded.name = question.qname.clone();
        signature.name = question.qname.clone();
        answers.extend([expanded, signature]);
    }
    if corrupt {
        for record in &mut records {
            match &mut record.rdata {
                RData::NSEC3(nsec3) => nsec3.flags ^= 1,
                RData::NSEC(nsec) => nsec.next_domain_name = name(&["tampered", "example"]),
                _ => {}
            }
        }
    }
    let answer = Message {
        headers: Headers {
            rcode: if kind == 0 {
                RCode::NameError
            } else {
                RCode::Ok
            },
            ..headers.clone()
        },
        questions: vec![question.clone()],
        answers,
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
async fn authenticated_optout_answers_clear_ad_and_keep_bounded_cache_lifetimes() {
    for kind in [0, 1, 2] {
        let (transport, anchor, query) = fixture(kind, false);
        let resolver = resolver(transport, anchor);
        let first = resolver.resolve(query.clone()).await.unwrap();
        assert!(!first.headers.ad, "kind {kind}");
        assert_eq!(
            first.headers.rcode,
            if kind == 0 {
                RCode::NameError
            } else {
                RCode::Ok
            }
        );
        assert_eq!(!first.answers.is_empty(), kind == 1);
        assert!(
            first
                .answers
                .iter()
                .chain(&first.authorities)
                .all(|rr| rr.ttl <= 7)
        );
        let hit = resolver.resolve_with_stats(query).await.unwrap();
        assert!(!hit.response().headers.ad);
        assert_eq!(
            hit.stats().final_cache_source(),
            Some(if kind == 1 {
                ResolutionCacheSource::Positive
            } else {
                ResolutionCacheSource::Negative
            })
        );
        assert!(
            hit.response()
                .answers
                .iter()
                .chain(&hit.response().authorities)
                .all(|rr| rr.ttl <= 7)
        );
    }
}

#[tokio::test]
async fn optout_does_not_bypass_denial_signature_verification() {
    for kind in [0, 1, 2] {
        let (transport, anchor, query) = fixture(kind, true);
        assert!(matches!(
            resolver(transport, anchor).resolve(query).await,
            Err(crate::ResolveError::DnssecBogus(_))
        ));
    }
}

#[tokio::test]
async fn wildcard_ds_nodata_cannot_authorize_an_unsigned_delegation() {
    for wildcard in [false, true] {
        let (transport, anchor, query) = super::fixtures::insecure_delegation_fixture(wildcard);
        let RData::DNSKEY(anchor_key) = &anchor.rdata else {
            unreachable!()
        };
        let signatures = transport
            .dnskey
            .answers
            .iter()
            .filter(|rr| rr.rtype == RecordType::RRSIG)
            .cloned()
            .collect::<Vec<_>>();
        let dns::DnssecValidation::Secure(keys) = dns::authenticate_dnskey_with_anchor(
            &anchor.name,
            anchor.class,
            std::slice::from_ref(&anchor),
            &signatures,
            anchor_key,
            super::super::unix_time(),
        ) else {
            panic!("fixture DNSKEY authentication failed")
        };
        let proofs = transport
            .ds
            .authorities
            .iter()
            .filter(|rr| rr.rtype == RecordType::NSEC)
            .cloned()
            .collect::<Vec<_>>();
        let signatures = transport
            .ds
            .authorities
            .iter()
            .filter(|rr| rr.rtype == RecordType::RRSIG)
            .cloned()
            .collect::<Vec<_>>();
        let dns::DnssecValidation::Secure(denial) = keys.validate_nsec_nodata(
            &name(&["child", "example"]),
            u16::from(RecordType::DS),
            &proofs,
            &signatures,
            super::super::unix_time(),
        ) else {
            panic!("fixture denial authentication failed")
        };
        assert_eq!(
            denial.kind(),
            if wildcard {
                dns::DnssecDenialKind::NoData
            } else {
                dns::DnssecDenialKind::UnsignedDelegation
            }
        );
        let result = resolver(transport, anchor).resolve(query).await;
        if wildcard {
            assert!(matches!(result, Err(crate::ResolveError::DnssecBogus(_))));
        } else {
            assert!(!result.unwrap().headers.ad);
        }
    }
}

#[tokio::test]
async fn secure_wildcard_positive_cache_retains_proofs_and_their_lifetime() {
    for nsec3 in [false, true] {
        let (transport, anchor, query) = fixture_options(1, false, false, nsec3);
        let requests = Arc::clone(&transport.requests);
        let resolver = resolver(transport, anchor);
        let first = resolver.resolve(query.clone()).await.unwrap();
        let count = requests.lock().unwrap().len();
        assert!(first.headers.ad);
        assert!(first.answers.iter().all(|rr| rr.ttl <= 7));
        let hit = resolver.resolve_with_stats(query.clone()).await.unwrap();
        assert_eq!(
            hit.stats().final_cache_source(),
            Some(ResolutionCacheSource::Positive)
        );
        assert_eq!(requests.lock().unwrap().len(), count);
        assert!(hit.response().headers.ad);
        let proof_type = if nsec3 {
            RecordType::NSEC3
        } else {
            RecordType::NSEC
        };
        for proof in first.authorities.iter().filter(|rr| rr.rtype == proof_type) {
            assert!(
                hit.response()
                    .authorities
                    .iter()
                    .any(|rr| rr.rtype == proof_type && rr.name.eq_dns(&proof.name))
            );
            assert!(hit.response().authorities.iter().any(|rr| rr.name.eq_dns(&proof.name) && matches!(&rr.rdata, RData::RRSIG(sig) if sig.type_covered == u16::from(proof_type))));
        }
        assert!(hit.response().authorities.iter().all(|rr| rr.ttl <= 7));
        // Exercise RRset cache replay directly, with rebuilt query headers.
        let replay = resolver.positive_cache.get_question(&query).unwrap();
        assert!(!replay.authorities.is_empty());
        assert!(
            replay
                .answers
                .iter()
                .chain(&replay.authorities)
                .all(|rr| rr.ttl <= 7)
        );
        let (transport, anchor, query) = fixture_options(1, true, false, nsec3);
        assert!(matches!(
            super::fixtures::resolver(transport, anchor)
                .resolve(query)
                .await,
            Err(crate::ResolveError::DnssecBogus(_))
        ));
    }
}
