//! Independent authenticated-denial reuse checks through real resolver transitions.
use super::super::{
    fixtures::resolver,
    negative::{negative_fixture, nsec3_negative_fixture},
    support::{SignedTransport, name},
};
use dns::{
    ClassType, Message, QClassType, QueryType, Question, RCode, RData, RecordType, ResourceRecord,
};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

fn assert_denial(response: &Message, question: &Question, proof_type: RecordType) {
    assert_eq!(response.headers.rcode, RCode::NameError);
    assert!(
        response.headers.ad,
        "reuse must retain authenticated status"
    );
    assert!(response.answers.is_empty());
    assert_eq!(response.questions.len(), 1);
    let echoed = &response.questions[0];
    assert_eq!(echoed.qname, question.qname, "preserve question byte case");
    assert_eq!(echoed.qtype, question.qtype);
    assert_eq!(echoed.qclass, question.qclass);
    assert!(
        response
            .authorities
            .iter()
            .any(|rr| rr.rtype == RecordType::SOA)
    );
    assert!(response.authorities.iter().any(|rr| rr.rtype == proof_type));
    assert!(
        response
            .authorities
            .iter()
            .any(|rr| rr.rtype == RecordType::RRSIG)
    );
}

async fn reuse_authenticated_denial(
    fixture: (SignedTransport, ResourceRecord, Question),
    proof_type: RecordType,
) {
    let (transport, anchor, question) = fixture;
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    let original = resolver.resolve(question.clone()).await.unwrap();
    assert_denial(&original, &question, proof_type);
    let acquired = requests.lock().unwrap().len();
    assert_eq!(
        acquired, 2,
        "one negative and one authenticated DNSKEY acquisition"
    );
    let owners = vec![
        name(&["ChIlD", "missing", "example"]),
        name(&["DeEp", "child", "missing", "example"]),
    ];
    for (qname, qtype) in owners.into_iter().zip([QueryType::AAAA, QueryType::TXT]) {
        let next = Question {
            qname,
            qtype,
            ..question.clone()
        };
        let response = resolver.resolve(next.clone()).await.unwrap();
        assert_denial(&response, &next, proof_type);
        assert_eq!(
            requests.lock().unwrap().len(),
            acquired,
            "a complete authenticated cached proof must avoid another upstream request"
        );
        for record in &response.authorities {
            if let Some(source) = original
                .authorities
                .iter()
                .find(|source| source.eq_dns(record))
            {
                assert!(
                    record.ttl <= source.ttl,
                    "reuse cannot renew source lifetime"
                );
            }
        }
    }
}

#[tokio::test]
async fn aggressive_negative_nsec_descendants_reuse_only_the_denied_subtree() {
    reuse_authenticated_denial(negative_fixture(), RecordType::NSEC).await;
}

#[tokio::test]
async fn aggressive_negative_nsec3_descendants_reuse_only_the_denied_subtree() {
    reuse_authenticated_denial(nsec3_negative_fixture(), RecordType::NSEC3).await;
}

#[tokio::test]
async fn aggressive_negative_cut_does_not_extend_to_siblings_or_other_classes() {
    for fixture in [negative_fixture(), nsec3_negative_fixture()] {
        let (transport, anchor, question) = fixture;
        let resolver = resolver(transport, anchor);
        resolver.resolve(question.clone()).await.unwrap();
        for next in [
            Question {
                qname: name(&["other", "example"]),
                ..question.clone()
            },
            Question {
                qname: name(&["child", "missing", "example"]),
                qclass: QClassType::Class(ClassType::CH),
                ..question.clone()
            },
            Question {
                qname: name(&["child", "missingexample"]),
                ..question.clone()
            },
        ] {
            assert!(resolver.cached_client_response(&next).unwrap().is_none());
        }
    }
}

#[tokio::test]
async fn aggressive_negative_cut_requires_current_keys_and_respects_cd_policy() {
    for fixture in [negative_fixture(), nsec3_negative_fixture()] {
        let (transport, anchor, question) = fixture;
        let mut resolver = resolver(transport, anchor);
        resolver.resolve(question.clone()).await.unwrap();
        let next = Question {
            qname: name(&["child", "missing", "example"]),
            ..question
        };
        assert!(resolver.cached_client_response(&next).unwrap().is_some());
        assert!(
            resolver
                .cached_client_response_with_policy(&next, false)
                .unwrap()
                .is_none()
        );
        let request = Message {
            headers: dns::Headers {
                cd: true,
                ..dns::Headers::default()
            },
            questions: vec![next.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        assert!(
            resolver
                .cached_client_response_udp(&request, 1232)
                .unwrap()
                .is_none()
        );
        resolver.authenticated_zones = super::super::super::AuthenticatedZoneCache::new(0);
        assert!(resolver.cached_client_response(&next).unwrap().is_none());
    }
}

#[tokio::test]
async fn aggressive_negative_cut_cannot_cross_a_new_delegation_or_child_anchor() {
    for fixture in [negative_fixture(), nsec3_negative_fixture()] {
        let (transport, anchor, question) = fixture;
        let anchored_transport = transport.clone();
        let resolver = resolver(transport, anchor.clone());
        resolver.resolve(question.clone()).await.unwrap();
        let next = Question {
            qname: name(&["child", "missing", "example"]),
            ..question
        };
        assert!(resolver.cached_client_response(&next).unwrap().is_some());
        let address = (Ipv4Addr::LOCALHOST, 53).into();
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: next.qname.clone(),
                class: ClassType::IN,
                candidates: vec![address],
                candidate_ttls: vec![(address, Duration::from_secs(60))],
                trusted_glue: vec![],
                name_servers: vec![name(&["ns", "other"])],
                ttl: Duration::from_secs(60),
            },
            Duration::from_secs(60),
        );
        assert!(resolver.cached_client_response(&next).unwrap().is_none());
        let exact_cut =
            super::super::fixtures::resolver(anchored_transport.clone(), anchor.clone());
        exact_cut.resolve(question_for_source(&next)).await.unwrap();
        assert!(exact_cut.cached_client_response(&next).unwrap().is_some());
        exact_cut.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: question_for_source(&next).qname,
                class: ClassType::IN,
                candidates: vec![address],
                candidate_ttls: vec![(address, Duration::from_secs(60))],
                trusted_glue: vec![],
                name_servers: vec![name(&["ns", "other"])],
                ttl: Duration::from_secs(60),
            },
            Duration::from_secs(60),
        );
        assert!(exact_cut.cached_client_response(&next).unwrap().is_none());
        let mut anchored = super::super::fixtures::resolver(anchored_transport, anchor.clone());
        anchored.resolve(question_for_source(&next)).await.unwrap();
        assert!(anchored.cached_client_response(&next).unwrap().is_some());
        let mut child_anchor = anchor;
        child_anchor.name = name(&["missing", "example"]);
        anchored.config.trust_anchors.push(child_anchor);
        assert!(anchored.cached_client_response(&next).unwrap().is_none());
    }
}

fn question_for_source(descendant: &Question) -> Question {
    Question {
        qname: name(&["missing", "example"]),
        ..descendant.clone()
    }
}

#[tokio::test]
async fn aggressive_negative_cut_rejects_optout_and_nodata_as_subtree_nonexistence() {
    for fixture in [
        super::super::optout::fixture_options(0, false, true, true),
        super::super::negative::negative_ds_fixture(),
    ] {
        let (transport, anchor, question) = fixture;
        let resolver = resolver(transport, anchor);
        let response = resolver.resolve(question.clone()).await.unwrap();
        if response.headers.rcode == RCode::NameError {
            assert!(!response.headers.ad);
        }
        let mut labels = vec![b"child".to_vec()];
        labels.extend(question.qname.as_ref().iter().cloned());
        let next = Question {
            qname: dns::DomainName::from_labels(labels).unwrap(),
            qtype: QueryType::A,
            ..question
        };
        assert!(resolver.cached_client_response(&next).unwrap().is_none());
    }
}

#[tokio::test]
async fn aggressive_negative_cut_expires_with_its_shortest_retained_record() {
    let mut resolvers = Vec::new();
    for fixture in [negative_fixture(), nsec3_negative_fixture()] {
        let (mut transport, anchor, question) = fixture;
        for rr in &mut transport.answer.authorities {
            rr.ttl = 5;
        }
        let resolver = resolver(transport, anchor);
        resolver.resolve(question.clone()).await.unwrap();
        let next = Question {
            qname: name(&["child", "missing", "example"]),
            ..question
        };
        assert!(resolver.cached_client_response(&next).unwrap().is_some());
        resolvers.push((resolver, next));
    }
    tokio::time::sleep(Duration::from_millis(5100)).await;
    for (resolver, next) in resolvers {
        assert!(resolver.cached_client_response(&next).unwrap().is_none());
    }
}

#[tokio::test]
async fn aggressive_negative_cut_rejects_a_forged_ad_proof_even_with_trusted_keys() {
    let (transport, anchor, question) = negative_fixture();
    let mut response = transport.answer.clone();
    let resolver = resolver(transport, anchor);
    resolver
        .validate_dnssec_response(&question, &mut response)
        .await
        .unwrap();
    response.headers.ad = true;
    let proof = response
        .authorities
        .iter_mut()
        .find(|rr| rr.rtype == RecordType::NSEC)
        .unwrap();
    let RData::NSEC(nsec) = &mut proof.rdata else {
        unreachable!()
    };
    nsec.next_domain_name = name(&["tampered", "example"]);
    resolver.cache_validated_response(&response, &question);
    let next = Question {
        qname: name(&["child", "missing", "example"]),
        ..question
    };
    assert!(resolver.cached_client_response(&next).unwrap().is_none());
}

#[tokio::test]
async fn aggressive_negative_cut_keeps_an_existing_descendant_positive_precedence() {
    let (transport, anchor, question) = negative_fixture();
    let resolver = resolver(transport, anchor);
    let next = Question {
        qname: name(&["child", "missing", "example"]),
        ..question.clone()
    };
    // RFC8020 explicitly permits continuing to serve already-cached data
    // below a later NXDOMAIN cut until that data expires.
    let query = Message {
        headers: dns::Headers::default(),
        questions: vec![next.clone()],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let mut positive = query.clone();
    positive.headers.qr = true;
    positive.headers.aa = true;
    positive.answers.push(ResourceRecord {
        name: next.qname.clone(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 42)),
    });
    assert!(
        resolver
            .positive_cache
            .insert(&query, &positive, Duration::from_secs(60))
    );
    resolver.resolve(question).await.unwrap();
    let retained = resolver
        .cached_client_response(&next)
        .unwrap()
        .unwrap()
        .response;
    assert_eq!(retained.headers.rcode, RCode::Ok);
    assert!(
        retained
            .answers
            .iter()
            .any(|rr| rr.rdata == positive.answers[0].rdata)
    );
    assert!(
        !retained.headers.ad,
        "cut must not promote the positive's trust"
    );
}

#[tokio::test]
async fn aggressive_negative_memo_preserves_content_signature_time_and_ttl_checks() {
    for fixture in [negative_fixture(), nsec3_negative_fixture()] {
        let (transport, anchor, question) = fixture;
        let mut response = transport.answer.clone();
        let resolver = resolver(transport, anchor);
        let validation = resolver
            .validate_dnssec_response_with_deadline(&question, &mut response, None)
            .await
            .unwrap();
        let keys = validation.negative_keys.unwrap().memoized;
        let now = super::super::super::unix_time();
        let validate = |response: &Message, at| {
            resolver.validate_negative_denial(
                &keys,
                &question.qname,
                question.qtype.value(),
                response,
                at,
            )
        };
        assert!(validate(&response, now).is_ok(), "genuine warmed proof");
        let mut lower_ttl = response.clone();
        for rr in &mut lower_ttl.authorities {
            rr.ttl = 1;
        }
        assert!(validate(&lower_ttl, now).unwrap().authenticated_ttl() <= 1);
        assert!(validate(&response, now.wrapping_add(3601)).is_err());
        let mut changed = response.clone();
        for rr in &mut changed.authorities {
            match &mut rr.rdata {
                RData::NSEC(nsec) => nsec.next_domain_name = name(&["tampered", "example"]),
                RData::NSEC3(nsec3) => nsec3.flags ^= 1,
                _ => {}
            }
        }
        assert!(
            validate(&changed, now).is_err(),
            "same-owner changed content must miss the math memo"
        );
        let mut changed_signature = response.clone();
        for rr in &mut changed_signature.authorities {
            if let RData::RRSIG(sig) = &mut rr.rdata
                && [u16::from(RecordType::NSEC), u16::from(RecordType::NSEC3)]
                    .contains(&sig.type_covered)
            {
                sig.signature[0] ^= 1;
            }
        }
        assert!(
            validate(&changed_signature, now).is_err(),
            "changed signature must miss the math memo"
        );
    }
}
