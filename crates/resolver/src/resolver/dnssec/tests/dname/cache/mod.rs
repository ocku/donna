mod external;
pub(super) mod network;

use super::super::{
    fixtures::{resolver, signed_record_fixture},
    support::name,
};
use dns::{
    ClassType, DnssecSecurityStatus, QClassType, QueryType, Question, RData, RecordType,
    ResourceRecord,
};
use std::sync::Arc;

#[tokio::test]
async fn secure_dname_is_cached_with_proof_and_synthesizes_descendant_cname() {
    let owner = name(&["old", "example"]);
    let target = name(&["new", "example"]);
    let (transport, anchor, _) = signed_record_fixture(
        false,
        owner.clone(),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(target),
    );
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport.clone(), anchor);
    let question = Question {
        qname: name(&["first", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = transport.answer.clone();
    reply.questions = vec![question.clone()];
    reply.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::CNAME(name(&["first", "new", "example"])),
    });
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    resolver.cache_validated_response(&reply, &question);
    let exact = Question {
        qname: owner.clone(),
        qtype: QueryType::A,
        qclass: question.qclass,
    };
    assert!(
        resolver.select_cached_dname(&exact).is_none(),
        "DNAME must not redirect its own owner"
    );
    let mixed = Question {
        qname: name(&["SeCoNd", "OlD", "ExAmPlE"]),
        ..question.clone()
    };
    assert!(
        resolver.select_cached_dname(&mixed).is_some(),
        "owner lookup is case-insensitive"
    );
    let original_calls = requests.lock().unwrap().len();
    let second = Question {
        qname: name(&["second", "old", "example"]),
        ..question
    };
    let answer = resolver.resolve(second.clone()).await.unwrap();
    assert!(answer.headers.ad);
    assert_eq!(
        answer.answers.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::RRSIG, RecordType::CNAME]
    );
    assert!(
        matches!(&answer.answers[2].rdata, RData::CNAME(value) if value.eq_dns(&name(&["second", "new", "example"])))
    );
    assert!(answer.answers[2].ttl <= answer.answers[0].ttl);
    assert!(
        !requests.lock().unwrap()[original_calls..]
            .iter()
            .any(|message| {
                let observed = &message.questions[0];
                observed.qname.eq_dns(&second.qname)
                    && observed.qtype == second.qtype
                    && observed.qclass == second.qclass
            })
    );
}

#[tokio::test]
async fn unrelated_signed_dname_is_not_promoted_to_cache() {
    let (transport, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let (other, _, _) = signed_record_fixture(
        false,
        name(&["unrelated", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["other", "example"])),
    );
    let resolver = resolver(transport.clone(), anchor);
    let question = Question {
        qname: name(&["first", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = transport.answer.clone();
    reply.questions = vec![question.clone()];
    reply.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 90,
        rdata: RData::CNAME(name(&["first", "new", "example"])),
    });
    reply.answers.extend(other.answer.answers);
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    resolver.cache_validated_response(&reply, &question);
    let unrelated = Question {
        qname: name(&["www", "unrelated", "example"]),
        ..question.clone()
    };
    assert!(resolver.select_cached_dname(&question).is_some());
    assert!(resolver.select_cached_dname(&unrelated).is_none());
}

#[tokio::test]
async fn expired_dname_reacquires_the_owner_and_cd_does_not_use_the_cached_ancestor() {
    let (transport, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport.clone(), anchor);
    let question = Question {
        qname: name(&["first", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = transport.answer.clone();
    reply.answers[0].ttl = 4;
    reply.questions = vec![question.clone()];
    reply.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 4,
        rdata: RData::CNAME(name(&["first", "new", "example"])),
    });
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    resolver.cache_validated_response(&reply, &question);
    assert!(resolver.select_cached_dname(&question).is_some());
    let before = requests.lock().unwrap().len();
    let cd_question = Question {
        qname: name(&["cd", "old", "example"]),
        ..question.clone()
    };
    let cd_reply = resolver
        .resolve_with_cache_check(cd_question.clone(), Default::default(), true, true)
        .await
        .unwrap();
    assert!(!cd_reply.headers.ad);
    assert!(
        requests.lock().unwrap()[before..]
            .iter()
            .any(|request| request.questions[0].qname.eq_dns(&cd_question.qname))
    );
    tokio::time::sleep(std::time::Duration::from_millis(4100)).await;
    assert!(resolver.select_cached_dname(&question).is_none());
    let expired = Question {
        qname: name(&["expired", "old", "example"]),
        ..question
    };
    let before = requests.lock().unwrap().len();
    assert!(resolver.resolve(expired.clone()).await.unwrap().headers.ad);
    assert!(
        requests.lock().unwrap()[before..]
            .iter()
            .any(|request| request.questions[0].qname.eq_dns(&expired.qname))
    );
}

#[tokio::test]
async fn cached_dname_overflow_returns_authenticated_yxdomain_without_upstream_query() {
    let destination = dns::DomainName::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 60],
    ])
    .unwrap();
    let owner = name(&["old", "example"]);
    let (transport, anchor, owner_question) = signed_record_fixture(
        false,
        owner,
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(destination),
    );
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    assert!(resolver.resolve(owner_question).await.unwrap().headers.ad);
    let before = requests.lock().unwrap().len();
    let overflow = Question {
        qname: name(&["prefix", "old", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let response = resolver.resolve(overflow.clone()).await.unwrap();
    assert_eq!(response.headers.rcode, dns::RCode::YXDomain);
    assert!(response.headers.ad);
    assert!(
        response
            .answers
            .iter()
            .any(|rr| rr.rtype == RecordType::DNAME)
    );
    assert!(
        !response
            .answers
            .iter()
            .any(|rr| rr.rtype == RecordType::CNAME)
    );
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|message| message.questions[0].qname.eq_dns(&overflow.qname))
    );
}

#[tokio::test]
async fn descendant_cut_vetoes_cached_synthesis_even_for_parent_side_ds() {
    let (transport, anchor, owner_question) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let resolver = resolver(transport, anchor);
    assert!(
        resolver
            .resolve(owner_question.clone())
            .await
            .unwrap()
            .headers
            .ad
    );
    let child = name(&["child", "old", "example"]);
    let referral = |zone: dns::DomainName| crate::protocol::Referral {
        zone,
        class: ClassType::IN,
        candidates: vec![(std::net::Ipv4Addr::LOCALHOST, 53).into()],
        candidate_ttls: vec![(
            (std::net::Ipv4Addr::LOCALHOST, 53).into(),
            std::time::Duration::from_secs(60),
        )],
        trusted_glue: vec![],
        name_servers: vec![name(&["ns", "other"])],
        ttl: std::time::Duration::from_secs(60),
    };
    resolver.delegation_cache.insert(
        &referral(owner_question.qname.clone()),
        std::time::Duration::from_secs(60),
    );
    let query = Question {
        qname: child.clone(),
        qtype: QueryType::DS,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(resolver.select_cached_dname(&query).is_some());
    assert!(
        resolver
            .select_cached_dname_with_cut(&query, Some(&child))
            .is_none(),
        "fresh descendant referral must veto before persistence"
    );
    assert!(
        resolver
            .select_cached_dname_with_cut(&query, Some(&owner_question.qname))
            .is_some(),
        "the DNAME's own serving-zone cut must not veto"
    );
    resolver
        .delegation_cache
        .insert(&referral(child), std::time::Duration::from_secs(60));
    assert!(resolver.select_cached_dname(&query).is_none());
    let below = Question {
        qname: name(&["www", "child", "old", "example"]),
        ..query
    };
    assert!(resolver.select_cached_dname(&below).is_none());
}

#[tokio::test]
async fn zero_ttl_synthesized_cname_preserves_authenticated_dname() {
    let (mut transport, anchor, _) = signed_record_fixture(
        false,
        name(&["old", "example"]),
        QueryType::DNAME,
        RecordType::DNAME,
        RData::DNAME(name(&["new", "example"])),
    );
    let question = Question {
        qname: name(&["zero", "old", "example"]),
        qtype: QueryType::CNAME,
        qclass: QClassType::Class(ClassType::IN),
    };
    transport.answer.answers.push(ResourceRecord {
        name: question.qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 0,
        rdata: RData::CNAME(name(&["zero", "new", "example"])),
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
    assert!(
        response
            .answers
            .iter()
            .find(|rr| rr.rtype == RecordType::DNAME)
            .unwrap()
            .ttl
            > 0
    );
    assert!(resolver.select_cached_dname(&question).is_some());
}

#[tokio::test]
async fn cached_secure_dname_to_insecure_target_never_sets_ad() {
    use super::super::{fixtures::insecure_fixture, support::TestRng};
    use rsa::pkcs8::EncodePrivateKey;
    let (transport, anchor, _) = insecure_fixture();
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let owner = name(&["old", "example"]);
    let question = Question {
        qname: name(&["www", "old", "example"]),
        qtype: QueryType::CNAME,
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
    let mut reply = dns::Message {
        headers: dns::Headers {
            qr: true,
            aa: true,
            ..dns::Headers::default()
        },
        questions: vec![question.clone()],
        answers: vec![
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
        ],
        authorities: vec![],
        additionals: vec![],
    };
    assert_eq!(
        resolver
            .validate_dnssec_response(&question, &mut reply)
            .await
            .unwrap(),
        DnssecSecurityStatus::Secure
    );
    reply.headers.ad = true;
    resolver.cache_validated_response(&reply, &question);
    let requested = Question {
        qtype: QueryType::A,
        ..question
    };
    let before = requests.lock().unwrap().len();
    let response = resolver.resolve(requested.clone()).await.unwrap();
    assert!(
        !response.headers.ad,
        "insecure target must not inherit the secure DNAME's AD"
    );
    assert!(
        response
            .answers
            .iter()
            .any(|rr| matches!(rr.rdata, RData::A(_)))
    );
    assert!(
        !requests.lock().unwrap()[before..]
            .iter()
            .any(|request| request.questions[0].qname.eq_dns(&requested.qname))
    );
}
