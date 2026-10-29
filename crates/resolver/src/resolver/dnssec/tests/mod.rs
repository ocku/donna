mod ancestor_insecurity;
mod authenticated_cache;
mod cache_engine_categories;
mod direct_cname;
mod dname;
mod ds_namespace;
mod external_backend;
mod fixtures;
mod negative;
mod optout;
mod rrsig_coexistence;
mod signature_only;
mod support;
mod wildcard_cname;
mod wildcard_nodata;

use std::{net::Ipv4Addr, sync::Arc};

use dns::{DnssecValidationError, QueryType, RCode, RData, RecordType};

use crate::{
    ResolveError, ResolverConfig,
    resolver::{AlgorithmSignals, Resolver},
};

use self::{
    fixtures::{
        delegated_fixture, insecure_fixture, resolver, signed_fixture, signed_record_fixture,
    },
    negative::{negative_fixture, nsec3_negative_fixture},
    support::name,
};

#[tokio::test]
async fn validates_a_signed_answer_from_a_dnskey_trust_anchor() {
    let (transport, anchor, question) = signed_fixture(false);
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    let response = resolver.resolve(question.clone()).await.unwrap();
    let cached = resolver.resolve(question).await.unwrap();

    assert!(response.headers.ad);
    assert!(cached.headers.ad);
    // Chain acquisition consumes its authenticated lifetime before delivery.
    assert!(
        response
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::A)
            .unwrap()
            .ttl
            <= 300
    );
    assert!(
        cached
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::A)
            .unwrap()
            .ttl
            <= 300
    );
    assert!(
        cached
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::RRSIG)
    );
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| { request.edns().unwrap().is_some_and(|edns| edns.dnssec_ok) })
    );
}

#[tokio::test]
async fn validates_and_evaluates_a_dnssec_secure_tlsa_answer() {
    let certificate = b"certificate";
    let association = dns::CertificateAssociation {
        certificate_usage: 3,
        selector: 0,
        matching_type: 0,
        association_data: certificate.to_vec(),
    };
    let (transport, anchor, question) = signed_record_fixture(
        false,
        name(&["_443", "_tcp", "www", "example"]),
        QueryType::TLSA,
        RecordType::TLSA,
        RData::TLSA(association.clone()),
    );
    let response = resolver(transport, anchor).resolve(question).await.unwrap();

    assert!(response.headers.ad);
    assert!(
        association
            .matches(
                dns::DnssecSecurityStatus::Secure,
                certificate,
                b"subject-public-key-info",
            )
            .unwrap()
    );
}

#[tokio::test]
async fn rejects_a_tampered_answer_below_a_trust_anchor() {
    let (transport, anchor, question) = signed_fixture(true);
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    for _ in 0..2 {
        assert!(matches!(
            resolver.resolve(question.clone()).await,
            Err(ResolveError::DnssecBogus(_))
        ));
    }
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(matches!(
        resolver.resolve(question).await,
        Err(ResolveError::DnssecBogus(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn checking_disabled_bypasses_an_admitted_bad_cache_entry() {
    let (transport, anchor, question) = signed_fixture(true);
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    for _ in 0..2 {
        assert!(matches!(
            resolver.resolve(question.clone()).await,
            Err(ResolveError::DnssecBogus(_))
        ));
    }

    // RFC 9520 suppresses the second validation attempt immediately. Also
    // admit the legacy bounded BAD entry so CD bypass covers both stores.
    resolver.record_bad_backend(&question).await.unwrap();
    assert!(resolver.bad_contains_backend(&question).await.unwrap());
    let response = resolver
        .resolve_with_algorithm_signals(question, AlgorithmSignals::default(), true)
        .await
        .unwrap();

    assert!(!response.headers.ad);
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn checking_disabled_returns_tampered_data_without_ad() {
    let (transport, anchor, question) = signed_fixture(true);
    let response = resolver(transport, anchor)
        .resolve_with_algorithm_signals(question, AlgorithmSignals::default(), true)
        .await
        .unwrap();

    assert!(!response.headers.ad);
}

#[tokio::test]
async fn accepts_data_below_an_authenticated_unsigned_delegation_without_ad() {
    let (transport, anchor, question) = insecure_fixture();
    let requests = Arc::clone(&transport.requests);
    let resolver = Resolver::new(
        transport,
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            trust_anchors: vec![anchor],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    );
    let response = resolver.resolve(question.clone()).await.unwrap();
    let cached = resolver.resolve(question).await.unwrap();

    assert!(!response.headers.ad);
    assert!(!cached.headers.ad);
    // Chain acquisition consumes its authenticated lifetime before delivery.
    assert!(
        response
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::A)
            .unwrap()
            .ttl
            <= 300
    );
    assert!(
        cached
            .answers
            .iter()
            .find(|record| record.rtype == RecordType::A)
            .unwrap()
            .ttl
            <= 300
    );
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn validates_a_parent_ds_to_child_dnskey_chain() {
    let (transport, anchor, question) = delegated_fixture();
    let requests = Arc::clone(&transport.requests);
    let response = Resolver::new(
        transport,
        ResolverConfig {
            root_servers: vec![(Ipv4Addr::LOCALHOST, 53).into()],
            trust_anchors: vec![anchor],
            max_attempts_per_server: 1,
            ..ResolverConfig::default()
        },
    )
    .resolve(question)
    .await
    .unwrap();

    assert!(response.headers.ad);
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn validates_a_signed_nsec_name_error() {
    let (transport, anchor, question) = negative_fixture();
    let requests = Arc::clone(&transport.requests);
    let resolver = resolver(transport, anchor);
    let response = resolver.resolve(question.clone()).await.unwrap();
    let cached = resolver.resolve(question).await.unwrap();

    assert_eq!(response.headers.rcode, RCode::NameError);
    assert!(response.headers.ad);
    assert_eq!(cached.headers.rcode, RCode::NameError);
    assert!(cached.headers.ad);
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn validates_a_signed_nsec3_name_error() {
    let (transport, anchor, question) = nsec3_negative_fixture();
    let response = resolver(transport, anchor).resolve(question).await.unwrap();

    assert_eq!(response.headers.rcode, RCode::NameError);
    assert!(response.headers.ad);
}

#[tokio::test]
async fn reports_indeterminate_when_no_anchor_covers_the_signer() {
    let (transport, mut anchor, question) = signed_fixture(false);
    anchor.name = name(&["unrelated"]);

    assert!(matches!(
        resolver(transport, anchor).resolve(question).await,
        Err(ResolveError::DnssecIndeterminate(
            DnssecValidationError::MissingTrustAnchor
        ))
    ));
}

// Cache policy tests use genuinely authenticated keys, never an unchecked AD bit.
pub(super) fn trusted_keys() -> Arc<dns::AuthenticatedDnskeySet> {
    static KEYS: std::sync::OnceLock<Arc<dns::AuthenticatedDnskeySet>> = std::sync::OnceLock::new();
    Arc::clone(KEYS.get_or_init(|| {
        let (transport, anchor, _) = fixtures::signed_fixture(false);
        let RData::DNSKEY(key) = &anchor.rdata else {
            unreachable!()
        };
        match dns::authenticate_dnskey_with_anchor(
            &anchor.name,
            anchor.class,
            &transport.dnskey.answers[..1],
            &transport.dnskey.answers[1..],
            key,
            super::unix_time(),
        ) {
            dns::DnssecValidation::Secure(keys) => Arc::new(keys),
            other => panic!("fixture failed authentication: {other:?}"),
        }
    }))
}
