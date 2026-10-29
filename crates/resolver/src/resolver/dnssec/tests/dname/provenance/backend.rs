use super::*;

#[tokio::test]
async fn delayed_external_checkout_cannot_readmit_expired_mixed_dname() {
    use std::sync::{Arc, atomic::Ordering};
    let (transport, anchor, question, mut reply) = mixed_answer();
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedCheckout::default());
    let resolver = crate::Resolver::with_cache_engine(
        transport,
        config,
        crate::CacheEngineConfig::new(backend.clone(), b"mixed-dname-deadline".to_vec(), [7; 32])
            .unwrap(),
    );
    for record in &mut reply.answers {
        record.ttl = record.ttl.min(2);
    }
    let validation = resolver
        .validate_dnssec_response_with_dnames(&question, &mut reply)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Insecure);
    backend.delay.store(true, Ordering::SeqCst);
    resolver
        .cache_validated_response_with_dnames_backend(&reply, &question, &validation)
        .await
        .unwrap();
    assert!(
        resolver
            .cached_dname_backend(&question)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn outer_response_ages_while_external_admission_is_delayed() {
    use std::sync::{Arc, atomic::Ordering};
    let (transport, anchor, question, mut reply) = mixed_answer();
    for record in &mut reply.answers {
        record.ttl = record.ttl.min(5);
    }
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedCheckout::default());
    backend.delay_admission.store(true, Ordering::SeqCst);
    let resolver = crate::Resolver::with_cache_engine(
        MixedTransport {
            upstream: transport,
            source: reply,
        },
        config,
        crate::CacheEngineConfig::new(backend.clone(), b"dname-delayed-admit".to_vec(), [8; 32])
            .unwrap(),
    );
    let response = resolver.resolve(question.clone()).await.unwrap();
    assert!(
        !backend.delay_admission.load(Ordering::SeqCst),
        "fixture must delay admission"
    );
    assert!(!response.headers.ad);
    assert!(
        response.answers.iter().all(|rr| rr.ttl == 0),
        "response TTLs must age during CAS"
    );
    assert!(
        resolver
            .cached_dname_backend(&question)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_signature_during_admission_is_not_returned_or_reused() {
    use std::sync::{Arc, atomic::Ordering};
    let (transport, anchor, question, mut reply) = mixed_answer();
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let der = private.to_pkcs8_der().unwrap();
    let key = dns::RsaDnssecSigningKey::from_pkcs8_der(257, 8, der.as_bytes()).unwrap();
    let now = super::super::super::super::unix_time();
    let sig = key
        .sign_rrset(
            &[reply.answers[0].clone()],
            &name(&["example"]),
            now.wrapping_sub(60),
            now + 3,
        )
        .unwrap();
    reply.answers[1].rdata = RData::RRSIG(sig);
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedCheckout::default());
    backend.delay_admission.store(true, Ordering::SeqCst);
    let resolver = crate::Resolver::with_cache_engine(
        MixedTransport {
            upstream: transport,
            source: reply,
        },
        config,
        crate::CacheEngineConfig::new(
            backend.clone(),
            b"dname-expired-signature".to_vec(),
            [9; 32],
        )
        .unwrap(),
    );
    let result = resolver.resolve(question.clone()).await;
    assert!(
        !backend.delay_admission.load(Ordering::SeqCst),
        "fixture must delay admission"
    );
    assert!(matches!(result, Err(crate::ResolveError::DnssecBogus(_))));
    assert!(
        resolver
            .cached_dname_backend(&question)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn signed_direct_external_hit_expires_during_cas() {
    use std::sync::{Arc, atomic::Ordering};
    let (mut transport, anchor, question) = super::super::super::fixtures::signed_record_fixture(
        false,
        name(&["www", "old", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A([192, 0, 2, 9].into()),
    );
    for record in &mut transport.answer.answers {
        record.ttl = 4;
    }
    let mut reply = transport.answer.clone();
    let config = resolver(transport.clone(), anchor).config.clone();
    let backend = Arc::new(DelayedCheckout::default());
    let resolver = crate::Resolver::with_cache_engine(
        transport,
        config,
        crate::CacheEngineConfig::new(backend.clone(), b"signed-direct-cas".to_vec(), [6; 32])
            .unwrap(),
    );
    let validation = resolver
        .validate_dnssec_response_with_dnames(&question, &mut reply)
        .await
        .unwrap();
    assert_eq!(validation.status, DnssecSecurityStatus::Secure);
    reply.headers.ad = true;
    resolver
        .cache_validated_response_with_dnames_backend(&reply, &question, &validation)
        .await
        .unwrap();
    assert!(
        resolver
            .cached_client_response_backend(&question)
            .await
            .unwrap()
            .is_some()
    );
    backend.delay_admission.store(true, Ordering::SeqCst);
    assert!(
        resolver
            .cached_client_response_backend(&question)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !backend.delay_admission.load(Ordering::SeqCst),
        "fixture must delay the hit CAS"
    );
}

#[tokio::test]
async fn delayed_key_acquisition_does_not_renew_negative_or_wildcard_proofs() {
    let fixtures = [
        super::super::super::negative::negative_fixture(),
        super::super::super::optout::fixture_options(1, false, false, true),
    ];
    for (mut transport, anchor, question) in fixtures {
        for record in &mut transport.answer.authorities {
            record.ttl = 1;
        }
        let resolver = resolver(DelayedKey(transport), anchor);
        let response = resolver.resolve(question).await.unwrap();
        assert!(response.headers.ad);
        assert!(
            response
                .authorities
                .iter()
                .filter(|rr| matches!(
                    rr.rtype,
                    RecordType::SOA | RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
                ))
                .all(|rr| rr.ttl == 0),
            "authorities: {:?}",
            response
                .authorities
                .iter()
                .map(|rr| (rr.rtype, rr.ttl))
                .collect::<Vec<_>>()
        );
        if !response.answers.is_empty() {
            assert!(response.answers.iter().all(|rr| rr.ttl == 0));
        }
    }
}
