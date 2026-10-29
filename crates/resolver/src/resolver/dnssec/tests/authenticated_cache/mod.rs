mod retry_deadlines;

use super::support::{SignedTransport, TestRng};
use super::*;
use dns::{ClassType, Message, Question, ResourceRecord, RsaDnssecSigningKey};
use rsa::pkcs8::EncodePrivateKey;
use std::{
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use transport::{Transport, TransportError};

#[derive(Clone)]
struct Pair {
    first: SignedTransport,
    second: SignedTransport,
}

impl Transport for Pair {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let source = if query.questions[0]
                .qname
                .eq_dns(&self.second.answer.questions[0].qname)
            {
                &self.second
            } else {
                &self.first
            };
            source.exchange(server, query, timeout).await
        })
    }
}

#[derive(Clone)]
struct Controlled<T> {
    state: Arc<Mutex<T>>,
    block: Arc<AtomicBool>,
    fail_dnskey: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    dnskeys: Arc<AtomicUsize>,
}
impl<T> Controlled<T> {
    fn new(state: T, block: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            block: Arc::new(AtomicBool::new(block)),
            fail_dnskey: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            dnskeys: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl<T: Transport + Clone> Transport for Controlled<T> {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            if query.questions[0].qtype == QueryType::DNSKEY {
                self.dnskeys.fetch_add(1, Ordering::SeqCst);
                if self.fail_dnskey.load(Ordering::SeqCst) {
                    return Err(TransportError::Timeout);
                }
                if self.block.swap(false, Ordering::SeqCst) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
            }
            let state = self.state.lock().unwrap().clone();
            state.exchange(server, query, timeout).await
        })
    }
}

fn pair() -> (Pair, ResourceRecord, Question, Question) {
    let (first, anchor, one) = signed_fixture(false);
    let (mut second, same, two) = signed_record_fixture(
        false,
        name(&["other", "example"]),
        QueryType::A,
        RecordType::A,
        RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    );
    assert!(anchor.eq_dns(&same));
    second.requests = Arc::clone(&first.requests);
    (Pair { first, second }, anchor, one, two)
}

#[tokio::test]
async fn distinct_owners_share_authenticated_material_and_concurrent_acquisition() {
    let (pair, anchor, one, two) = pair();
    let controlled = Controlled::new(pair, true);
    let resolver = Arc::new(resolver(controlled.clone(), anchor));
    let a = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.resolve(one).await })
    };
    controlled.entered.notified().await;
    let b = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.resolve(two).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 1);
    controlled.release.notify_one();
    assert!(a.await.unwrap().unwrap().headers.ad);
    assert!(b.await.unwrap().unwrap().headers.ad);
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_chain_leader_releases_distinct_owner_waiters() {
    let (pair, anchor, one, two) = pair();
    let controlled = Controlled::new(pair, true);
    let resolver = Arc::new(resolver(controlled.clone(), anchor));
    let a = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.resolve(one).await })
    };
    controlled.entered.notified().await;
    let b = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move { resolver.resolve(two).await })
    };
    tokio::task::yield_now().await;
    a.abort();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), b)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .headers
            .ad
    );
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn anchor_ds_and_child_key_ttls_independently_bound_reuse() {
    // Include an unchanged long-lived control to distinguish dependency expiry
    // from unconditional reacquisition of every chain.
    for shortened in 0..4 {
        let (mut transport, anchor, _) = delegated_fixture();
        let source = match shortened {
            0 => None,
            1 => Some(&mut transport.parent_dnskey),
            2 => Some(&mut transport.ds),
            _ => Some(&mut transport.child_dnskey),
        };
        if let Some(source) = source {
            for record in &mut source.answers {
                record.ttl = 1;
            }
        }
        let requests = Arc::clone(&transport.requests);
        let resolver = resolver(transport, anchor);
        let zone = name(&["child", "example"]);
        resolver
            .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
            .await
            .unwrap();
        let before = requests.lock().unwrap().len();
        assert_eq!(before, 3, "initial parent/DS/child acquisition");
        // A one-second dependency may already expire at the next wall-second
        // during chain acquisition. Reuse is tested with longer-lived material
        // elsewhere; this test checks that each dependency bounds expiration.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        resolver
            .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
            .await
            .unwrap();
        let after = requests.lock().unwrap().len();
        if shortened == 0 {
            assert_eq!(after, before, "long-lived chain must be reused");
        } else {
            assert!(after > before, "dependency {shortened} did not expire");
        }
    }
}

fn signing_key(seed: u64) -> RsaDnssecSigningKey {
    let private = rsa::RsaPrivateKey::new(&mut TestRng(seed), 1024).unwrap();
    RsaDnssecSigningKey::from_pkcs8_der(257, 8, private.to_pkcs8_der().unwrap().as_bytes()).unwrap()
}

#[tokio::test]
async fn genuinely_signed_wrong_ds_fails_after_parent_warming() {
    let (mut transport, anchor, _) = delegated_fixture();
    let parent = transport.parent.clone();
    let RData::DS(ds) = &mut transport.ds.answers[0].rdata else {
        unreachable!()
    };
    ds.digest[0] ^= 1;
    let now = super::super::unix_time();
    let signature = signing_key(0x1111_2222_3333_4444)
        .sign_rrset(
            &transport.ds.answers[..1],
            &parent,
            now.wrapping_sub(60),
            now.wrapping_add(3600),
        )
        .unwrap();
    transport.ds.answers[1].rdata = RData::RRSIG(signature);
    let resolver = resolver(transport, anchor);
    resolver
        .authenticate_zone(&parent, ClassType::IN, now)
        .await
        .unwrap();
    assert!(matches!(
        resolver
            .authenticate_zone(&name(&["child", "example"]), ClassType::IN, now)
            .await,
        Err(ResolveError::DnssecBogus(
            DnssecValidationError::NoMatchingDs
        ))
    ));
}

#[tokio::test]
async fn rollover_refresh_is_authenticated_and_rate_bounded() {
    for zero_ttl in [false, true] {
        let (transport, anchor, question) = signed_fixture(false);
        let zone = anchor.name.clone();
        let controlled = Controlled::new(transport, false);
        let resolver = resolver(controlled.clone(), anchor.clone());
        resolver
            .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
            .await
            .unwrap();
        let new = signing_key(0x7777_6666_5555_4444);
        let now = super::super::unix_time();
        {
            let mut state = controlled.state.lock().unwrap();
            let key = ResourceRecord {
                rdata: RData::DNSKEY(new.dnskey().clone()),
                ..anchor
            };
            let keys = vec![state.dnskey.answers[0].clone(), key];
            let signature = signing_key(0xfeed_face_cafe_beef)
                .sign_rrset(&keys, &zone, now.wrapping_sub(60), now.wrapping_add(3600))
                .unwrap();
            let mut sig = state.dnskey.answers[1].clone();
            sig.rdata = RData::RRSIG(signature);
            state.dnskey.answers = keys;
            state.dnskey.answers.push(sig);
            state.answer.answers[0].rdata = RData::A(Ipv4Addr::new(192, 0, 2, 99));
            state.answer.answers[1].rdata = RData::RRSIG(
                new.sign_rrset(
                    &state.answer.answers[..1],
                    &zone,
                    now.wrapping_sub(60),
                    now.wrapping_add(3600),
                )
                .unwrap(),
            );
        }
        if zero_ttl {
            for record in &mut controlled.state.lock().unwrap().dnskey.answers {
                record.ttl = 0;
            }
        }
        let reply = resolver.resolve(question.clone()).await.unwrap();
        assert!(reply.headers.ad);
        assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 2);
        if zero_ttl {
            assert!(reply.answers.iter().all(|record| record.ttl == 0));
            assert!(resolver.resolve(question).await.unwrap().headers.ad);
            assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 3);
            continue;
        }
        let mut bad = controlled.state.lock().unwrap().answer.clone();
        let RData::RRSIG(sig) = &mut bad.answers[1].rdata else {
            unreachable!()
        };
        sig.signature[0] ^= 1;
        for _ in 0..3 {
            assert!(matches!(
                resolver
                    .validate_dnssec_response(&question, &mut bad.clone())
                    .await,
                Err(ResolveError::DnssecBogus(_))
            ));
        }
        assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn cd_acquisition_cannot_populate_trusted_material() {
    let (transport, anchor, question) = signed_fixture(true);
    let controlled = Controlled::new(transport, false);
    let resolver = resolver(controlled.clone(), anchor);
    assert!(
        !resolver
            .resolve_with_algorithm_signals(question.clone(), AlgorithmSignals::default(), true)
            .await
            .unwrap()
            .headers
            .ad
    );
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 0);
    assert!(matches!(
        resolver.resolve(question).await,
        Err(ResolveError::DnssecBogus(_))
    ));
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn parent_key_rollover_refreshes_a_cached_ancestor_for_a_fresh_child() {
    let (transport, anchor, question) = delegated_fixture();
    let parent = transport.parent.clone();
    let controlled = Controlled::new(transport, false);
    let resolver = resolver(controlled.clone(), anchor.clone());
    resolver
        .authenticate_zone(&parent, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    let new = signing_key(0x7777_6666_5555_4444);
    let now = super::super::unix_time();
    {
        let mut state = controlled.state.lock().unwrap();
        let key = ResourceRecord {
            rdata: RData::DNSKEY(new.dnskey().clone()),
            ..anchor
        };
        let keys = vec![state.parent_dnskey.answers[0].clone(), key];
        let signature = signing_key(0x1111_2222_3333_4444)
            .sign_rrset(&keys, &parent, now.wrapping_sub(60), now.wrapping_add(3600))
            .unwrap();
        let mut sig = state.parent_dnskey.answers[1].clone();
        sig.rdata = RData::RRSIG(signature);
        state.parent_dnskey.answers = keys;
        state.parent_dnskey.answers.push(sig);
        state.ds.answers[1].rdata = RData::RRSIG(
            new.sign_rrset(
                &state.ds.answers[..1],
                &parent,
                now.wrapping_sub(60),
                now.wrapping_add(3600),
            )
            .unwrap(),
        );
    }
    assert!(resolver.resolve(question).await.unwrap().headers.ad);
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn failed_rollover_refresh_preserves_bogus_and_bad_cache_accounting() {
    let (transport, anchor, question) = signed_fixture(true);
    let requests = Arc::clone(&transport.requests);
    let zone = anchor.name.clone();
    let controlled = Controlled::new(transport, false);
    let resolver = resolver(controlled.clone(), anchor);
    resolver
        .authenticate_zone(&zone, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    controlled.fail_dnskey.store(true, Ordering::SeqCst);
    assert!(matches!(
        resolver.resolve(question.clone()).await,
        Err(ResolveError::DnssecBogus(_))
    ));
    let after_refresh = controlled.dnskeys.load(Ordering::SeqCst);
    assert!(
        after_refresh > 1,
        "one acquisition may also try classic EDNS fallback"
    );
    assert!(matches!(
        resolver.resolve(question.clone()).await,
        Err(ResolveError::DnssecBogus(_))
    ));
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), after_refresh);
    let before = requests.lock().unwrap().len();
    assert!(matches!(
        resolver.resolve(question).await,
        Err(ResolveError::DnssecBogus(_))
    ));
    assert_eq!(requests.lock().unwrap().len(), before);
}

#[tokio::test]
async fn delayed_child_acquisition_cannot_renew_an_expired_cached_parent() {
    let (mut transport, anchor, _) = delegated_fixture();
    for record in &mut transport.parent_dnskey.answers {
        record.ttl = 2;
    }
    let parent = transport.parent.clone();
    let controlled = Controlled::new(transport, false);
    let resolver = Arc::new(resolver(controlled.clone(), anchor));
    resolver
        .authenticate_zone(&parent, ClassType::IN, super::super::unix_time())
        .await
        .unwrap();
    controlled.block.store(true, Ordering::SeqCst);
    let child = {
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            resolver
                .authenticate_zone(
                    &name(&["child", "example"]),
                    ClassType::IN,
                    super::super::unix_time(),
                )
                .await
        })
    };
    controlled.entered.notified().await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    controlled.release.notify_one();
    let status = tokio::time::timeout(Duration::from_secs(4), child)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let super::super::chain::ChainStatus::Secure { deadline, .. } = status else {
        panic!("expected authenticated child")
    };
    assert!(
        deadline <= std::time::Instant::now(),
        "a held parent can validate this transaction only at TTL zero"
    );
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 2);
    let fresh = resolver
        .authenticate_zone(
            &name(&["child", "example"]),
            ClassType::IN,
            super::super::unix_time(),
        )
        .await
        .unwrap();
    let super::super::chain::ChainStatus::Secure { deadline, .. } = fresh else {
        panic!("expected fresh authenticated child")
    };
    assert!(deadline > std::time::Instant::now());
    assert_eq!(
        controlled.dnskeys.load(Ordering::SeqCst),
        4,
        "the expired parent must not be reused by another transaction"
    );
}

#[tokio::test]
async fn zero_ttl_keys_authenticate_current_queries_but_are_not_reused() {
    let (mut transport, anchor, question) = signed_fixture(false);
    for record in &mut transport.dnskey.answers {
        record.ttl = 0;
    }
    let controlled = Controlled::new(transport, false);
    let resolver = resolver(controlled.clone(), anchor);
    for _ in 0..2 {
        let reply = resolver.resolve(question.clone()).await.unwrap();
        assert!(reply.headers.ad);
        assert!(reply.answers.iter().all(|record| record.ttl == 0));
    }
    assert_eq!(controlled.dnskeys.load(Ordering::SeqCst), 2);
}
