//! Routing selection must honor deadlines after the external commit.
use super::*;
use crate::protocol::Referral;

fn referral(zone: DomainName, ns: DomainName, route: SocketAddr, ttl: u64, glue: u64) -> Referral {
    Referral {
        zone,
        class: ClassType::IN,
        candidates: vec![route],
        candidate_ttls: vec![(route, Duration::from_secs(glue))],
        trusted_glue: vec![],
        name_servers: vec![ns],
        ttl: Duration::from_secs(ttl),
    }
}

#[tokio::test]
async fn delayed_checkout_and_retry_do_not_restart_referral_or_glue_ttls() {
    for glue_only in [false, true] {
        let backend = Arc::new(DelayedBackend::default());
        let resolver = Arc::new(make_resolver(backend.clone()));
        let zone = name(&["example"]);
        let query = question(&["host", "example"]);
        let route: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let referral = referral(
            zone.clone(),
            name(&["ns", "example"]),
            route,
            if glue_only { 60 } else { 1 },
            1,
        );
        backend.checkout_wait.store(true, Ordering::SeqCst);
        backend.inner.conflicts.store(1, Ordering::SeqCst);
        let waiting = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                resolver
                    .insert_delegation_backend(&referral, std::time::Instant::now())
                    .await
            })
        };
        release_after(&backend, Duration::from_millis(1200)).await;
        waiting.await.unwrap().unwrap();
        // Read with a fresh resolver: the stored deadline itself must survive.
        let restarted = make_resolver(backend);
        let (selected_zone, routes, pending, cached) =
            restarted.candidates_for(&query, false).await.unwrap();
        if glue_only {
            assert!(cached);
            assert!(selected_zone.eq_dns(&zone));
            assert!(
                routes.is_empty(),
                "expired glue was renewed on admission retry"
            );
            assert_eq!(pending.len(), 1);
        } else {
            assert!(!cached, "expired NS RRset was renewed on admission retry");
            assert!(selected_zone.as_ref().is_empty());
            assert_eq!(routes, restarted.config.root_servers);
        }
    }
}

#[tokio::test]
async fn expired_delegation_or_glue_is_not_used_after_commit() {
    for glue_only in [false, true] {
        let backend = Arc::new(DelayedBackend::default());
        let resolver = Arc::new(make_resolver(backend.clone()));
        let query = question(&["host", "child", "example"]);
        let parent = name(&["example"]);
        let child = name(&["child", "example"]);
        let parent_route: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let child_route: SocketAddr = "192.0.2.11:53".parse().unwrap();
        resolver
            .insert_delegation_backend(
                &referral(
                    parent.clone(),
                    name(&["ns", "example"]),
                    parent_route,
                    60,
                    60,
                ),
                std::time::Instant::now(),
            )
            .await
            .unwrap();
        resolver
            .insert_delegation_backend(
                &referral(
                    child.clone(),
                    name(&["ns", "child", "example"]),
                    child_route,
                    if glue_only { 60 } else { 1 },
                    1,
                ),
                std::time::Instant::now(),
            )
            .await
            .unwrap();
        let (_, routes, _, cached) = resolver.candidates_for(&query, false).await.unwrap();
        assert!(cached);
        assert_eq!(routes, [child_route]);
        backend.cas_wait.store(true, Ordering::SeqCst);
        let waiting = {
            let resolver = resolver.clone();
            let query = query.clone();
            tokio::spawn(async move {
                let (zone, routes, pending, cached) =
                    resolver.candidates_for(&query, false).await?;
                Ok::<_, ResolveError>((zone, routes, pending.len(), cached))
            })
        };
        release_after(&backend, Duration::from_millis(1200)).await;
        let (zone, routes, pending, cached) = waiting.await.unwrap().unwrap();
        assert!(cached);
        if glue_only {
            assert!(zone.eq_dns(&child));
            assert!(routes.is_empty(), "expired glue must be resolved again");
            assert_eq!(pending, 1);
        } else {
            assert!(zone.eq_dns(&parent));
            assert_eq!(routes, [parent_route]);
        }
        assert!(resolver.transport.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn expired_delegation_failure_is_rechecked_after_commit() {
    for cd in [false, true] {
        let backend = Arc::new(DelayedBackend::default());
        let resolver = Arc::new(make_resolver(backend.clone()));
        let zone = name(&["example"]);
        let query = question(&["host", "example"]);
        resolver
            .cache_transaction_for(std::slice::from_ref(&query), |context| {
                let token = context
                    .delegation_cache
                    .claim_refresh(&zone, ClassType::IN, cd, Duration::from_secs(1))
                    .unwrap();
                context.delegation_cache.finish_refresh_failure(
                    &zone,
                    ClassType::IN,
                    cd,
                    token,
                    Duration::from_secs(1),
                );
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            resolver.candidates_for(&query, cd).await,
            Err(ResolveError::CachedDelegationFailure)
        ));
        assert!(resolver.candidates_for(&query, !cd).await.is_ok());
        backend.cas_wait.store(true, Ordering::SeqCst);
        let waiting = {
            let resolver = resolver.clone();
            let query = query.clone();
            tokio::spawn(async move {
                let (zone, routes, pending, cached) = resolver.candidates_for(&query, cd).await?;
                Ok::<_, ResolveError>((zone, routes, pending.len(), cached))
            })
        };
        release_after(&backend, Duration::from_millis(1200)).await;
        let (zone, routes, pending, cached) = waiting.await.unwrap().unwrap();
        assert!(zone.as_ref().is_empty());
        assert_eq!(routes, resolver.config.root_servers);
        assert_eq!(pending, 0);
        assert!(!cached);
    }
}
