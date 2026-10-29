//! Docker-only Redis per-entry CacheEngine plus PostgreSQL ZoneStore integration.
mod catalog_contract;
mod engine_fixture;
mod postgres_zones;
mod redis_engine;
mod redis_engine_contract;

use dns::{Edns, IntoWire, Message, QueryType, RCode, RecordType};
use engine_fixture::{Authority, Failure, cases, catalog, config, external, question, zone};
use redis_engine::RedisCacheEngine;
use resolver::{
    CacheCategory, CacheEngine, CacheMutation, CacheMutationBatch, CacheRead, CacheReadPlan,
    CacheReadResult, ResolveError, Resolver,
};
use std::{
    env,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use transport::Transport;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn answer(
    resolver: &Resolver<Authority>,
    authority: &Authority,
    label: &str,
    query: dns::Question,
    origin: Instant,
) -> Result<usize, Failure> {
    let before = authority.exchanges.load(Ordering::Relaxed);
    let captured = authority
        .captures
        .lock()
        .map_err(|_| "capture lock poisoned")?
        .len();
    let reply = resolver.resolve(query.clone()).await?;
    let elapsed = origin.elapsed().as_nanos();
    let wall = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    assert!(
        reply.headers.ad,
        "signed fixture answer must be authenticated"
    );
    assert_eq!(reply.questions.len(), 1);
    assert_eq!(reply.questions[0].qname, query.qname);
    assert_eq!(reply.questions[0].qtype, query.qtype);
    assert_eq!(reply.questions[0].qclass, query.qclass);
    assert_eq!(
        reply.headers.rcode,
        if label.ends_with("negative") || label.ends_with("descendant") {
            RCode::NameError
        } else {
            RCode::Ok
        }
    );
    let delta = authority.exchanges.load(Ordering::Relaxed) - before;
    for item in &authority
        .captures
        .lock()
        .map_err(|_| "capture lock poisoned")?[captured..]
    {
        println!(
            "UPSTREAM {label} {} {} {} {}",
            item.wall,
            item.mono,
            hex(&item.query.into_wire()?),
            hex(&item.response.into_wire()?)
        );
    }
    println!(
        "REPLY {label} {wall} {elapsed} {delta} {}",
        hex(&reply.into_wire()?)
    );
    Ok(delta)
}
async fn functional(
    authority: Authority,
    engine: Arc<RedisCacheEngine>,
    install: bool,
    origin: Instant,
) -> Result<(), Failure> {
    if install {
        let native = Resolver::new(authority.clone(), config(4096)?);
        for (name, query) in cases()? {
            answer(
                &native,
                &authority,
                &format!("default-first-{name}"),
                query.clone(),
                origin,
            )
            .await?;
            assert_eq!(
                answer(
                    &native,
                    &authority,
                    &format!("default-repeat-{name}"),
                    query,
                    origin
                )
                .await?,
                0
            );
        }
    }
    let provider = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-signed",
        4096,
    )?;
    for (name, query) in cases()? {
        let delta = answer(
            &provider,
            &authority,
            &format!("provider-first-{name}"),
            query.clone(),
            origin,
        )
        .await?;
        if !install {
            assert_eq!(
                delta, 0,
                "persistent entry must survive process/database restart"
            );
        }
        assert_eq!(
            answer(
                &provider,
                &authority,
                &format!("provider-repeat-{name}"),
                query,
                origin
            )
            .await?,
            0
        );
    }
    drop(provider);
    let restarted = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-signed",
        4096,
    )?;
    for (name, query) in cases()? {
        assert_eq!(
            answer(
                &restarted,
                &authority,
                &format!("restarted-{name}"),
                query,
                origin
            )
            .await?,
            0
        );
    }
    println!(
        "PASS engine integration: default/provider signed A AAAA TXT DNAME NXDOMAIN and ancestor cuts; persistent restart"
    );
    if !install {
        return Ok(());
    }

    let no_cache = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-disabled",
        0,
    )?;
    let before = engine.metrics.counts();
    for _ in 0..2 {
        assert!(
            answer(
                &no_cache,
                &authority,
                "disabled-a",
                question("coherence.example.test.", QueryType::A)?,
                origin
            )
            .await?
                > 0
        );
    }
    assert_eq!(
        engine.metrics.counts(),
        before,
        "capacity0 must skip every engine read/apply"
    );
    println!("PASS engine capacity0: two fresh signed resolutions, no provider I/O");

    let ttl = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-expiry",
        4096,
    )?;
    let q = question("expire.example.test.", QueryType::A)?;
    answer(&ttl, &authority, "expiry-first", q.clone(), origin).await?;
    assert_eq!(
        answer(&ttl, &authority, "expiry-repeat", q.clone(), origin).await?,
        0
    );
    tokio::time::sleep(Duration::from_millis(6250)).await;
    assert!(answer(&ttl, &authority, "expiry-after", q, origin).await? > 0);
    println!("PASS engine TTL: original absolute deadline requires fresh authority acquisition");

    let corrupt = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-corruption",
        4096,
    )?;
    let q = question("coherence.example.test.", QueryType::A)?;
    answer(&corrupt, &authority, "corruption-first", q.clone(), origin).await?;
    let namespace = engine.observed_namespace()?;
    let plan = CacheReadPlan {
        reads: vec![CacheRead::OwnerFamily(resolver::CacheEntryFamily {
            category: CacheCategory::Positive,
            owner: q.qname.into_wire()?,
            class: 1,
        })],
        maximum_entries: 1024,
        maximum_bytes: 1024 * 1024,
    };
    let CacheReadResult::Read(state) = engine.read(&namespace, None, &plan).await? else {
        return Err("unexpected read conflict".into());
    };
    let original = state
        .entries
        .first()
        .ok_or("missing retained positive")?
        .clone();
    let mut poisoned = original.clone();
    let last = poisoned.value.last_mut().ok_or("missing sealed payload")?;
    *last ^= 1;
    let changed = engine
        .apply(
            &namespace,
            &state.revision,
            &CacheMutationBatch {
                mutations: vec![CacheMutation::Put(poisoned)],
            },
        )
        .await?
        .ok_or("corruption conflict")?;
    let before = authority.exchanges.load(Ordering::Relaxed);
    assert!(matches!(
        corrupt.resolve(q.clone()).await,
        Err(ResolveError::CacheBackend(_))
    ));
    assert_eq!(
        authority.exchanges.load(Ordering::Relaxed),
        before,
        "corrupt seal cannot use native fallback"
    );
    engine
        .apply(
            &namespace,
            &changed,
            &CacheMutationBatch {
                mutations: vec![CacheMutation::Put(original)],
            },
        )
        .await?
        .ok_or("repair conflict")?;
    assert_eq!(
        answer(&corrupt, &authority, "corruption-repaired", q, origin).await?,
        0
    );
    println!(
        "PASS engine sealed-entry corruption: authentication error, no native/upstream fallback, repair under fresh generation"
    );

    authority.unavailable.store(true, Ordering::Relaxed);
    let failing = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-terminal-failure",
        4096,
    )?;
    let q = question("retry.example.test.", QueryType::A)?;
    assert!(failing.resolve(q.clone()).await.is_err());
    let before = authority.exchanges.load(Ordering::Relaxed);
    assert!(failing.resolve(q).await.is_err());
    assert_eq!(authority.exchanges.load(Ordering::Relaxed), before);
    authority.unavailable.store(false, Ordering::Relaxed);
    let changed = zone("bad-tld.db", "test.")?;
    let expected_ds = changed
        .records()
        .iter()
        .find(|r| r.rtype == RecordType::DS)
        .ok_or("missing bad DS")?
        .clone();
    assert_eq!(
        authority.server.install(changed).await?,
        nameserver::InstallOutcome::Replaced
    );
    let ds_query = Message::builder()
        .questions([question("example.test.", QueryType::DS)?])
        .additionals([Edns {
            dnssec_ok: true,
            ..Edns::default()
        }
        .into_record()])
        .build()?;
    let served = authority
        .exchange(
            "172.29.53.71:53".parse()?,
            &ds_query,
            Duration::from_secs(2),
        )
        .await?;
    let served_ds = served
        .answers
        .iter()
        .find(|r| r.rtype == RecordType::DS)
        .ok_or("bad DS not served")?;
    assert_eq!(
        served_ds.into_wire()?,
        expected_ds.into_wire()?,
        "must observe newly published DS, not a cached good chain"
    );
    println!(
        "DS-WITNESS {} {} {}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        hex(&ds_query.into_wire()?),
        hex(&served.into_wire()?)
    );
    let bogus = external(
        authority.clone(),
        engine.clone(),
        b"remote-engine-bad-ds",
        4096,
    )?;
    assert!(
        matches!(
            bogus
                .resolve(question("coherence.example.test.", QueryType::A)?)
                .await,
            Err(ResolveError::DnssecBogus(_))
        ),
        "fresh namespace must reject the served supported-algorithm DS mismatch as Bogus"
    );
    assert_eq!(
        authority
            .server
            .install(zone("restored-tld.db", "test.")?)
            .await?,
        nameserver::InstallOutcome::Replaced
    );
    for count in &engine.metrics.category_puts {
        assert!(
            count.load(Ordering::Relaxed) > 0,
            "all six categories must use provider mutations"
        );
    }
    println!(
        "PASS engine six genuine resolver categories: positive negative delegation BAD terminal-failure authenticated-DNSKEY"
    );
    println!(
        "METRICS {:?} {:?}",
        engine.metrics.counts(),
        engine
            .metrics
            .category_puts
            .each_ref()
            .map(|n| n.load(Ordering::Relaxed))
    );
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Failure> {
    let mode = env::args().nth(1).ok_or("mode required")?;
    let redis = env::var("REDIS_URL")?;
    let postgres = env::var("POSTGRES_URL")?;
    let origin = Instant::now();
    let engine = Arc::new(RedisCacheEngine::new(&redis)?);
    if mode == "seed" {
        redis_engine_contract::check(Arc::new(RedisCacheEngine::new(&redis)?), &redis).await?;
    }
    let authority = catalog(postgres.clone(), mode == "seed", origin).await?;
    if mode == "seed" {
        let request = Message::builder()
            .questions([question("coherence.example.test.", QueryType::A)?])
            .build()?;
        catalog_contract::check(&authority.server, &request, &postgres).await?;
    }
    match mode.as_str() {
        "seed" | "verify" => functional(authority, engine, mode == "seed", origin).await?,
        "cache-unavailable" => {
            let resolver = external(authority.clone(), engine, b"remote-engine-signed", 4096)?;
            assert!(matches!(
                resolver
                    .resolve(question("coherence.example.test.", QueryType::A)?)
                    .await,
                Err(ResolveError::CacheBackend(_))
            ));
            assert_eq!(authority.exchanges.load(Ordering::Relaxed), 0);
            println!(
                "PASS engine Redis outage: explicit error, no hidden native/upstream fallback"
            );
        }
        "catalog-unavailable" => {
            let request = Message::builder()
                .questions([question("coherence.example.test.", QueryType::A)?])
                .build()?;
            assert_eq!(
                authority.server.handle(request).await.headers.rcode,
                RCode::ServerFailure
            );
            println!("PASS engine PostgreSQL outage: authoritative SERVFAIL");
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}
