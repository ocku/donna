//! Real-service provider contract checks; these opaque fixtures assert no DNS trust.
use crate::redis_engine::RedisCacheEngine;
use dns::{DomainName, IntoWire};
use resolver::{
    CacheCategory, CacheEngine, CacheEntryFamily, CacheEntryKey, CacheMutation, CacheMutationBatch,
    CacheRead, CacheReadPlan, CacheReadResult, CacheReadSet, SealedCacheEntry,
};
use std::{
    error::Error,
    sync::{Arc, atomic::Ordering},
};

type Failure = Box<dyn Error + Send + Sync>;
fn key(category: CacheCategory, owner: &str, discriminator: u8) -> Result<CacheEntryKey, Failure> {
    Ok(CacheEntryKey {
        family: CacheEntryFamily {
            category,
            owner: DomainName::from_dotted(owner)?.into_wire()?,
            class: 1,
        },
        discriminator: vec![discriminator],
    })
}
fn plan(reads: Vec<CacheRead>) -> CacheReadPlan {
    CacheReadPlan {
        reads,
        maximum_entries: 1024,
        maximum_bytes: 1024 * 1024,
    }
}
async fn read(
    engine: &RedisCacheEngine,
    ns: &[u8],
    plan: &CacheReadPlan,
) -> Result<CacheReadSet, Failure> {
    match engine.read(ns, None, plan).await? {
        CacheReadResult::Read(state) => Ok(state),
        CacheReadResult::Conflict => Err("unexpected unpinned conflict".into()),
    }
}
fn entry(key: CacheEntryKey, size: usize) -> SealedCacheEntry {
    SealedCacheEntry {
        key,
        value: vec![0x5a; size],
        expires_unix_nanos: i128::MAX,
        weight: size as u64,
    }
}
fn batch(mutations: Vec<CacheMutation>) -> CacheMutationBatch {
    CacheMutationBatch { mutations }
}

pub async fn check(engine: Arc<RedisCacheEngine>, url: &str) -> Result<(), Failure> {
    use CacheCategory::{
        AuthenticatedKeys, Bad, Delegation, Failure as TerminalFailure, Negative, Positive,
    };
    let ns = b"provider-contract-six-categories";
    let keys = [
        Positive,
        Negative,
        Delegation,
        Bad,
        TerminalFailure,
        AuthenticatedKeys,
    ]
    .map(|kind| key(kind, "one.provider.test.", 0).unwrap());
    let wanted = plan(keys.iter().cloned().map(CacheRead::Exact).collect());
    let initial = read(&engine, ns, &wanted).await?;
    assert!(initial.entries.is_empty());
    let zero = CacheReadPlan {
        reads: vec![],
        maximum_entries: 0,
        maximum_bytes: 0,
    };
    assert!(read(&engine, ns, &zero).await?.entries.is_empty());
    let values = batch(
        keys.iter()
            .cloned()
            .map(|k| CacheMutation::Put(entry(k, 64)))
            .collect(),
    );
    let revision = engine
        .apply(ns, &initial.revision, &values)
        .await?
        .ok_or("unexpected initial conflict")?;
    assert!(
        engine
            .apply(ns, &initial.revision, &values)
            .await?
            .is_none()
    );
    let state = read(&engine, ns, &wanted).await?;
    assert_eq!(state.entries.len(), 6);
    let zero = CacheReadPlan {
        reads: vec![CacheRead::Exact(keys[0].clone())],
        maximum_entries: 0,
        maximum_bytes: 0,
    };
    assert!(engine.read(ns, None, &zero).await.is_err());
    let absent = key(Positive, "absent.provider.test.", 0)?;
    let residual = CacheReadPlan {
        reads: vec![CacheRead::Exact(absent)],
        maximum_entries: 0,
        maximum_bytes: 0,
    };
    assert!(read(&engine, ns, &residual).await?.entries.is_empty());
    let residual = CacheReadPlan {
        reads: vec![CacheRead::Exact(keys[0].clone())],
        maximum_entries: 1,
        maximum_bytes: 512,
    };
    assert_eq!(read(&engine, ns, &residual).await?.entries.len(), 1);
    assert_eq!(state.revision, revision);
    let duplicate = read(&engine, ns, &wanted).await?;
    assert_eq!(
        duplicate.revision, revision,
        "read cannot update access/retention"
    );
    let accesses = batch(vec![CacheMutation::Access(keys[0].clone())]);
    let (first, second) = tokio::join!(
        engine.apply(ns, &revision, &accesses),
        engine.apply(ns, &revision, &accesses)
    );
    assert_ne!(
        first?.is_some(),
        second?.is_some(),
        "one concurrent writer wins"
    );
    assert!(matches!(
        engine.read(ns, Some(&revision), &wanted).await?,
        CacheReadResult::Conflict
    ));
    // A previously absent family member is protected by the namespace token.
    let family = plan(vec![CacheRead::OwnerFamily(keys[0].family.clone())]);
    let before = read(&engine, ns, &family).await?;
    let extra = key(Positive, "one.provider.test.", 1)?;
    engine
        .apply(
            ns,
            &before.revision,
            &batch(vec![CacheMutation::Put(entry(extra, 80))]),
        )
        .await?
        .ok_or("phantom writer conflict")?;
    assert!(
        engine
            .apply(ns, &before.revision, &accesses)
            .await?
            .is_none()
    );
    let child = key(Positive, "child.one.provider.test.", 0)?;
    let ancestor = read(&engine, ns, &plan(vec![CacheRead::Ancestors(child.family)])).await?;
    assert_eq!(ancestor.entries.len(), 2);
    let optional = read(
        &engine,
        ns,
        &plan(vec![CacheRead::DenialCandidates(keys[0].family.clone())]),
    )
    .await?;
    assert!(optional.entries.is_empty());
    let mut small = wanted.clone();
    small.maximum_entries = 1;
    assert!(engine.read(ns, None, &small).await.is_err());
    assert_eq!(
        read(&engine, ns, &family).await?.revision,
        ancestor.revision,
        "rejected read is side-effect-free"
    );
    let large = key(Positive, "large.provider.test.", 0)?;
    let state = read(&engine, ns, &plan(vec![])).await?;
    engine
        .apply(
            ns,
            &state.revision,
            &batch(vec![CacheMutation::Put(entry(large.clone(), 2048))]),
        )
        .await?
        .ok_or("large writer conflict")?;
    let mut small = plan(vec![CacheRead::Exact(large)]);
    small.maximum_bytes = 1024;
    assert!(engine.read(ns, None, &small).await.is_err());
    println!(
        "PASS engine provider: six categories, exact/family/ancestors, phantom/concurrent CAS, complete bounded reads, optional hints"
    );

    // Provider FIFO differs from Donna's native LFU. Access does not protect oldest.
    let fifo = RedisCacheEngine::new(url)?.with_capacity(2)?;
    let ns = b"provider-fifo";
    let a = key(Positive, "a.provider.test.", 0)?;
    let b = key(Positive, "b.provider.test.", 0)?;
    let c = key(Positive, "c.provider.test.", 0)?;
    let p = plan(vec![
        CacheRead::Exact(a.clone()),
        CacheRead::Exact(b.clone()),
        CacheRead::Exact(c.clone()),
    ]);
    let s = read(&fifo, ns, &p).await?;
    let rev = fifo
        .apply(
            ns,
            &s.revision,
            &batch(vec![
                CacheMutation::Put(entry(a.clone(), 8)),
                CacheMutation::Put(entry(b.clone(), 8)),
            ]),
        )
        .await?
        .unwrap();
    let rev = fifo
        .apply(ns, &rev, &batch(vec![CacheMutation::Access(a.clone())]))
        .await?
        .unwrap();
    fifo.apply(
        ns,
        &rev,
        &batch(vec![CacheMutation::Put(entry(c.clone(), 8))]),
    )
    .await?
    .unwrap();
    let retained = read(&fifo, ns, &p).await?;
    assert_eq!(retained.entries.len(), 2);
    assert!(!retained.entries.iter().any(|e| e.key == a));
    assert!(fifo.metrics.evictions.load(Ordering::Relaxed) > 0);
    // Declining a replacement removes the old key instead of preserving old data.
    let none = RedisCacheEngine::new(url)?.with_capacity(0)?;
    none.apply(
        ns,
        &retained.revision,
        &batch(vec![
            CacheMutation::Put(entry(b, 8)),
            CacheMutation::Remove(c),
        ]),
    )
    .await?
    .unwrap();
    assert!(read(&none, ns, &p).await?.entries.is_empty());
    println!(
        "PASS engine provider: independent FIFO eviction, mandatory removals, declined replacement becomes absent"
    );

    // A targeted hit remains one value with a large unrelated population.
    let ns = b"provider-targeted-population";
    let mut inserts = Vec::new();
    let mut target = None;
    for index in 0..2048 {
        let k = key(Positive, &format!("p{index}.population.test."), 0)?;
        if index == 1024 {
            target = Some(k.clone());
        }
        inserts.push(CacheMutation::Put(entry(k, 64)));
    }
    let empty = read(&engine, ns, &plan(vec![])).await?;
    engine
        .apply(ns, &empty.revision, &batch(inserts))
        .await?
        .ok_or("population writer conflict")?;
    let before = engine.metrics.counts();
    let one = read(&engine, ns, &plan(vec![CacheRead::Exact(target.unwrap())])).await?;
    let after = engine.metrics.counts();
    assert_eq!(one.entries.len(), 1);
    assert_eq!(after[2] - before[2], 1);
    assert!(after[3] - before[3] < 1024);
    println!(
        "PASS engine provider: unrelated population=2048 exact returned_entries=1 returned_bytes={}",
        after[3] - before[3]
    );
    Ok(())
}
