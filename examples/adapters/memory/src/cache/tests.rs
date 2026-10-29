use super::*;
use dns::{ClassType, DomainName, IntoWire};
use resolver::{CacheCategory, CacheEntryKey};

fn entry(owner: &str, variant: u8, class: ClassType) -> SealedCacheEntry {
    SealedCacheEntry {
        key: CacheEntryKey {
            family: CacheEntryFamily {
                category: CacheCategory::Positive,
                owner: DomainName::from_dotted(owner).unwrap().into_wire().unwrap(),
                class: u16::from(class),
            },
            discriminator: vec![variant],
        },
        value: b"opaque provider fixture".to_vec(),
        expires_unix_nanos: i128::MAX,
        weight: 1,
    }
}

fn plan(reads: Vec<CacheRead>, maximum_entries: usize) -> CacheReadPlan {
    CacheReadPlan {
        reads,
        maximum_entries,
        maximum_bytes: 4096,
    }
}

async fn read(cache: &ApplicationCache, plan: &CacheReadPlan) -> CacheReadSet {
    match cache.read(b"contract", None, plan).await.unwrap() {
        CacheReadResult::Read(readset) => readset,
        CacheReadResult::Conflict => panic!("an initial read must not conflict"),
    }
}

#[tokio::test]
async fn complete_ancestor_reads_preserve_class_variants_and_enforce_limits() {
    let cache = ApplicationCache::default();
    let entries = [
        entry("test.", 0, ClassType::IN),
        entry("one.test.", 0, ClassType::IN),
        entry("one.test.", 1, ClassType::IN),
        entry("one.test.", 0, ClassType::CH),
        entry("other.test.", 0, ClassType::IN),
    ];
    let initial = read(&cache, &plan(vec![], 0)).await;
    let batch = CacheMutationBatch {
        mutations: entries.iter().cloned().map(CacheMutation::Put).collect(),
    };
    let revision = cache
        .apply(b"contract", &initial.revision, &batch)
        .await
        .unwrap()
        .unwrap();
    let predicates = vec![
        CacheRead::Ancestors(entry("child.one.test.", 0, ClassType::IN).key.family),
        CacheRead::Exact(entries[1].key.clone()),
    ];
    let selected = read(&cache, &plan(predicates.clone(), 3)).await;
    assert_eq!(selected.revision, revision);
    assert_eq!(selected.entries.len(), 3);
    assert_eq!(
        selected
            .entries
            .into_iter()
            .map(|item| item.key)
            .collect::<HashSet<_>>(),
        entries[..3].iter().map(|item| item.key.clone()).collect()
    );
    assert!(
        cache
            .read(b"contract", None, &plan(predicates.clone(), 2))
            .await
            .is_err()
    );
    let tiny = CacheReadPlan {
        maximum_bytes: 1,
        ..plan(predicates.clone(), 3)
    };
    assert!(cache.read(b"contract", None, &tiny).await.is_err());
    assert_eq!(read(&cache, &plan(predicates, 3)).await.revision, revision);
}

#[tokio::test]
async fn absent_members_and_removals_keep_non_reusable_revisions() {
    let cache = ApplicationCache::default();
    let item = entry("one.test.", 0, ClassType::IN);
    let wanted = plan(vec![CacheRead::OwnerFamily(item.key.family.clone())], 2);
    let initial = read(&cache, &wanted).await;
    assert!(initial.entries.is_empty());
    let puts = CacheMutationBatch {
        mutations: vec![CacheMutation::Put(item.clone())],
    };
    let revision = cache
        .apply(b"contract", &initial.revision, &puts)
        .await
        .unwrap()
        .unwrap();
    assert!(
        cache
            .apply(b"contract", &initial.revision, &puts)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        cache
            .read(b"contract", Some(&initial.revision), &wanted)
            .await
            .unwrap(),
        CacheReadResult::Conflict
    ));
    let removals = CacheMutationBatch {
        mutations: vec![CacheMutation::Remove(item.key)],
    };
    let removed = cache
        .apply(b"contract", &revision, &removals)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(removed, initial.revision);
    let final_state = read(&cache, &wanted).await;
    assert_eq!(final_state.revision, removed);
    assert!(final_state.entries.is_empty());
    assert!(
        cache
            .apply(b"contract", &revision, &puts)
            .await
            .unwrap()
            .is_none()
    );
}
