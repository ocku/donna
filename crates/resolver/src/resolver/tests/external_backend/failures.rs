//! Defensive boundaries remain Donna's responsibility even for broken adapters.
use super::*;

struct InvalidBackend {
    revision: usize,
    value: Option<Vec<u8>>,
    commits: AtomicUsize,
}

impl CacheEngine for InvalidBackend {
    fn read<'future>(
        &'future self,
        _: &'future [u8],
        _: Option<&'future [u8]>,
        plan: &'future crate::CacheReadPlan,
    ) -> transport::BoxFuture<'future, io::Result<CacheReadResult>> {
        Box::pin(async move {
            let entries = self.value.as_ref().map_or_else(Vec::new, |value| {
                let crate::CacheRead::OwnerFamily(family) = &plan.reads[0] else {
                    panic!("fixture expects a family read")
                };
                vec![crate::SealedCacheEntry {
                    key: crate::CacheEntryKey {
                        family: family.clone(),
                        discriminator: vec![],
                    },
                    value: value.clone(),
                    expires_unix_nanos: 0,
                    weight: value.len() as u64,
                }]
            });
            Ok(CacheReadResult::Read(crate::CacheReadSet {
                revision: vec![0; self.revision],
                entries,
            }))
        })
    }

    fn apply<'future>(
        &'future self,
        _: &'future [u8],
        _: &'future [u8],
        _: &'future crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'future, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            self.commits.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "commit failed",
            ))
        })
    }
}

fn resolver(backend: Arc<InvalidBackend>) -> Resolver<MockTransport> {
    Resolver::with_cache_engine(
        MockTransport {
            replies: Arc::new(Mutex::new(vec![])),
            requests: Arc::new(Mutex::new(vec![])),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend, b"failure-boundaries".to_vec(), [7; 32])
            .unwrap()
            .with_read_limits(16, 1024)
            .unwrap(),
    )
}

#[tokio::test]
async fn oversized_engine_readsets_are_rejected_before_operation_or_commit() {
    for (revision, value) in [(257, None), (8, Some(vec![0; 1025]))] {
        let backend = Arc::new(InvalidBackend {
            revision,
            value,
            commits: AtomicUsize::new(0),
        });
        let resolver = resolver(backend.clone());
        let operated = AtomicBool::new(false);
        let result = resolver
            .cache_transaction_for(&[question(&["broken", "example"])], |_| {
                operated.store(true, Ordering::Relaxed);
                Ok(())
            })
            .await;
        assert!(
            matches!(result, Err(ResolveError::CacheBackend(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(!operated.load(Ordering::Relaxed));
        assert_eq!(backend.commits.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn failed_external_commit_does_not_publish_to_builtin_cache() {
    let backend = Arc::new(InvalidBackend {
        revision: 8,
        value: None,
        commits: AtomicUsize::new(0),
    });
    let resolver = resolver(backend.clone());
    let query = question(&["failed-commit", "example"]);
    let reply = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(query.qname.clone(), 1)],
    );
    let result = resolver
        .cache_positive_entries_backend(0, &reply, &query)
        .await;
    assert!(
        matches!(result, Err(ResolveError::CacheBackend(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
    );
    assert_eq!(backend.commits.load(Ordering::Relaxed), 1);
    assert!(resolver.cached_positive_response(&query).is_none());
}
