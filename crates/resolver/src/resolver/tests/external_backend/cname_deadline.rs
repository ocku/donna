//! A network alias must keep its original deadline while cache I/O awaits.
use super::*;
use tokio::sync::Semaphore;

struct DelayedBackend {
    inner: Backend,
    armed: AtomicBool,
    skip: AtomicUsize,
    entered: tokio::sync::Notify,
    release: Semaphore,
}

impl Default for DelayedBackend {
    fn default() -> Self {
        Self {
            inner: Backend::default(),
            armed: AtomicBool::new(false),
            skip: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: Semaphore::new(0),
        }
    }
}

impl CacheEngine for DelayedBackend {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected_revision: Option<&'a [u8]>,
        plan: &'a crate::CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        self.inner.read(namespace, expected_revision, plan)
    }

    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        value: &'a crate::CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if self.armed.load(Ordering::SeqCst)
                && self
                    .skip
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .is_err()
                && self.armed.swap(false, Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.release.acquire().await.unwrap().forget();
            }
            self.inner.apply(namespace, expected, value).await
        })
    }
}

#[derive(Clone)]
struct AliasTransport {
    backend: Arc<DelayedBackend>,
    target: DomainName,
    calls: Arc<AtomicUsize>,
}

impl Transport for AliasTransport {
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> transport::BoxFuture<'a, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut alias = cname_record(query.questions[0].qname.clone(), self.target.clone());
            alias.ttl = 2;
            let mut reply = response(
                Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    ..Headers::default()
                },
                vec![alias],
            );
            reply.questions = query.questions.clone();
            // Skip the alias insertion's CAS; hold the following cached-target
            // selection after the network alias was already received.
            self.backend.skip.store(1, Ordering::SeqCst);
            self.backend.armed.store(true, Ordering::SeqCst);
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn network_alias_expires_during_cached_target_commit() {
    let backend = Arc::new(DelayedBackend {
        release: Semaphore::new(0),
        ..DelayedBackend::default()
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let target = question(&["target", "example"]);
    let alias = question(&["alias", "example"]);
    let resolver = Arc::new(Resolver::with_cache_engine(
        AliasTransport {
            backend: backend.clone(),
            target: target.qname.clone(),
            calls: calls.clone(),
        },
        config(vec!["192.0.2.53:53".parse().unwrap()]),
        CacheEngineConfig::new(backend.clone(), b"cname-deadline".to_vec(), [7; 32]).unwrap(),
    ));
    let cached = response(
        Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        vec![address_record(target.qname.clone(), 42)],
    );
    resolver
        .cache_positive_entries_backend(0, &cached, &target)
        .await
        .unwrap();

    let waiting = {
        let resolver = resolver.clone();
        tokio::spawn(async move { resolver.resolve(alias).await })
    };
    tokio::time::timeout(Duration::from_secs(3), backend.entered.notified())
        .await
        .expect("cached target transaction did not reach commit");
    tokio::time::sleep(Duration::from_millis(2200)).await;
    backend.release.add_permits(1);
    let reply = waiting.await.unwrap().unwrap();
    let alias = reply
        .answers
        .iter()
        .find(|rr| rr.rtype == RecordType::CNAME)
        .unwrap();
    let address = reply
        .answers
        .iter()
        .find(|rr| rr.rtype == RecordType::A)
        .unwrap();
    assert_eq!(
        alias.ttl, 0,
        "the network alias cannot be renewed during cache I/O"
    );
    assert!(
        address.ttl > 0,
        "the separately cached target retains its own TTL"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
