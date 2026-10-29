//! Per-entry Redis provider. Retention is FIFO; Donna supplies no LFU policy here.
#[path = "redis_engine_codec.rs"]
mod codec;
use resolver::{
    CacheEngine, CacheMutation, CacheMutationBatch, CacheRead, CacheReadPlan, CacheReadResult,
    CacheReadSet,
};
use std::{
    collections::BTreeSet,
    io,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;

const READ: &str = include_str!("redis_engine_read.lua");
const APPLY: &str = include_str!("redis_engine_apply.lua");
const DEADLINE: Duration = Duration::from_secs(3);

type ReadReply = (i64, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

#[derive(Default)]
pub struct Metrics {
    pub reads: AtomicUsize,
    pub applies: AtomicUsize,
    pub returned_entries: AtomicUsize,
    pub returned_bytes: AtomicUsize,
    pub conflicts: AtomicUsize,
    pub evictions: AtomicUsize,
    pub declined: AtomicUsize,
    pub category_reads: [AtomicUsize; 6],
    pub category_puts: [AtomicUsize; 6],
}
impl Metrics {
    pub fn counts(&self) -> [usize; 7] {
        [
            &self.reads,
            &self.applies,
            &self.returned_entries,
            &self.returned_bytes,
            &self.conflicts,
            &self.evictions,
            &self.declined,
        ]
        .map(|n| n.load(Ordering::Relaxed))
    }
}
pub struct RedisCacheEngine {
    client: redis::Client,
    capacity: usize,
    pub metrics: Metrics,
    observed_namespace: Mutex<Option<Vec<u8>>>,
}
impl RedisCacheEngine {
    pub fn new(url: &str) -> Result<Self, redis::RedisError> {
        Ok(Self {
            client: redis::Client::open(url)?,
            capacity: codec::MAX_ENTRIES,
            metrics: Metrics::default(),
            observed_namespace: Mutex::new(None),
        })
    }
    pub fn with_capacity(mut self, capacity: usize) -> io::Result<Self> {
        if capacity > codec::MAX_ENTRIES {
            return Err(codec::invalid("provider capacity exceeds bound"));
        }
        self.capacity = capacity;
        Ok(self)
    }
    // Diagnostic identity only, used by the disposable corruption check.
    // No entry, DNS rank, popularity, TTL or validation result is stored here.
    pub fn observed_namespace(&self) -> io::Result<Vec<u8>> {
        self.observed_namespace
            .lock()
            .map_err(|_| codec::invalid("namespace diagnostic poisoned"))?
            .clone()
            .ok_or_else(|| codec::invalid("no provider operation observed"))
    }
    pub(crate) fn keys(namespace: &[u8]) -> io::Result<[String; 2]> {
        if namespace.is_empty() || namespace.len() > 4096 {
            return Err(codec::invalid("invalid provider namespace"));
        }
        let tag = codec::hex(namespace);
        Ok([
            format!("donna:entry:v1:{{{tag}}}:values"),
            format!("donna:entry:v1:{{{tag}}}:fifo"),
        ])
    }
    async fn eval<T: redis::FromRedisValue>(
        &self,
        script: &str,
        namespace: &[u8],
        args: Vec<Vec<u8>>,
    ) -> io::Result<T> {
        let keys = Self::keys(namespace)?;
        *self
            .observed_namespace
            .lock()
            .map_err(|_| codec::invalid("namespace diagnostic poisoned"))? =
            Some(namespace.to_vec());
        timeout(DEADLINE, async {
            let mut connection = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(io::Error::other)?;
            let mut command = redis::cmd("EVAL");
            command.arg(script).arg(2).arg(&keys).arg(args);
            command
                .query_async(&mut connection)
                .await
                .map_err(io::Error::other)
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "Redis operation timed out; a write may have committed",
            )
        })?
    }
}
fn decimal(value: usize) -> Vec<u8> {
    value.to_string().into_bytes()
}
impl CacheEngine for RedisCacheEngine {
    fn read<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: Option<&'a [u8]>,
        plan: &'a CacheReadPlan,
    ) -> transport::BoxFuture<'a, io::Result<CacheReadResult>> {
        Box::pin(async move {
            if expected.is_some_and(|r| !codec::revision(r))
                || plan.reads.len() > 4096
                || plan.maximum_entries > 65536
                || plan.maximum_bytes > 64 * 1024 * 1024
            {
                return Err(codec::invalid("invalid provider read plan"));
            }
            let (mut exact, mut families) = (BTreeSet::new(), BTreeSet::new());
            for read in &plan.reads {
                match read {
                    CacheRead::Exact(key) => {
                        exact.insert(codec::field(key)?);
                    }
                    CacheRead::OwnerFamily(f) => {
                        families.insert(codec::family(f)?);
                    }
                    CacheRead::Ancestors(f) => {
                        families.extend(codec::ancestors(f)?);
                    }
                    CacheRead::DenialCandidates(_) => {} // Optional index unsupported.
                }
                if exact.len() + families.len() > 65536 {
                    return Err(codec::invalid("expanded provider plan exceeds bound"));
                }
            }
            if exact.len() + families.len() > 65536 {
                return Err(codec::invalid("expanded provider plan exceeds bound"));
            }
            let mut args = vec![
                expected.unwrap_or_default().to_vec(),
                decimal(plan.maximum_entries),
                decimal(plan.maximum_bytes),
                decimal(exact.len()),
            ];
            args.extend(exact.into_iter().map(String::into_bytes));
            args.push(decimal(families.len()));
            args.extend(families.into_iter().map(String::into_bytes));
            self.metrics.reads.fetch_add(1, Ordering::Relaxed);
            let (status, revision, rows): ReadReply = self.eval(READ, namespace, args).await?;
            if !codec::revision(&revision) {
                return Err(codec::invalid("invalid returned revision"));
            }
            if status == 0 {
                self.metrics.conflicts.fetch_add(1, Ordering::Relaxed);
                return Ok(CacheReadResult::Conflict);
            }
            if status != 1 || rows.len() > plan.maximum_entries {
                return Err(codec::invalid("invalid provider reply"));
            }
            let mut entries = Vec::with_capacity(rows.len());
            let mut total = 0usize;
            for (field, blob) in rows {
                total = total
                    .checked_add(blob.len())
                    .ok_or_else(|| codec::invalid("provider byte overflow"))?;
                if total > plan.maximum_bytes {
                    return Err(codec::invalid("provider response exceeds bound"));
                }
                let entry = codec::decode(&field, &blob)?;
                self.metrics.category_reads[entry.key.family.category as usize - 1]
                    .fetch_add(1, Ordering::Relaxed);
                entries.push(entry);
            }
            self.metrics
                .returned_entries
                .fetch_add(entries.len(), Ordering::Relaxed);
            self.metrics
                .returned_bytes
                .fetch_add(total, Ordering::Relaxed);
            Ok(CacheReadResult::Read(CacheReadSet { revision, entries }))
        })
    }
    fn apply<'a>(
        &'a self,
        namespace: &'a [u8],
        expected: &'a [u8],
        batch: &'a CacheMutationBatch,
    ) -> transport::BoxFuture<'a, io::Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            if !codec::revision(expected) || batch.mutations.len() > 8192 {
                return Err(codec::invalid("invalid provider batch"));
            }
            let mut args = vec![
                expected.to_vec(),
                decimal(self.capacity),
                decimal(codec::MAX_BYTES),
                decimal(batch.mutations.len()),
            ];
            let mut total = 0usize;
            for mutation in &batch.mutations {
                let (op, key, value) = match mutation {
                    CacheMutation::Put(entry) => {
                        self.metrics.category_puts[entry.key.family.category as usize - 1]
                            .fetch_add(1, Ordering::Relaxed);
                        (b"P".to_vec(), &entry.key, codec::encode(entry)?)
                    }
                    CacheMutation::Remove(key) => (b"R".to_vec(), key, Vec::new()),
                    CacheMutation::Access(key) => (b"A".to_vec(), key, Vec::new()),
                };
                total = total
                    .checked_add(value.len())
                    .ok_or_else(|| codec::invalid("provider batch overflow"))?;
                if total > 64 * 1024 * 1024 {
                    return Err(codec::invalid("provider batch exceeds bound"));
                }
                args.extend([
                    op,
                    codec::field(key)?.into_bytes(),
                    codec::family(&key.family)?.into_bytes(),
                    value,
                ]);
            }
            self.metrics.applies.fetch_add(1, Ordering::Relaxed);
            let (status, revision, evicted, declined): (i64, Vec<u8>, usize, usize) =
                self.eval(APPLY, namespace, args).await?;
            if !codec::revision(&revision) {
                return Err(codec::invalid("invalid returned revision"));
            }
            if status == 0 {
                self.metrics.conflicts.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            if status != 1 || revision == expected {
                return Err(codec::invalid("invalid provider commit"));
            }
            self.metrics.evictions.fetch_add(evicted, Ordering::Relaxed);
            self.metrics.declined.fetch_add(declined, Ordering::Relaxed);
            Ok(Some(revision))
        })
    }
}
