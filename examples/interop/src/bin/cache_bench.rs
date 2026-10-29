//! Isolate cache costs from network latency at increasing cache populations.
use std::{
    env,
    hint::black_box,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use dns::{
    ClassType, DomainName, Headers, Message, QClassType, QueryType, Question, RCode, RData,
    RecordType, ResourceRecord,
};
use donna_interop::Failure;
use resolver::{Resolver, ResolverConfig};
use transport::{Transport, TransportError};

struct Authority(Arc<AtomicUsize>);

impl Transport for Authority {
    fn exchange<'future>(
        &'future self,
        _: SocketAddr,
        query: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            let question = &query.questions[0];
            let missing = question.qname.as_ref()[0].starts_with(b"missing-");
            let alias = question.qname.as_ref()[0].starts_with(b"alias-");
            let nodata = question.qname.as_ref()[0].starts_with(b"nodata-");
            let negative = missing || nodata;
            let record = if negative {
                ResourceRecord {
                    name: DomainName::from_dotted("bench.test.").unwrap(),
                    rtype: RecordType::SOA,
                    class: ClassType::IN,
                    ttl: 3600,
                    rdata: RData::SOA {
                        mname: DomainName::from_dotted("ns.bench.test.").unwrap(),
                        rname: DomainName::from_dotted("hostmaster.bench.test.").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 900,
                        expire: 86400,
                        minimum: 3600,
                    },
                }
            } else if alias {
                let label = std::str::from_utf8(&question.qname.as_ref()[0]).unwrap();
                ResourceRecord {
                    name: question.qname.clone(),
                    rtype: RecordType::CNAME,
                    class: ClassType::IN,
                    ttl: 3600,
                    rdata: RData::CNAME(
                        DomainName::from_dotted(&format!(
                            "positive-{}.bench.test.",
                            label.strip_prefix("alias-").unwrap()
                        ))
                        .unwrap(),
                    ),
                }
            } else {
                ResourceRecord {
                    name: question.qname.clone(),
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 3600,
                    rdata: RData::A(Ipv4Addr::new(192, 0, 2, 80)),
                }
            };
            Ok(Message {
                headers: Headers {
                    id: query.headers.id,
                    qr: true,
                    aa: true,
                    rcode: if missing { RCode::NameError } else { RCode::Ok },
                    ..Headers::default()
                },
                questions: query.questions.clone(),
                answers: if negative {
                    vec![]
                } else {
                    vec![record.clone()]
                },
                authorities: if negative { vec![record] } else { vec![] },
                additionals: vec![],
            })
        })
    }
}

fn question(kind: &str, index: usize) -> Question {
    Question {
        qname: DomainName::from_dotted(&format!("{kind}-{index}.bench.test.")).unwrap(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn report(capacity: usize, workload: &str, mut samples: Vec<Duration>) {
    samples.sort_unstable();
    let mean =
        samples.iter().map(Duration::as_secs_f64).sum::<f64>() / samples.len() as f64 * 1_000_000.0;
    println!(
        "{capacity},{workload},{},{mean:.3},{:.3},{:.3}",
        samples.len(),
        samples[samples.len() / 2].as_secs_f64() * 1_000_000.0,
        samples[samples.len() * 95 / 100].as_secs_f64() * 1_000_000.0
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Failure> {
    let capacities: Vec<usize> = env::args()
        .skip(1)
        .map(|value| value.parse())
        .collect::<Result<_, _>>()?;
    let capacities = if capacities.is_empty() {
        vec![128, 1024, 4096, 16384]
    } else {
        capacities
    };
    println!("capacity,workload,operations,mean_us,median_us,p95_us");
    for capacity in capacities {
        if capacity == 0 {
            return Err("capacity must be positive".into());
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            Authority(Arc::clone(&calls)),
            ResolverConfig {
                root_servers: vec!["192.0.2.53:53".parse()?],
                cache_capacity: capacity,
                ..ResolverConfig::default()
            },
        );
        // Populate both stores, exposing cross-cache admission/coherence costs.
        let mut fill = Vec::with_capacity(capacity * 2);
        for index in 0..capacity {
            for kind in ["positive", "missing"] {
                let query = question(kind, index);
                let started = Instant::now();
                black_box(resolver.resolve(query).await?);
                fill.push(started.elapsed());
            }
        }
        assert_eq!(calls.load(Ordering::Relaxed), capacity * 2);
        report(capacity, "fill_mixed", fill);
        for kind in ["positive", "missing"] {
            let queries: Vec<_> = (0..capacity).map(|index| question(kind, index)).collect();
            let before = calls.load(Ordering::Relaxed);
            let mut samples = Vec::with_capacity(10000);
            for index in 0..10000 {
                let query = queries[(index * 7919) % capacity].clone();
                let started = Instant::now();
                black_box(resolver.resolve(query).await?);
                samples.push(started.elapsed());
            }
            assert_eq!(
                calls.load(Ordering::Relaxed),
                before,
                "warm queries went upstream"
            );
            report(capacity, &format!("hit_{kind}"), samples);
        }
        // NODATA probes both name- and type-scoped denials. Keep its owner
        // population separate so negative-cache capacity does not evict the
        // mixed workload being reported above.
        let nodata_resolver = Resolver::new(
            Authority(Arc::clone(&calls)),
            ResolverConfig {
                root_servers: vec!["192.0.2.53:53".parse()?],
                cache_capacity: capacity,
                ..ResolverConfig::default()
            },
        );
        let queries: Vec<_> = (0..capacity)
            .map(|index| question("nodata", index))
            .collect();
        for query in &queries {
            let response = nodata_resolver.resolve(query.clone()).await?;
            assert!(response.answers.is_empty() && response.headers.rcode == RCode::Ok);
        }
        let before = calls.load(Ordering::Relaxed);
        let mut samples = Vec::with_capacity(10000);
        for index in 0..10000 {
            let started = Instant::now();
            black_box(
                nodata_resolver
                    .resolve(queries[(index * 7919) % capacity].clone())
                    .await?,
            );
            samples.push(started.elapsed());
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            before,
            "NODATA hit went upstream"
        );
        report(capacity, "hit_nodata", samples);
        // Admit aliases independently so every warm A query composes a cached
        // CNAME with its cached terminal RRset, rather than an aggregate hit.
        let cname_resolver = Resolver::new(
            Authority(Arc::clone(&calls)),
            ResolverConfig {
                root_servers: vec!["192.0.2.53:53".parse()?],
                cache_capacity: capacity * 2,
                ..ResolverConfig::default()
            },
        );
        for index in 0..capacity {
            cname_resolver.resolve(question("positive", index)).await?;
            let mut alias = question("alias", index);
            alias.qtype = QueryType::CNAME;
            cname_resolver.resolve(alias).await?;
        }
        let queries: Vec<_> = (0..capacity)
            .map(|index| question("alias", index))
            .collect();
        let before = calls.load(Ordering::Relaxed);
        let mut samples = Vec::with_capacity(10000);
        for index in 0..10000 {
            let started = Instant::now();
            black_box(
                cname_resolver
                    .resolve(queries[(index * 7919) % capacity].clone())
                    .await?,
            );
            samples.push(started.elapsed());
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            before,
            "CNAME hit went upstream"
        );
        report(capacity, "hit_cname", samples);
        for kind in ["positive", "missing"] {
            let mut samples = Vec::with_capacity(512);
            for index in capacity..capacity + 512 {
                let query = question(kind, index);
                let started = Instant::now();
                black_box(resolver.resolve(query).await?);
                samples.push(started.elapsed());
            }
            report(capacity, &format!("churn_{kind}"), samples);
        }
    }
    Ok(())
}
