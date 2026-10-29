//! Profile admitted validating cache replies using genuine BIND wire captures.
//! Socket I/O, UDP normalization and truncation are excluded from these phases.
//! Initial resolution and first UDP use are separate from steady-state samples.

use dns::{
    ClassType, DomainName, Edns, FromWire, Headers, IntoWire, Message, QClassType, QueryType,
    Question, RCode, RData, RecordType,
};
use donna_interop::Failure;
use resolver::{RecursiveServer, Resolver, ResolverConfig};
use std::{
    hint::black_box,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use transport::{DnsRequestHandler, Transport, TransportError, TransportProtocol};

#[path = "validating_cache_bench/allocator.rs"]
mod allocator;
use allocator::{ALLOCATIONS, BYTES};

struct CapturedAuthority {
    replies: Vec<Message>,
    calls: Arc<AtomicUsize>,
}

impl Transport for CapturedAuthority {
    fn exchange<'future>(
        &'future self,
        _: SocketAddr,
        query: &'future Message,
        _: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let question = &query.questions[0];
            let mut reply = self
                .replies
                .iter()
                .find(|reply| {
                    reply.questions.first().is_some_and(|q| {
                        q.qname.eq_dns(&question.qname)
                            && q.qtype == question.qtype
                            && q.qclass == question.qclass
                    })
                })
                .cloned()
                .unwrap_or_else(|| Message {
                    headers: Headers {
                        qr: true,
                        rcode: RCode::Refused,
                        ..Headers::default()
                    },
                    questions: vec![],
                    answers: vec![],
                    authorities: vec![],
                    additionals: vec![],
                });
            reply.headers.id = query.headers.id;
            reply.headers.rd = query.headers.rd;
            reply.questions.clone_from(&query.questions);
            Ok(reply)
        })
    }
}

fn measure(
    mode: &str,
    workload: &str,
    phase: &str,
    bytes: usize,
    operation: impl Fn(),
    iterations: usize,
) {
    for _ in 0..100 {
        operation();
    }
    for repeat in 0..3 {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let ns = start.elapsed().as_nanos() / iterations as u128;
        let allocations = ALLOCATIONS.load(Ordering::Relaxed) as f64 / iterations as f64;
        let allocated = BYTES.load(Ordering::Relaxed) as f64 / iterations as f64;
        println!("{repeat},{mode},{workload},{phase},{bytes},{allocations:.2},{allocated:.2},{ns}");
    }
}

// Single first-use observations include admission/setup work. These are not
// steady-state medians or cold root-to-leaf validation measurements.
fn measure_once<T>(mode: &str, workload: &str, phase: &str, operation: impl FnOnce() -> T) -> T {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    let start = Instant::now();
    let result = operation();
    let ns = start.elapsed().as_nanos();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let allocated = BYTES.load(Ordering::Relaxed);
    println!("0,{mode},{workload},{phase},0,{allocations},{allocated},{ns}");
    result
}

// Two independently cached unsigned aliases share one terminal negative.
// This stresses composition reuse across query names without adding crypto or
// network effects to the allocation/CPU measurement.
fn profile_fan_in(runtime: &tokio::runtime::Runtime, iterations: usize) -> Result<(), Failure> {
    let terminal = DomainName::from_dotted("empty.example.test.")?;
    let zone = DomainName::from_dotted("example.test.")?;
    let questions: Vec<_> = ["one.negative.example.test.", "two.negative.example.test."]
        .into_iter()
        .map(|text| {
            Ok(Question {
                qname: DomainName::from_dotted(text)?,
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            })
        })
        .collect::<Result<_, Failure>>()?;
    let terminal_question = Question {
        qname: terminal.clone(),
        ..questions[0].clone()
    };
    let mut replies = Vec::new();
    for question in &questions {
        replies.push(Message {
            headers: Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: vec![question.clone()],
            answers: vec![dns::ResourceRecord {
                name: question.qname.clone(),
                rtype: RecordType::CNAME,
                class: ClassType::IN,
                ttl: 300,
                rdata: RData::CNAME(terminal.clone()),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        });
    }
    replies.push(Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![terminal_question],
        answers: Vec::new(),
        authorities: vec![dns::ResourceRecord {
            name: zone,
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: 300,
            rdata: RData::SOA {
                mname: DomainName::from_dotted("ns.example.test.")?,
                rname: DomainName::from_dotted("hostmaster.example.test.")?,
                serial: 1,
                refresh: 60,
                retry: 60,
                expire: 3600,
                minimum: 300,
            },
        }],
        additionals: Vec::new(),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Resolver::new(
        CapturedAuthority {
            replies,
            calls: Arc::clone(&calls),
        },
        ResolverConfig {
            root_servers: vec!["192.0.2.53:53".parse()?],
            ..ResolverConfig::default()
        },
    );
    for question in &questions {
        let response = runtime.block_on(resolver.resolve(question.clone()))?;
        assert_eq!(response.headers.rcode, RCode::Ok);
        assert!(!response.headers.ad);
    }
    let server = RecursiveServer::with_resolver(resolver);
    let peer = "127.0.0.1:1234".parse()?;
    let mut prepared = Vec::new();
    for question in questions {
        let query = Message {
            headers: Headers {
                rd: true,
                ..Headers::default()
            },
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: vec![
                Edns {
                    dnssec_ok: true,
                    ..Edns::new(1232)
                }
                .into_record(),
            ],
        };
        let wire = query.into_wire()?;
        for _ in 0..128 {
            black_box(
                server
                    .try_handle(&query, &wire, peer, TransportProtocol::Udp)
                    .unwrap(),
            );
        }
        let mut expected = server
            .try_handle(&query, &wire, peer, TransportProtocol::Udp)
            .unwrap();
        let sample = server.try_handle_udp(&query, &wire, peer, 1232).unwrap();
        let mut actual = match sample {
            transport::ImmediateUdpResponse::Encoded(reply) => {
                assert!(reply.matches_request(&query));
                reply.into_message()?
            }
            transport::ImmediateUdpResponse::Message(reply) => reply,
        };
        assert!(!actual.headers.ad);
        for message in [&mut actual, &mut expected] {
            for record in message.answers.iter_mut().chain(&mut message.authorities) {
                record.ttl = 0;
            }
        }
        assert_eq!(actual.into_wire()?, expected.into_wire()?);
        prepared.push((query, wire));
    }
    let upstream = calls.load(Ordering::Relaxed);
    let next = std::cell::Cell::new(0);
    measure(
        "unsigned",
        "cname_negative_fan_in",
        "udp_ready",
        0,
        || {
            let index = next.get();
            next.set(index ^ 1);
            let (query, wire) = &prepared[index];
            let reply = server
                .try_handle_udp(black_box(query), wire, peer, 1232)
                .unwrap();
            match reply {
                transport::ImmediateUdpResponse::Encoded(reply) => {
                    assert!(reply.matches_request(query));
                    assert!(reply.as_bytes().len() <= 1232);
                    black_box(reply.into_bytes());
                }
                transport::ImmediateUdpResponse::Message(reply) => {
                    black_box(reply.into_wire().unwrap());
                }
            }
        },
        iterations,
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        upstream,
        "fan-in profile performed upstream work"
    );
    Ok(())
}

fn main() -> Result<(), Failure> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("expected capture directory")?,
    );
    let iterations = std::env::var("CACHE_PROFILE_ITERATIONS")
        .map(|s| s.parse())
        .unwrap_or(Ok(10000_usize))?;
    assert!(iterations > 0);
    let query_format =
        std::env::var("CACHE_PROFILE_QUERY_FORMAT").unwrap_or_else(|_| "edns-do".to_owned());
    if !matches!(query_format.as_str(), "classic" | "edns" | "edns-do") {
        return Err("CACHE_PROFILE_QUERY_FORMAT must be classic, edns, or edns-do".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    println!("repeat,mode,workload,phase,wire_bytes,allocations,allocated_bytes,ns");
    for mode in ["nsec", "nsec3"] {
        let directory = root.join(mode);
        let mut replies = Vec::new();
        for file in std::fs::read_dir(&directory)? {
            let file = file?.path();
            if file.extension().is_some_and(|ext| ext == "wire") {
                replies.push(Message::from_wire(&std::fs::read(file)?)?);
            }
        }
        let keys = Message::from_wire(&std::fs::read(directory.join("keys.wire"))?)?;
        let trust_anchors = keys
            .answers
            .into_iter()
            .filter(|record| {
                record.rtype == RecordType::DNSKEY
                    && matches!(&record.rdata, RData::DNSKEY(key) if key.flags == 257)
            })
            .collect::<Vec<_>>();
        assert!(!trust_anchors.is_empty());
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            CapturedAuthority {
                replies,
                calls: Arc::clone(&calls),
            },
            ResolverConfig {
                root_servers: vec!["192.0.2.53:53".parse()?],
                trust_anchors,
                ..ResolverConfig::default()
            },
        );
        let cases = [
            ("positive", "www.example.test.", QueryType::A, RCode::Ok),
            ("cname", "alias.example.test.", QueryType::A, RCode::Ok),
            (
                "negative",
                "missing.example.test.",
                QueryType::A,
                RCode::NameError,
            ),
            ("nodata", "empty.example.test.", QueryType::A, RCode::Ok),
            (
                "wildcard",
                "m.wild.example.test.",
                QueryType::TXT,
                RCode::Ok,
            ),
            (
                "cname_negative",
                "alias-empty.example.test.",
                QueryType::A,
                RCode::Ok,
            ),
        ];
        let mut prepared = Vec::new();
        for (workload, text, qtype, rcode) in cases {
            let question = Question {
                qname: DomainName::from_dotted(text)?,
                qtype,
                qclass: QClassType::Class(ClassType::IN),
            };
            let warmed = measure_once(mode, workload, "initial_resolution", || {
                runtime.block_on(resolver.resolve(question.clone()))
            })?;
            assert_eq!(warmed.headers.rcode, rcode);
            let expected_ad = !(mode == "nsec3" && matches!(workload, "negative" | "wildcard"));
            assert_eq!(warmed.headers.ad, expected_ad);
            let query = Message::builder()
                .headers(Headers {
                    rd: true,
                    ..Headers::default()
                })
                .questions([question])
                .additionals(
                    std::iter::once(
                        Edns {
                            dnssec_ok: query_format == "edns-do",
                            ..Edns::new(1232)
                        }
                        .into_record(),
                    )
                    .filter(|_| query_format != "classic"),
                )
                .build()?;
            prepared.push((workload, query, expected_ad && query_format == "edns-do"));
        }
        let server = RecursiveServer::with_resolver(resolver);
        let upstream = calls.load(Ordering::Relaxed);
        for (workload, query, expected_ad) in prepared {
            let wire_query = query.into_wire()?;
            let peer = "127.0.0.1:1234".parse()?;
            let early = measure_once(mode, workload, "first_udp", || {
                server
                    .try_handle_udp(&query, &wire_query, peer, 1232)
                    .unwrap()
            });
            black_box(early);
            let assemble = || {
                server
                    .try_handle(black_box(&query), &wire_query, peer, TransportProtocol::Udp)
                    .unwrap()
            };
            let response = assemble();
            assert_eq!(response.headers.ad, expected_ad);
            let wire = response.into_wire()?;
            measure(
                mode,
                workload,
                "assemble",
                wire.len(),
                || {
                    black_box(assemble());
                },
                iterations,
            );
            measure(
                mode,
                workload,
                "validate",
                wire.len(),
                || {
                    black_box(&response).validate_for_forwarding().unwrap();
                },
                iterations,
            );
            measure(
                mode,
                workload,
                "encode_including_validation",
                wire.len(),
                || {
                    black_box(black_box(&response).into_wire().unwrap());
                },
                iterations,
            );
            measure(
                mode,
                workload,
                "assemble_and_encode",
                wire.len(),
                || {
                    black_box(assemble().into_wire().unwrap());
                },
                iterations,
            );
            let udp_sample = measure_once(mode, workload, "popular_udp_setup", || {
                server
                    .try_handle_udp(&query, &wire_query, peer, 1232)
                    .unwrap()
            });
            let udp_wire = match udp_sample {
                transport::ImmediateUdpResponse::Encoded(sample) => {
                    assert!(sample.matches_request(&query));
                    sample.into_bytes()
                }
                transport::ImmediateUdpResponse::Message(sample) => sample.into_wire().unwrap(),
            };
            let mut udp_decoded = Message::from_wire(&udp_wire).unwrap();
            assert_eq!(udp_decoded.headers.ad, expected_ad);
            let mut expected = response.clone();
            for message in [&mut udp_decoded, &mut expected] {
                for record in message.answers.iter_mut().chain(&mut message.authorities) {
                    record.ttl = 0;
                }
            }
            assert_eq!(
                udp_decoded.into_wire().unwrap(),
                expected.into_wire().unwrap()
            );
            measure(
                mode,
                workload,
                "udp_ready",
                udp_wire.len(),
                || {
                    let response = server
                        .try_handle_udp(black_box(&query), &wire_query, peer, 1232)
                        .unwrap();
                    match response {
                        transport::ImmediateUdpResponse::Encoded(response) => {
                            assert!(response.matches_request(&query));
                            assert!(response.as_bytes().len() <= 1232);
                            black_box(response.into_bytes());
                        }
                        transport::ImmediateUdpResponse::Message(response) => {
                            black_box(response.into_wire().unwrap());
                        }
                    }
                },
                iterations,
            );
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            upstream,
            "cache profile performed upstream work"
        );
    }
    profile_fan_in(&runtime, iterations)?;
    Ok(())
}
