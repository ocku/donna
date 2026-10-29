//! Count wire-codec allocations independently of DNS lookup and network costs.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use dns::{
    ClassType, DomainName, FromWire, Headers, IntoWire, Message, QClassType, QueryType, Question,
    RData, RecordType, ResourceRecord,
};
use resolver::{Resolver, ResolverConfig};
use transport::{Transport, TransportError};

struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure(label: &str, wire_bytes: usize, operation: impl FnMut()) {
    measure_iterations(label, wire_bytes, 100, operation);
}

fn measure_iterations(
    label: &str,
    wire_bytes: usize,
    iterations: u128,
    mut operation: impl FnMut(),
) {
    // Setup, formatting and console output remain outside the counted interval.
    ALLOCATIONS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed().as_nanos() / iterations;
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) / iterations as usize;
    let bytes = BYTES.load(Ordering::Relaxed) / iterations as usize;
    println!("{label},{wire_bytes},{allocations},{bytes},{elapsed}");
}

fn aggregate_admission_costs() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let questions = (0..10)
        .map(|index| Question {
            qname: DomainName::from_dotted(&format!("aggregate{index}.example.test.")).unwrap(),
            qtype: QueryType::ANY,
            qclass: QClassType::Class(ClassType::IN),
        })
        .collect::<Vec<_>>();
    for count in [16, 64, 128, 256] {
        for capacity in [0, 1024] {
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver = Resolver::new(
                Authority {
                    calls: Arc::clone(&calls),
                    records: count,
                },
                ResolverConfig {
                    cache_capacity: capacity,
                    ..ResolverConfig::default()
                },
            );
            let mut next = 0;
            measure_iterations(
                &format!("any_rrset_{count}_capacity_{capacity}"),
                0,
                10,
                || {
                    let response = runtime
                        .block_on(resolver.resolve(questions[next].clone()))
                        .unwrap();
                    assert_eq!(response.answers.len(), count);
                    black_box(response);
                    next += 1;
                },
            );
            assert_eq!(calls.load(Ordering::Relaxed), 10);
        }
    }
}

fn query(name: DomainName) -> Message {
    Message {
        headers: Headers::default(),
        questions: vec![Question {
            qname: name,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

struct Authority {
    calls: Arc<AtomicUsize>,
    records: usize,
}

impl Transport for Authority {
    fn exchange<'future>(
        &'future self,
        _: std::net::SocketAddr,
        request: &'future Message,
        _: std::time::Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut response = request.clone();
            response.headers.qr = true;
            response.headers.aa = true;
            response.additionals.clear();
            response.answers = (0..self.records)
                .map(|index| ResourceRecord {
                    name: request.questions[0].qname.clone(),
                    rtype: RecordType::A,
                    class: ClassType::IN,
                    ttl: 300,
                    rdata: RData::A(std::net::Ipv4Addr::from(0xc0000200 + index as u32)),
                })
                .collect();
            Ok(response)
        })
    }
}

fn clone_and_cache_costs() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for labels in [3, 127] {
        let name = DomainName::from_labels(vec![vec![b'a']; labels]).unwrap();
        let request = query(name.clone());
        let wire_bytes = request.into_wire().unwrap().len();
        measure(&format!("clone_name_labels_{labels}"), wire_bytes, || {
            black_box(black_box(&name).clone());
        });
        measure(&format!("clone_query_labels_{labels}"), wire_bytes, || {
            black_box(black_box(&request).clone());
        });
        let upstream_calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::new(
            Authority {
                calls: Arc::clone(&upstream_calls),
                records: 1,
            },
            ResolverConfig::default(),
        );
        let question = &request.questions[0];
        runtime
            .block_on(resolver.resolve(question.clone()))
            .unwrap();
        let cold_calls = upstream_calls.load(Ordering::Relaxed);
        measure(&format!("cache_hit_labels_{labels}"), wire_bytes, || {
            black_box(
                runtime
                    .block_on(resolver.resolve(question.clone()))
                    .unwrap(),
            );
        });
        assert_eq!(upstream_calls.load(Ordering::Relaxed), cold_calls);
    }
}

fn cold_resolution_costs() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let questions = (0..100)
        .map(|index| {
            query(DomainName::from_dotted(&format!("cold{index}.example.test.")).unwrap())
                .questions
                .remove(0)
        })
        .collect::<Vec<_>>();
    for count in [1, 128, 512, 2048] {
        for capacity in [0, 1024] {
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver = Resolver::new(
                Authority {
                    calls: Arc::clone(&calls),
                    records: count,
                },
                ResolverConfig {
                    cache_capacity: capacity,
                    ..ResolverConfig::default()
                },
            );
            let mut next = 0;
            // Names and clients are prepared outside the timed interval.
            // Every query has a new owner, so admission cannot become a hit.
            measure(
                &format!("cold_rrset_{count}_capacity_{capacity}"),
                0,
                || {
                    let response = runtime
                        .block_on(resolver.resolve(questions[next].clone()))
                        .unwrap();
                    assert_eq!(response.answers.len(), count);
                    black_box(response);
                    next += 1;
                },
            );
            assert_eq!(calls.load(Ordering::Relaxed), 100);
        }
    }
}

fn request_decode_costs() {
    let mut names = vec![(
        "common".to_owned(),
        DomainName::from_dotted("www.example.test.").unwrap(),
    )];
    names.extend([3, 16, 64, 127].map(|labels| {
        (
            format!("labels_{labels}"),
            DomainName::from_labels(vec![vec![b'a']; labels]).unwrap(),
        )
    }));
    for (case, name) in names {
        for edns in [false, true] {
            let mut request = query(name.clone());
            if edns {
                let options = dns::Edns {
                    udp_payload_size: 1232,
                    dnssec_ok: true,
                    ..dns::Edns::default()
                };
                request.additionals.push(options.into_record());
            }
            let wire = request.into_wire().unwrap();
            let decoded = Message::from_wire(&wire).unwrap();
            assert_eq!(decoded.into_wire().unwrap(), wire);
            assert_eq!(decoded.questions[0].qname, request.questions[0].qname);
            assert_eq!(decoded.additionals.len(), usize::from(edns));
            if edns {
                let options = decoded.edns().unwrap().unwrap();
                assert_eq!(options.udp_payload_size, 1232);
                assert!(options.dnssec_ok);
                assert!(options.options.is_empty());
            }
            for _ in 0..1_000 {
                black_box(Message::from_wire(black_box(&wire)).unwrap());
            }
            measure_iterations(
                &format!("decode_request_{case}_edns_{edns}"),
                wire.len(),
                100_000,
                || {
                    black_box(Message::from_wire(black_box(&wire)).unwrap());
                },
            );
        }
    }
}

fn main() {
    println!("case,wire_bytes,allocations,allocated_bytes,nanoseconds");
    if std::env::args().nth(1).as_deref() == Some("--decode-only") {
        request_decode_costs();
        return;
    }
    for labels in [3, 16, 64, 127] {
        let name = DomainName::from_labels(vec![vec![b'a']; labels]).unwrap();
        let wire = query(name).into_wire().unwrap();
        measure(&format!("decode_labels_{labels}"), wire.len(), || {
            black_box(Message::from_wire(black_box(&wire)).unwrap());
        });
    }
    for count in [1, 16, 128, 512, 2048] {
        let mut response = query(DomainName::from_dotted("example.test.").unwrap());
        response.headers.qr = true;
        response.headers.aa = true;
        response.answers = (0..count)
            .map(|index| ResourceRecord {
                name: DomainName::from_dotted(&format!("owner{index}.example.test.")).unwrap(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 300,
                rdata: RData::A("192.0.2.80".parse().unwrap()),
            })
            .collect();
        let wire = response.into_wire().unwrap();
        measure(&format!("validate_owners_{count}"), wire.len(), || {
            black_box(black_box(&response).validate_for_forwarding()).unwrap();
        });
        measure(&format!("encode_owners_{count}"), wire.len(), || {
            black_box(black_box(&response).into_wire().unwrap());
        });
        for (index, record) in response.answers.iter_mut().enumerate() {
            record.name.clone_from(&response.questions[0].qname);
            record.rdata = RData::A(std::net::Ipv4Addr::from(0xc0000200 + index as u32));
        }
        let wire = response.into_wire().unwrap();
        measure(&format!("validate_rrset_{count}"), wire.len(), || {
            black_box(black_box(&response).validate_for_forwarding()).unwrap();
        });
    }
    clone_and_cache_costs();
    cold_resolution_costs();
    aggregate_admission_costs();
}
