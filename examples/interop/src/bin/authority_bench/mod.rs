//! Allocation-counted authority assembly, validation and encoding. This uses
//! static public BIND fixtures; it does not time signature verification,
//! transport normalization, UDP truncation, or socket I/O.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use dns::{
    DomainName, Edns, FromWire, IntoWire, Message, QClassType, QueryType, Question, RData,
    RecordType, master::MasterFile,
};
use nameserver::{NameServer, Zone};
use transport::{DnsRequestHandler, TransportProtocol};
#[path = "authority_bench/memory.rs"]
mod memory;

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

fn measure(
    mode: &str,
    workload: &str,
    phase: &str,
    wire_bytes: usize,
    iterations: usize,
    mut operation: impl FnMut(),
) {
    for _ in 0..100 {
        operation();
    }
    for repeat in 0..3 {
        ALLOCATIONS.store(0, Ordering::Relaxed);
        BYTES.store(0, Ordering::Relaxed);
        let started = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let nanos = started.elapsed().as_nanos() / iterations as u128;
        let allocations = ALLOCATIONS.load(Ordering::Relaxed) as f64 / iterations as f64;
        let bytes = BYTES.load(Ordering::Relaxed) as f64 / iterations as f64;
        println!(
            "{repeat},{mode},{workload},{phase},{wire_bytes},{allocations:.2},{bytes:.2},{nanos}"
        );
    }
}

fn snapshot_build_profile() {
    let iterations = std::env::var("AUTHORITY_BENCH_BUILD_ITERATIONS")
        .map(|value| {
            value
                .parse::<usize>()
                .expect("positive build iteration count")
        })
        .unwrap_or(200);
    assert!(iterations > 0);
    eprintln!(
        "object layout bytes: DomainName={} Question={} ResourceRecord={} Message={}",
        std::mem::size_of::<DomainName>(),
        std::mem::size_of::<Question>(),
        std::mem::size_of::<dns::ResourceRecord>(),
        std::mem::size_of::<Message>()
    );
    println!("repeat,mode,workload,phase,wire_bytes,allocations,allocated_bytes,ns");
    for (mode, text) in [
        ("unsigned", include_str!("../../fixtures/basic/zone.db")),
        (
            "nsec",
            include_str!("../../../../crates/nameserver/src/zone/tests/fixtures/bind-nsec.zone"),
        ),
        (
            "nsec3",
            include_str!("../../../../crates/nameserver/src/zone/tests/fixtures/bind-nsec3.zone"),
        ),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let parsed = MasterFile::parse(text, Some(apex.clone())).unwrap();
        // Includes cloning caller-owned parsed records, validation, snapshot
        // construction and dropping the result. Parsing itself stays outside.
        measure(
            mode,
            "snapshot",
            "build_from_parsed_and_drop",
            0,
            iterations,
            || {
                let input = MasterFile {
                    records: parsed.records.clone(),
                };
                black_box(Zone::from_master(apex.clone(), input).unwrap());
            },
        );
    }
}

fn main() {
    if let Ok(kind) = std::env::var("AUTHORITY_BENCH_MEMORY") {
        memory::run(&kind);
        return;
    }
    if std::env::var_os("AUTHORITY_BENCH_BUILD_ONLY").is_some() {
        snapshot_build_profile();
        return;
    }
    let iterations: usize = std::env::var("AUTHORITY_BENCH_ITERATIONS")
        .map(|value| value.parse().expect("positive iteration count"))
        .unwrap_or(10000);
    assert!(iterations > 0);
    eprintln!(
        "object layout bytes: DomainName={} Question={} ResourceRecord={} Message={}",
        std::mem::size_of::<DomainName>(),
        std::mem::size_of::<Question>(),
        std::mem::size_of::<dns::ResourceRecord>(),
        std::mem::size_of::<Message>()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    println!("repeat,mode,workload,phase,wire_bytes,allocations,allocated_bytes,ns");
    let invalid = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    measure(
        "common",
        "invalid-first",
        "decode_query",
        12,
        iterations,
        || {
            assert!(Message::from_wire(black_box(&invalid)).is_err());
        },
    );
    for (mode, text) in [
        (
            "nsec",
            include_str!("../../../../crates/nameserver/src/zone/tests/fixtures/bind-nsec.zone"),
        ),
        (
            "nsec3",
            include_str!("../../../../crates/nameserver/src/zone/tests/fixtures/bind-nsec3.zone"),
        ),
    ] {
        let apex = DomainName::from_dotted("example.test.").unwrap();
        let master = MasterFile::parse(text, Some(apex.clone())).unwrap();
        let server = NameServer::new();
        runtime
            .block_on(server.install(Zone::from_master(apex, master).unwrap()))
            .unwrap();
        for (workload, text, qtype, rcode) in [
            ("positive", "www.example.test.", QueryType::A, 0),
            ("negative", "missing.example.test.", QueryType::A, 3),
            ("nodata", "empty.example.test.", QueryType::A, 0),
            ("nodata_owner", "www.example.test.", QueryType::TXT, 0),
            ("wildcard", "m.wild.example.test.", QueryType::TXT, 0),
            ("wildcard_nodata", "m.wild.example.test.", QueryType::A, 0),
            ("cname", "alias.example.test.", QueryType::A, 0),
        ] {
            let query = Message::builder()
                .questions([Question {
                    qname: DomainName::from_dotted(text).unwrap(),
                    qtype,
                    qclass: QClassType::Class(dns::ClassType::IN),
                }])
                .additionals([Edns {
                    dnssec_ok: true,
                    ..Edns::new(1232)
                }
                .into_record()])
                .build()
                .unwrap();
            let query_wire = query.into_wire().unwrap();
            let name_end = 12 + query.questions[0].qname.wire_len();
            measure(
                mode,
                workload,
                "decode_name",
                name_end - 12,
                iterations,
                || {
                    black_box(DomainName::from_wire(black_box(&query_wire[12..name_end])).unwrap());
                },
            );
            measure(
                mode,
                workload,
                "decode_question",
                name_end - 8,
                iterations,
                || {
                    black_box(
                        dns::Question::from_wire(black_box(&query_wire[12..name_end + 4])).unwrap(),
                    );
                },
            );
            measure(
                mode,
                workload,
                "clone_name",
                name_end - 12,
                iterations,
                || {
                    black_box(black_box(&query.questions[0].qname).clone());
                },
            );
            measure(
                mode,
                workload,
                "request_edns_parse",
                query_wire.len(),
                iterations,
                || {
                    black_box(black_box(&query).edns().unwrap());
                },
            );
            measure(
                mode,
                workload,
                "request_validation",
                query_wire.len(),
                iterations,
                || {
                    black_box(&query).validate_for_forwarding().unwrap();
                },
            );
            measure(
                mode,
                workload,
                "decode_query",
                query_wire.len(),
                iterations,
                || {
                    black_box(Message::from_wire(black_box(&query_wire)).unwrap());
                },
            );
            let peer = "127.0.0.1:1234".parse().unwrap();
            let assemble = || {
                server
                    .try_handle(black_box(&query), &query_wire, peer, TransportProtocol::Udp)
                    .unwrap()
            };
            let response = assemble();
            assert_eq!(response.extended_rcode(), rcode);
            assert!(response.headers.aa);
            let wire = response.into_wire().unwrap();
            if workload == "negative" {
                let authorities = response.authorities.iter().collect::<Vec<_>>();
                let borrowed = || {
                    dns::wire::EncodedReply::authoritative_negative(
                        black_box(&query),
                        black_box(&authorities),
                        true,
                        1232,
                    )
                    .unwrap()
                    .unwrap()
                };
                assert_eq!(borrowed().as_bytes(), wire);
                measure(
                    mode,
                    workload,
                    "borrowed_negative_writer",
                    wire.len(),
                    iterations,
                    || {
                        black_box(borrowed());
                    },
                );
            }
            measure(
                mode,
                workload,
                "clone_response",
                wire.len(),
                iterations,
                || {
                    black_box(black_box(&response).clone());
                },
            );
            measure(mode, workload, "assemble", wire.len(), iterations, || {
                black_box(assemble());
            });
            measure(mode, workload, "validate", wire.len(), iterations, || {
                black_box(&response).validate_for_forwarding().unwrap();
            });
            measure(
                mode,
                workload,
                "encode_including_validation",
                wire.len(),
                iterations,
                || {
                    black_box(black_box(&response).into_wire().unwrap());
                },
            );
            // The actual query is decoded for every operation, then follows
            // the same checked immediate handler. Socket batching, admission,
            // transport correlation/normalization and syscalls remain outside
            // this component; their cost must be measured in a live server.
            measure(
                mode,
                workload,
                "decode_and_udp",
                wire.len(),
                iterations,
                || {
                    let decoded = Message::from_wire(black_box(&query_wire)).unwrap();
                    let reply = server
                        .try_handle_udp(&decoded, &query_wire, peer, 1232)
                        .unwrap();
                    let bytes = match reply {
                        transport::ImmediateUdpResponse::Encoded(reply) => reply.into_bytes(),
                        transport::ImmediateUdpResponse::Message(reply) => {
                            reply.into_wire().unwrap()
                        }
                    };
                    black_box(bytes);
                },
            );
            // Separate immutable SOA/signature field checks from the ordinary
            // prefix encoding cost. This is profiling only: production still
            // validates the entire selected response, including proof RRsets.
            let prefix_len = response.authorities.iter().take_while(|record| {
                record.rtype == RecordType::SOA
                    || matches!(&record.rdata, RData::SIG(sig) if record.rtype == RecordType::SIG && sig.type_covered == 6)
                    || matches!(&record.rdata, RData::RRSIG(sig) if record.rtype == RecordType::RRSIG && sig.type_covered == 6)
            }).count();
            if prefix_len > 0 {
                measure(
                    mode,
                    workload,
                    "prefix_record_validation",
                    wire.len(),
                    iterations,
                    || {
                        for record in &response.authorities[..prefix_len] {
                            black_box(record).validate().unwrap();
                        }
                    },
                );
                measure(
                    mode,
                    workload,
                    "proof_record_validation",
                    wire.len(),
                    iterations,
                    || {
                        for record in &response.authorities[prefix_len..] {
                            black_box(record).validate().unwrap();
                        }
                    },
                );
                let mut prefix = response.clone();
                assert!(prefix.answers.is_empty());
                prefix.authorities.truncate(prefix_len);
                let prefix_wire = prefix.into_wire().unwrap();
                measure(
                    mode,
                    workload,
                    "prefix_validate_message",
                    prefix_wire.len(),
                    iterations,
                    || {
                        black_box(&prefix).validate_for_forwarding().unwrap();
                    },
                );
                measure(
                    mode,
                    workload,
                    "prefix_encode_including_validation",
                    prefix_wire.len(),
                    iterations,
                    || {
                        black_box(black_box(&prefix).into_wire().unwrap());
                    },
                );
            }

            measure(
                mode,
                workload,
                "assemble_and_encode",
                wire.len(),
                iterations,
                || {
                    black_box(assemble().into_wire().unwrap());
                },
            );
            let udp = || match server
                .try_handle_udp(black_box(&query), &query_wire, peer, 1232)
                .unwrap()
            {
                transport::ImmediateUdpResponse::Encoded(reply) => reply.into_bytes(),
                transport::ImmediateUdpResponse::Message(reply) => reply.into_wire().unwrap(),
            };
            assert_eq!(udp(), wire);
            // Exercise popularity-gated preparation before comparing bytes,
            // rather than checking only the initial borrowed response.
            for _ in 0..40 {
                assert_eq!(udp(), wire);
            }
            measure(
                mode,
                workload,
                "udp_assemble_and_encode",
                wire.len(),
                iterations,
                || {
                    black_box(udp());
                },
            );
        }
    }
}
