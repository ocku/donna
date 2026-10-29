//! Fixed-time signature costs using committed public BIND fixtures.
//! This excludes sockets, resolver admission, chain acquisition and wall-clock sampling.
use std::{hint::black_box, time::Instant};

use dns::{
    ClassType, DnssecValidation, DomainName, Edns, Message, QClassType, QueryType, Question, RData,
    RecordType, authenticate_dnskey_with_anchor, master::MasterFile,
};
use nameserver::{NameServer, Zone};
use transport::{DnsRequestHandler, TransportProtocol};

fn secure<T: std::fmt::Debug>(outcome: DnssecValidation<T>) -> T {
    match outcome {
        DnssecValidation::Secure(value) => value,
        other => panic!("fixture must authenticate: {other:?}"),
    }
}

fn measure(mode: &str, workload: &str, phase: &str, iterations: usize, mut f: impl FnMut()) {
    for _ in 0..100 {
        f();
    }
    for repeat in 0..5 {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        println!(
            "{mode},{workload},{phase},{repeat},{}",
            start.elapsed().as_nanos() / iterations as u128
        );
    }
}

fn main() {
    let iterations = std::env::var("SIGNATURE_BENCH_ITERATIONS")
        .map(|n| n.parse::<usize>().expect("positive iteration count"))
        .unwrap_or(10_000);
    assert!(iterations > 0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    println!("mode,workload,phase,repeat,nanoseconds");
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
        let records: Vec<_> = master
            .records
            .iter()
            .filter(|r| r.rtype == RecordType::DNSKEY)
            .cloned()
            .collect();
        let signatures: Vec<_> = master
            .records
            .iter()
            .filter(|r| matches!(&r.rdata, RData::RRSIG(sig) if sig.type_covered == 48))
            .cloned()
            .collect();
        let anchor = records
            .iter()
            .find_map(|r| match &r.rdata {
                RData::DNSKEY(key) if key.flags & 1 != 0 => Some(key),
                _ => None,
            })
            .unwrap();
        let RData::RRSIG(signature) = &signatures[0].rdata else {
            unreachable!()
        };
        let now = signature.signature_inception.wrapping_add(60);
        eprintln!("fixture {mode} validation_time={now}");
        let keys = secure(authenticate_dnskey_with_anchor(
            &apex,
            ClassType::IN,
            &records,
            &signatures,
            anchor,
            now,
        ));
        let server = NameServer::new();
        runtime
            .block_on(server.install(Zone::from_master(apex, master).unwrap()))
            .unwrap();
        for (workload, name, name_error) in [
            ("negative", "missing.example.test.", true),
            ("nodata", "empty.example.test.", false),
        ] {
            let name = DomainName::from_dotted(name).unwrap();
            let query = Message::builder()
                .questions([Question {
                    qname: name.clone(),
                    qtype: QueryType::A,
                    qclass: QClassType::Class(ClassType::IN),
                }])
                .additionals([Edns {
                    dnssec_ok: true,
                    ..Edns::new(1232)
                }
                .into_record()])
                .build()
                .unwrap();
            let response = server
                .try_handle(
                    &query,
                    &[],
                    "127.0.0.1:1234".parse().unwrap(),
                    TransportProtocol::Udp,
                )
                .unwrap();
            assert!(response.headers.aa && response.answers.is_empty());
            assert_eq!(response.extended_rcode(), if name_error { 3 } else { 0 });
            let soa: Vec<_> = response
                .authorities
                .iter()
                .filter(|r| r.rtype == RecordType::SOA)
                .cloned()
                .collect();
            let signatures: Vec<_> = response
                .authorities
                .iter()
                .filter(|r| r.rtype == RecordType::RRSIG)
                .cloned()
                .collect();
            let soa_signatures: Vec<_> = signatures
                .iter()
                .filter(|r| matches!(&r.rdata,RData::RRSIG(sig) if sig.type_covered==6))
                .cloned()
                .collect();
            let soa_result = secure(keys.validate_rrset(&soa, &soa_signatures, now));
            assert_eq!(soa_result.authenticated_ttl(), 30);
            let RData::RRSIG(sig) = &soa_signatures[0].rdata else {
                unreachable!()
            };
            let proofs: Vec<_> = response
                .authorities
                .iter()
                .filter(|r| {
                    r.rtype
                        == if mode == "nsec" {
                            RecordType::NSEC
                        } else {
                            RecordType::NSEC3
                        }
                })
                .cloned()
                .collect();
            let denial = || match (mode, name_error) {
                ("nsec", true) => keys.validate_nsec_name_error(&name, &proofs, &signatures, now),
                ("nsec", false) => keys.validate_nsec_nodata(&name, 1, &proofs, &signatures, now),
                (_, true) => keys.validate_nsec3_name_error(&name, &proofs, &signatures, now, 10),
                (_, false) => keys.validate_nsec3_nodata(&name, 1, &proofs, &signatures, now, 10),
            };
            secure(denial());
            measure(mode, workload, "soa_canonical_data", iterations, || {
                black_box(sig.signed_data(black_box(&soa)).unwrap());
            });
            measure(mode, workload, "soa_validate", iterations, || {
                black_box(secure(keys.validate_rrset(
                    black_box(&soa),
                    black_box(&soa_signatures),
                    now,
                )));
            });
            measure(mode, workload, "denial_validate", iterations, || {
                black_box(secure(denial()));
            });
            measure(
                mode,
                workload,
                "soa_and_denial_validate",
                iterations,
                || {
                    black_box(secure(keys.validate_rrset(
                        black_box(&soa),
                        black_box(&soa_signatures),
                        now,
                    )));
                    black_box(secure(denial()));
                },
            );
        }
    }
}
