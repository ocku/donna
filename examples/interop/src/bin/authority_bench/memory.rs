//! Fresh-process resident-memory and requested-allocation probes. Run separately
//! from timed CPU samples; allocator-retained pages are part of RSS, not a
//! claim about exact live object bytes.
use super::*;

fn resident_kib() -> Option<(usize, usize)> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |name| {
        text.lines().find_map(|line| {
            line.strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    };
    Some((field("VmRSS:")?, field("VmHWM:")?))
}

fn sample<T>(kind: &str, count: usize, construct: impl FnOnce() -> T) {
    let before = resident_kib();
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let bytes = BYTES.load(Ordering::Relaxed);
    let objects = construct();
    black_box(&objects);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - allocations;
    let bytes = BYTES.load(Ordering::Relaxed) - bytes;
    let after = resident_kib();
    let optional = |value: Option<usize>| value.map_or("null".to_owned(), |v| v.to_string());
    println!(
        "{{\"mode\":\"{kind}\",\"count\":{count},\"allocations\":{allocations},\"requested_bytes\":{bytes},\"domain_name_bytes\":{},\"question_bytes\":{},\"record_bytes\":{},\"rss_before_kib\":{},\"rss_after_kib\":{},\"high_water_kib\":{}}}",
        std::mem::size_of::<DomainName>(),
        std::mem::size_of::<Question>(),
        std::mem::size_of::<dns::ResourceRecord>(),
        optional(before.map(|v| v.0)),
        optional(after.map(|v| v.0)),
        optional(after.map(|v| v.1))
    );
    black_box(objects);
}

pub(super) fn run(kind: &str) {
    let count = std::env::var("AUTHORITY_BENCH_MEMORY_COUNT")
        .map(|s| s.parse::<usize>().expect("positive object count"))
        .unwrap_or(if kind == "zones" { 200 } else { 100_000 });
    assert!(count > 0);
    let name = DomainName::from_dotted("m.wild.example.test.").unwrap();
    let query = Message::builder()
        .questions([Question {
            qname: name.clone(),
            qtype: QueryType::TXT,
            qclass: QClassType::Class(dns::ClassType::IN),
        }])
        .additionals([Edns::new(1232).into_record()])
        .build()
        .unwrap();
    let wire = query.into_wire().unwrap();
    match kind {
        "wire" => sample(kind, count, || {
            (0..count)
                .map(|_| Message::from_wire(&wire).unwrap())
                .collect::<Vec<_>>()
        }),
        "aliases" => sample(kind, count, || vec![name; count]),
        "messages" => sample(kind, count, || vec![query; count]),
        "zones" => {
            let apex = DomainName::from_dotted("example.test.").unwrap();
            let parsed = MasterFile::parse(
                include_str!(
                    "../../../../../crates/nameserver/src/zone/tests/fixtures/bind-nsec3.zone"
                ),
                Some(apex.clone()),
            )
            .unwrap();
            sample(kind, count, || {
                (0..count)
                    .map(|_| {
                        Zone::from_master(
                            apex.clone(),
                            MasterFile {
                                records: parsed.records.clone(),
                            },
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>()
            });
        }
        _ => panic!("unknown memory probe mode"),
    }
}
