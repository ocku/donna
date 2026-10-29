//! Fixed-time DNSSEC component costs from a public signed master file.
//! Excludes chain acquisition, resolver composition, I/O and wall-clock sampling.
use std::{hint::black_box, path::PathBuf, sync::atomic::Ordering, time::Instant};

use dns::{
    ClassType, DnssecValidation, DomainName, RData, RecordType, ResourceRecord,
    authenticate_dnskey_with_anchor, master::MasterFile,
};
use donna_interop::Failure;

#[path = "validating_cache_bench/allocator.rs"]
mod allocator;

fn secure<T: std::fmt::Debug>(result: DnssecValidation<T>) -> T {
    match result {
        DnssecValidation::Secure(value) => value,
        other => panic!("fixture must authenticate: {other:?}"),
    }
}

struct Rrset {
    records: Vec<ResourceRecord>,
    signatures: Vec<ResourceRecord>,
}

fn rrsets(records: &[ResourceRecord], rtype: RecordType) -> Vec<Rrset> {
    let mut result: Vec<Rrset> = Vec::new();
    for record in records.iter().filter(|record| record.rtype == rtype) {
        if let Some(existing) = result
            .iter_mut()
            .find(|set| set.records[0].name.eq_dns(&record.name))
        {
            existing.records.push(record.clone());
        } else {
            result.push(Rrset {
                records: vec![record.clone()],
                signatures: records
                    .iter()
                    .filter(|candidate| {
                        candidate.name.eq_dns(&record.name)
                            && candidate.class == record.class
                            && matches!(&candidate.rdata, RData::RRSIG(signature)
                                if signature.type_covered == u16::from(rtype))
                    })
                    .cloned()
                    .collect(),
            });
        }
    }
    assert!(!result.is_empty(), "fixture lacks {rtype:?}");
    result
}

fn measure(workload: &str, phase: &str, iterations: usize, mut operation: impl FnMut()) {
    for _ in 0..100 {
        operation();
    }
    for repeat in 0..5 {
        allocator::ALLOCATIONS.store(0, Ordering::Relaxed);
        allocator::BYTES.store(0, Ordering::Relaxed);
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let elapsed = start.elapsed().as_nanos();
        let allocations = allocator::ALLOCATIONS.load(Ordering::Relaxed) as f64 / iterations as f64;
        let bytes = allocator::BYTES.load(Ordering::Relaxed) as f64 / iterations as f64;
        println!(
            "{workload},{phase},{repeat},{},{allocations:.2},{bytes:.2}",
            elapsed / iterations as u128
        );
    }
}

fn main() -> Result<(), Failure> {
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("expected signed master file")?,
    );
    let zone = DomainName::from_dotted(&std::env::args().nth(2).ok_or("expected zone apex")?)?;
    let iterations: usize = std::env::var("RRSET_BENCH_ITERATIONS")
        .map(|text| text.parse())
        .unwrap_or(Ok(10_000))?;
    assert!(iterations > 0);
    let master = MasterFile::parse(&std::fs::read_to_string(path)?, Some(zone.clone()))?;
    let key_sets = rrsets(&master.records, RecordType::DNSKEY);
    let dnskeys = &key_sets[0];
    let anchor = dnskeys
        .records
        .iter()
        .find_map(|record| match &record.rdata {
            RData::DNSKEY(key) if key.flags & 1 != 0 => Some(key),
            _ => None,
        })
        .ok_or("missing KSK")?;
    let now = match &dnskeys.signatures[0].rdata {
        RData::RRSIG(signature) => signature.signature_inception.wrapping_add(60),
        _ => unreachable!(),
    };
    let keys = secure(authenticate_dnskey_with_anchor(
        &zone,
        ClassType::IN,
        &dnskeys.records,
        &dnskeys.signatures,
        anchor,
        now,
    ));
    let dnames = rrsets(&master.records, RecordType::DNAME);
    let targets: Vec<_> = rrsets(&master.records, RecordType::A)
        .into_iter()
        .filter(|set| {
            set.records[0].name.as_ref().first().is_some_and(|label| {
                label.len() == 5 && label[0] == b'p' && label[1..].iter().all(u8::is_ascii_digit)
            })
        })
        .collect();
    assert!(!targets.is_empty(), "expected pNNNN target A owners");
    eprintln!(
        "fixed_validation_time={now} dnames={} targets={} iterations={iterations}",
        dnames.len(),
        targets.len()
    );
    for set in dnames.iter().chain(&targets) {
        secure(keys.validate_rrset(&set.records, &set.signatures, now));
        let mut forged = set.records.clone();
        forged[0].rdata = match forged[0].rtype {
            RecordType::A => RData::A("192.0.2.254".parse()?),
            RecordType::DNAME => RData::DNAME(DomainName::from_dotted("forged.invalid.")?),
            _ => unreachable!(),
        };
        assert!(!matches!(
            keys.validate_rrset(&forged, &set.signatures, now),
            DnssecValidation::Secure(_)
        ));
        let mut bad_signatures = set.signatures.clone();
        for record in &mut bad_signatures {
            let RData::RRSIG(signature) = &mut record.rdata else {
                unreachable!()
            };
            signature.signature[0] ^= 1;
        }
        assert!(!matches!(
            keys.validate_rrset(&set.records, &bad_signatures, now),
            DnssecValidation::Secure(_)
        ));
        let expiry = match &set.signatures[0].rdata {
            RData::RRSIG(signature) => signature.signature_expiration.wrapping_add(1),
            _ => unreachable!(),
        };
        assert!(!matches!(
            keys.validate_rrset(&set.records, &set.signatures, expiry),
            DnssecValidation::Secure(_)
        ));
    }
    println!("workload,phase,repeat,ns,allocations,allocated_bytes");
    for (workload, sets) in [("dname", &dnames), ("target_a", &targets)] {
        for phase in [
            "canonical_data",
            "validate_repeated",
            "validate_round_robin",
        ] {
            let mut index = 0;
            measure(workload, phase, iterations, || {
                let set = &sets[index];
                match phase {
                    "canonical_data" => {
                        let RData::RRSIG(signature) = &set.signatures[0].rdata else {
                            unreachable!()
                        };
                        black_box(signature.signed_data(black_box(&set.records)).unwrap());
                    }
                    _ => {
                        black_box(secure(keys.validate_rrset(
                            black_box(&set.records),
                            black_box(&set.signatures),
                            now,
                        )));
                    }
                }
                index = if phase == "validate_repeated" {
                    0
                } else {
                    (index + 1) % sets.len()
                };
            });
        }
    }
    let mut index = 0;
    measure(
        "dname_and_target",
        "validate_round_robin",
        iterations,
        || {
            for set in [&dnames[index % dnames.len()], &targets[index]] {
                black_box(secure(keys.validate_rrset(
                    black_box(&set.records),
                    black_box(&set.signatures),
                    now,
                )));
            }
            index = (index + 1) % targets.len();
        },
    );
    Ok(())
}
