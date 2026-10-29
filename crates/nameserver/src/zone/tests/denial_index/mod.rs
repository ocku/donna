use super::*;
use dns::{IntoWire, Nsec3Chain, Nsec3param};

fn signature(owner: DomainName, covered: RecordType) -> ResourceRecord {
    record(
        owner,
        RecordType::RRSIG,
        RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(covered),
            algorithm: 8,
            labels: 1,
            original_ttl: 60,
            signature_expiration: u32::MAX,
            signature_inception: 0,
            key_tag: 1,
            signer_name: name(&["example"]),
            signature: vec![1],
        }),
    )
}

pub(super) fn ring(opt_out: bool, iterations: u16, single: bool) -> Vec<ResourceRecord> {
    let apex = name(&["example"]);
    let mut source = vec![
        soa(),
        record(
            apex.clone(),
            RecordType::NS,
            RData::NS(name(&["ns", "external"])),
        ),
    ];
    if !single {
        source.extend([
            record(
                name(&["www", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            ),
            record(
                name(&["*", "wild", "example"]),
                RecordType::TXT,
                RData::TXT(vec![b"wild".to_vec()]),
            ),
            record(
                name(&["child", "example"]),
                RecordType::NS,
                RData::NS(name(&["ns", "child", "example"])),
            ),
            record(
                name(&["ns", "child", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            ),
            record(
                name(&["redirect", "example"]),
                RecordType::DNAME,
                RData::DNAME(DomainName::root()),
            ),
            record(
                name(&["leaf", "empty", "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            ),
        ]);
        for i in 0..32 {
            source.push(record(
                name(&[&format!("owner-{i}"), "example"]),
                RecordType::A,
                RData::A(Ipv4Addr::LOCALHOST),
            ));
        }
    }
    let chain = Nsec3Chain::build(
        &apex,
        ClassType::IN,
        &source,
        Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations,
            salt: if iterations == 0 {
                vec![]
            } else {
                vec![0xa1, 0xb2]
            },
        },
        60,
        opt_out,
        iterations,
    )
    .unwrap();
    let (parameters, mut denials) = chain.into_records();
    // Deliberately differ from hash order and interleave unrelated records.
    denials.reverse();
    source.push(parameters);
    source.push(signature(apex.clone(), RecordType::SOA));
    source.push(record(
        apex.clone(),
        RecordType::SIG,
        RData::SIG(dns::Sig {
            type_covered: 6,
            algorithm: 8,
            labels: 1,
            original_ttl: 60,
            signature_expiration: u32::MAX,
            signature_inception: 0,
            key_tag: 1,
            signer_name: apex,
            signature: vec![2],
        }),
    ));
    for denial in denials {
        source.push(signature(denial.name.clone(), RecordType::NSEC3));
        source.push(denial);
    }
    source
}

fn encoded(records: &[ResourceRecord]) -> Vec<Result<Vec<u8>, String>> {
    records
        .iter()
        .map(|record| record.into_wire().map_err(|err| err.to_string()))
        .collect()
}

fn assert_equivalent(records: Vec<ResourceRecord>) {
    let indexed = zone(records.clone(), soa());
    let mut reference = zone(records, soa());
    reference.nsec3_index = None;
    reference.nsec_index = None;
    let mut names = vec![
        name(&["example"]),
        name(&["www", "example"]),
        name(&["missing", "example"]),
        name(&["child", "example"]),
        name(&["x", "child", "example"]),
        name(&["redirect", "example"]),
        name(&["x", "redirect", "example"]),
        name(&["empty", "example"]),
        name(&["x", "empty", "example"]),
        name(&["*", "wild", "example"]),
        name(&["m", "wild", "example"]),
        name(&["p", "q", "wild", "example"]),
        name(&["outside"]),
    ];
    for i in 0..32 {
        names.push(name(&[&format!("owner-{i}"), "example"]));
    }
    for owner in &names {
        for name_error in [false, true] {
            for dnssec_ok in [false, true] {
                let actual =
                    indexed.negative_response_authorities(owner, owner, name_error, dnssec_ok);
                let expected =
                    reference.negative_response_authorities(owner, owner, name_error, dnssec_ok);
                assert_eq!(
                    encoded(&actual),
                    encoded(&expected),
                    "owner={owner:?} nx={name_error} do={dnssec_ok}"
                );
            }
        }
    }
    for expanded in [
        name(&["m", "wild", "example"]),
        name(&["p", "q", "wild", "example"]),
    ] {
        let wildcard = name(&["*", "wild", "example"]);
        let actual = indexed.negative_response_authorities(&wildcard, &expanded, false, true);
        let expected = reference.negative_response_authorities(&wildcard, &expanded, false, true);
        assert_eq!(encoded(&actual), encoded(&expected));
        let mut answer = signature(expanded, RecordType::TXT);
        if let RData::RRSIG(sig) = &mut answer.rdata {
            sig.labels = 2;
        }
        let (mut actual, mut expected) = (vec![], vec![]);
        indexed.append_wildcard_denial(&[answer.clone()], &mut actual);
        reference.append_wildcard_denial(&[answer], &mut expected);
        assert_eq!(encoded(&actual), encoded(&expected));
    }
}

mod membership;
mod nsec3;
