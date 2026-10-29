mod index;

use std::thread;

use dns::{QueryType, RecordType};

use super::*;

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn question(qtype: QueryType) -> Question {
    Question {
        qname: name(&["Missing", "example"]),
        qtype,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn negative(rcode: RCode, soa_ttl: u32, minimum: u32) -> Message {
    Message {
        headers: Headers {
            qr: true,
            aa: true,
            rcode,
            ..Headers::default()
        },
        questions: vec![question(QueryType::A)],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::SOA,
            class: ClassType::IN,
            ttl: soa_ttl,
            rdata: RData::SOA {
                mname: name(&["ns", "example"]),
                rname: name(&["hostmaster", "example"]),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum,
            },
        }],
        additionals: Vec::new(),
    }
}

fn nsec_record(owner: DomainName, next: DomainName, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype: RecordType::NSEC,
        class: ClassType::IN,
        ttl,
        rdata: RData::NSEC(dns::Nsec {
            next_domain_name: next,
            type_bitmap: dns::TypeBitmap::new([1, 46, 47]).unwrap(),
        }),
    }
}

fn nsec3_record(owner: DomainName, ttl: u32) -> ResourceRecord {
    ResourceRecord {
        name: owner,
        rtype: RecordType::NSEC3,
        class: ClassType::IN,
        ttl,
        rdata: RData::NSEC3(dns::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
            next_hashed_owner_name: vec![0; 20],
            type_bitmap: Some(dns::TypeBitmap::new([6, 46, 50]).unwrap()),
        }),
    }
}

fn rrsig_record(
    owner: DomainName,
    type_covered: RecordType,
    ttl: u32,
    signature: u8,
) -> ResourceRecord {
    let labels = owner.as_ref().len() as u8;
    ResourceRecord {
        name: owner,
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: u16::from(type_covered),
            algorithm: 15,
            labels,
            original_ttl: ttl,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: name(&["example"]),
            signature: vec![signature],
        }),
    }
}

#[test]
fn nxdomain_matches_name_and_class_across_query_types() {
    let cache = NegativeCache::new(2);
    cache.insert(
        &question(QueryType::A),
        &negative(RCode::NameError, 60, 30),
        true,
        Duration::from_secs(60),
    );

    let hit = cache.get(&question(QueryType::TXT)).unwrap();
    assert_eq!(hit.headers.rcode, RCode::NameError);
    assert_eq!(hit.questions[0].qtype, QueryType::TXT);
    assert_eq!(hit.authorities.len(), 1);
    assert!(hit.authorities[0].ttl <= 30);
}

#[test]
fn nodata_is_specific_to_name_type_and_class() {
    let cache = NegativeCache::new(2);
    cache.insert(
        &question(QueryType::A),
        &negative(RCode::Ok, 60, 30),
        true,
        Duration::from_secs(60),
    );

    assert!(cache.get(&question(QueryType::A)).is_some());
    assert!(cache.get(&question(QueryType::TXT)).is_none());
}

#[test]
fn retains_a_type_one_negative_response_implicit_referral() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::Ok, 60, 30);
    let zone = name(&["example"]);
    let name_server = name(&["ns", "example"]);
    reply.authorities.push(ResourceRecord {
        name: zone.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 20,
        rdata: RData::NS(name_server.clone()),
    });

    assert!(cache.insert(&query, &reply, true, Duration::from_secs(60)));
    let cached = cache.get(&query).unwrap();

    assert!(cached.authorities.iter().any(|record| {
        record.name.eq_dns(&zone)
            && record.rtype == RecordType::NS
            && record.ttl <= 20
            && matches!(&record.rdata, RData::NS(target) if target.eq_dns(&name_server))
    }));
}

#[test]
fn requires_a_usable_soa_and_expires_at_the_configured_limit() {
    let cache = NegativeCache::new(2);
    let query = question(QueryType::A);
    let mut without_soa = negative(RCode::NameError, 60, 30);
    without_soa.authorities.clear();
    cache.insert(&query, &without_soa, true, Duration::from_secs(60));
    cache.insert(
        &query,
        &negative(RCode::NameError, 0x8000_0001, 30),
        true,
        Duration::from_secs(60),
    );
    assert!(cache.get(&query).is_none());

    cache.insert(
        &query,
        &negative(RCode::NameError, 60, 30),
        true,
        Duration::from_millis(10),
    );
    assert!(cache.get(&query).is_some());
    thread::sleep(Duration::from_millis(20));
    assert!(cache.get(&query).is_none());
}

#[test]
fn ignores_an_soa_outside_the_negative_names_zone() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    reply.authorities[0].name = name(&["other"]);

    cache.insert(&query, &reply, true, Duration::from_secs(60));

    assert!(cache.get(&query).is_none());
}

#[test]
fn uses_the_closest_enclosing_soa_independent_of_authority_order() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    let mut closest = reply.authorities[0].clone();
    let RData::SOA {
        serial, minimum, ..
    } = &mut closest.rdata
    else {
        unreachable!("the helper creates an SOA")
    };
    *serial = 2;
    *minimum = 5;
    reply.authorities[0].name = DomainName::root();
    reply.authorities.push(closest);

    cache.insert(&query, &reply, true, Duration::from_secs(60));
    let hit = cache.get(&query).unwrap();

    assert_eq!(hit.authorities.len(), 1);
    assert!(hit.authorities[0].name.eq_dns(&name(&["example"])));
    assert!(matches!(
        hit.authorities[0].rdata,
        RData::SOA { serial: 2, .. }
    ));
    assert!(hit.authorities[0].ttl <= 5);
}

#[test]
fn retains_negative_proofs_with_individual_bounded_ttls() {
    let cache = NegativeCache::new(2);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    let proof_name = name(&["proof", "example"]);
    reply.authorities.extend([
        ResourceRecord {
            name: proof_name.clone(),
            rtype: RecordType::Unknown(30),
            class: ClassType::IN,
            ttl: 5,
            rdata: RData::Unknown(vec![1]),
        },
        ResourceRecord {
            name: proof_name,
            rtype: RecordType::SIG,
            class: ClassType::IN,
            ttl: 20,
            rdata: RData::SIG(dns::Sig {
                type_covered: 30,
                algorithm: 1,
                labels: 2,
                original_ttl: 20,
                signature_expiration: 2,
                signature_inception: 1,
                key_tag: 1,
                signer_name: DomainName::root(),
                signature: vec![2],
            }),
        },
        nsec_record(name(&["other"]), DomainName::root(), 20),
        rrsig_record(name(&["example"]), RecordType::SOA, 40, 4),
    ]);

    cache.insert(&query, &reply, true, Duration::from_secs(60));
    let hit = cache.get(&query).unwrap();

    assert_eq!(hit.authorities.len(), 4);
    assert_eq!(
        hit.authorities
            .iter()
            .map(|record| u16::from(record.rtype))
            .collect::<Vec<_>>(),
        [6, 30, 24, 46]
    );
    assert!(hit.authorities[1].ttl <= 5);
    assert!(hit.authorities[2].ttl <= 20);
    assert!(hit.authorities[3].name.eq_dns(&name(&["example"])));
    assert!(hit.authorities.iter().all(|record| record.ttl <= 30));
}

#[test]
fn nodata_retains_all_in_zone_proofs() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::Ok, 60, 30);
    reply.authorities.extend([
        nsec_record(query.qname.clone(), name(&["next", "example"]), 20),
        rrsig_record(query.qname.clone(), RecordType::NSEC, 10, 2),
        nsec_record(
            name(&["other", "example"]),
            name(&["next-other", "example"]),
            20,
        ),
    ]);

    cache.insert(&query, &reply, true, Duration::from_secs(60));
    let hit = cache.get(&query).unwrap();

    assert_eq!(hit.authorities.len(), 4);
    assert_eq!(u16::from(hit.authorities[1].rtype), 47);
    assert!(hit.authorities[1].name.eq_dns(&query.qname));
    assert_eq!(u16::from(hit.authorities[3].rtype), 46);
    assert!(hit.authorities[3].name.eq_dns(&query.qname));
    assert!(hit.authorities[3].ttl <= 10);
}

#[test]
fn nodata_retains_nsec3_proofs_at_hashed_owner_names() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::Ok, 60, 30);
    let proof_name = name(&["0123456789abcdefghijklmnopqrstuv", "example"]);
    reply.authorities.extend([
        nsec3_record(proof_name.clone(), 20),
        rrsig_record(proof_name.clone(), RecordType::NSEC3, 10, 2),
    ]);

    assert!(cache.insert(&query, &reply, true, Duration::from_secs(60)));
    let hit = cache.get(&query).unwrap();

    assert_eq!(hit.authorities.len(), 3);
    assert!(
        hit.authorities
            .iter()
            .any(|record| { record.rtype == RecordType::NSEC3 && record.name.eq_dns(&proof_name) })
    );
    assert!(hit.authorities.iter().any(|record| {
        record.rtype == RecordType::RRSIG
            && record.name.eq_dns(&proof_name)
            && matches!(&record.rdata, RData::RRSIG(rrsig)
                if rrsig.type_covered == u16::from(RecordType::NSEC3))
    }));
}

#[test]
fn negative_cache_excludes_colocated_signatures_covering_unrelated_types() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    let proof_name = name(&["proof", "example"]);
    reply.authorities.extend([
        nsec_record(proof_name.clone(), name(&["next", "example"]), 20),
        rrsig_record(name(&["example"]), RecordType::A, 20, 2),
        rrsig_record(proof_name, RecordType::A, 20, 3),
    ]);

    assert!(cache.insert(&query, &reply, true, Duration::from_secs(60)));
    let hit = cache.get(&query).unwrap();

    assert_eq!(hit.authorities.len(), 2);
    assert_eq!(hit.authorities[0].rtype, RecordType::SOA);
    assert_eq!(u16::from(hit.authorities[1].rtype), 47);
}

#[test]
fn non_authoritative_negatives_are_never_cached() {
    for rcode in [RCode::NameError, RCode::Ok] {
        let cache = NegativeCache::new(1);
        let query = question(QueryType::A);
        let mut reply = negative(rcode, 60, 30);
        reply.headers.aa = false;

        assert!(!cache.insert(&query, &reply, false, Duration::from_secs(60)));
        assert!(cache.get(&query).is_none());
    }
}

#[test]
fn raw_aa_does_not_override_missing_effective_authority() {
    for rcode in [RCode::NameError, RCode::Ok] {
        let cache = NegativeCache::new(1);
        let query = question(QueryType::A);
        let reply = negative(rcode, 60, 30);

        assert!(!cache.insert(&query, &reply, false, Duration::from_secs(60)));
        assert!(cache.get(&query).is_none());
    }
}

#[test]
fn non_authoritative_negative_does_not_replace_authoritative_entry() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let authoritative = negative(RCode::NameError, 60, 30);
    cache.insert(&query, &authoritative, true, Duration::from_secs(60));

    let mut non_authoritative = negative(RCode::NameError, 60, 30);
    non_authoritative.headers.aa = false;
    let RData::SOA { serial, .. } = &mut non_authoritative.authorities[0].rdata else {
        unreachable!("the helper creates an SOA")
    };
    *serial = 2;
    cache.insert(&query, &non_authoritative, false, Duration::from_secs(60));

    let hit = cache.get(&query).unwrap();
    assert!(matches!(
        hit.authorities[0].rdata,
        RData::SOA { serial: 1, .. }
    ));
}

#[test]
fn cached_response_rebuilds_question_and_decrements_the_soa_ttl() {
    let cache = NegativeCache::new(1);
    let mut query = question(QueryType::A);
    let reply = negative(RCode::NameError, 60, 30);
    cache.insert(&query, &reply, true, Duration::from_secs(60));
    query.qname = name(&["missing", "EXAMPLE"]);

    let hit = cache.get(&query).unwrap();

    assert!(!hit.headers.aa);
    assert!(hit.questions[0].qname.eq_dns(&query.qname));
    assert_eq!(hit.authorities[0].rtype, RecordType::SOA);
    assert!(hit.authorities[0].ttl <= 30);
    assert_eq!(hit.authorities[0].class, ClassType::IN);
    assert!(matches!(hit.authorities[0].rdata, RData::SOA { .. }));
}

#[test]
fn truncated_negative_answers_are_never_cached() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::A);
    let mut reply = negative(RCode::NameError, 60, 30);
    reply.headers.tc = true;

    assert!(!cache.insert(&query, &reply, true, Duration::from_secs(60)));
    assert!(cache.get(&query).is_none());
}

#[test]
fn authenticated_wildcard_nodata_keeps_complete_proofs_until_entry_expiry() {
    let cache = NegativeCache::new(1);
    let query = question(QueryType::AAAA);
    let mut reply = negative(RCode::Ok, 60, 60);
    reply.headers.ad = true;
    let wildcard = name(&["*", "example"]);
    let cover = name(&["a", "example"]);
    reply.authorities.extend([
        nsec_record(wildcard.clone(), cover.clone(), 30),
        nsec_record(cover.clone(), name(&["z", "example"]), 20),
        rrsig_record(wildcard.clone(), RecordType::NSEC, 15, 2),
        rrsig_record(cover.clone(), RecordType::NSEC, 7, 3),
    ]);
    assert!(cache.insert(&query, &reply, true, Duration::from_secs(60)));
    let hit = cache.get(&query).unwrap();
    assert!(hit.headers.ad);
    assert_eq!(hit.authorities.len(), 5);
    for owner in [&wildcard, &cover] {
        assert!(
            hit.authorities
                .iter()
                .any(|rr| rr.name.eq_dns(owner) && rr.rtype == RecordType::NSEC)
        );
        assert!(
            hit.authorities
                .iter()
                .any(|rr| rr.name.eq_dns(owner) && rr.rtype == RecordType::RRSIG)
        );
    }
    assert!(hit.authorities.iter().all(|rr| rr.ttl <= 7));
    {
        let mut entries = cache.entries.lock().unwrap();
        let entry = entries.values.first().unwrap();
        assert!(entry.expires_at <= Instant::now() + Duration::from_secs(7));
        assert!(
            entry
                .authorities
                .iter()
                .all(|rr| rr.expires_at >= entry.expires_at)
        );
        entries.modify(0, |entry| entry.expires_at = Instant::now());
    }
    assert!(cache.get(&query).is_none());
}

mod deadline_lock;
mod rendering;
