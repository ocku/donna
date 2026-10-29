//! RRSIG records follow their covered data, not an owner-wide RRSIG RRset.
use super::super::rrset_comparison::{rrsets_conflict, rrsets_overlap};
use super::*;
use std::net::Ipv6Addr;

const LIMIT: Duration = Duration::from_secs(300);

fn request(kind: QueryType) -> Message {
    let mut message = question(0x5353);
    message.questions[0].qtype = kind;
    message
}

fn signature(covered: u16, algorithm: u8, key_tag: u16) -> ResourceRecord {
    ResourceRecord {
        name: request(QueryType::A).questions[0].qname.clone(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: covered,
            algorithm,
            labels: 2,
            original_ttl: 60,
            signature_expiration: 2_000_000_000,
            signature_inception: 1_600_000_000,
            key_tag,
            signer_name: DomainName::from_dotted("example.").unwrap(),
            // Deliberately not cryptographic evidence: these tests exercise
            // cache coherence without asserting authenticated rank.
            signature: vec![algorithm; 8],
        }),
    }
}

fn reply(kind: QueryType, members: usize) -> Message {
    let mut message = request(kind);
    message.headers.qr = true;
    message.headers.aa = true;
    for index in 0..members {
        let (rtype, rdata) = match kind {
            QueryType::A => (
                RecordType::A,
                RData::A(Ipv4Addr::from(0xc0000200 + index as u32)),
            ),
            QueryType::AAAA => (
                RecordType::AAAA,
                RData::AAAA(Ipv6Addr::from(
                    0x20010db8000000000000000000000000 + index as u128,
                )),
            ),
            QueryType::TXT => (
                RecordType::TXT,
                RData::TXT(vec![format!("member-{index}").into_bytes()]),
            ),
            _ => unreachable!(),
        };
        message.answers.push(ResourceRecord {
            name: message.questions[0].qname.clone(),
            rtype,
            class: ClassType::IN,
            ttl: 60,
            rdata,
        });
    }
    message.answers.extend([
        signature(kind.value(), 8, 10),
        signature(kind.value(), 13, 20),
    ]);
    message
}

#[test]
fn signed_address_and_text_families_coexist_with_independent_authority_rank() {
    for members in [1, 12] {
        for later_authoritative in [false, true] {
            let cache = PositiveCache::new(16);
            for (index, kind) in [QueryType::A, QueryType::AAAA, QueryType::TXT]
                .into_iter()
                .enumerate()
            {
                let mut answer = reply(kind, members);
                if index > 0 {
                    answer.headers.aa = later_authoritative;
                    for rr in &mut answer.answers {
                        rr.name = DomainName::from_dotted("www.EXAMPLE.").unwrap();
                    }
                }
                assert!(
                    cache.insert(&request(kind), &answer, LIMIT),
                    "independent {kind:?} unexpectedly rejected"
                );
            }
            for kind in [QueryType::A, QueryType::AAAA, QueryType::TXT] {
                let cached = cache
                    .get(&request(kind))
                    .expect("all three covered families coexist");
                assert_eq!(cached.answers.len(), members + 2);
                assert!(!cached.headers.ad, "coherence is not authentication");
                assert_eq!(
                    cached
                        .answers
                        .iter()
                        .filter_map(|rr| match &rr.rdata {
                            RData::RRSIG(sig) => Some(sig.type_covered),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    [kind.value(), kind.value()]
                );
            }
        }
    }
}

#[test]
fn same_covered_type_keeps_all_algorithms_and_keys_in_one_comparison_family() {
    for covered in [1, 16, 28, 65_000] {
        let first = signature(covered, 8, 10);
        for (algorithm, tag) in [(8, 11), (13, 10), (15, 12)] {
            let second = signature(covered, algorithm, tag);
            assert!(rrsets_overlap(
                std::slice::from_ref(&first),
                std::slice::from_ref(&second)
            ));
            assert!(rrsets_conflict(
                std::slice::from_ref(&first),
                std::slice::from_ref(&second)
            ));
        }
        let other = signature(covered ^ 0x8000, 8, 10);
        assert!(!rrsets_overlap(
            std::slice::from_ref(&first),
            std::slice::from_ref(&other)
        ));
        assert!(!rrsets_conflict(
            std::slice::from_ref(&first),
            std::slice::from_ref(&other)
        ));
        let original: Vec<_> = (0..12)
            .map(|index| signature(covered, 8, 100 + index))
            .collect();
        let mut repeated = original.clone();
        let mut changed = repeated.clone();
        changed[11] = signature(covered, 13, 20);
        assert!(
            rrsets_conflict(&repeated, &changed),
            "indexed path must compare same-cover signature members"
        );
        repeated.iter_mut().for_each(|rr| rr.ttl = 1);
        assert!(
            !rrsets_conflict(&original, &repeated),
            "outer TTL is not signature identity"
        );
    }
}

#[test]
fn changed_covered_signatures_invalidate_aggregate_but_keep_other_types() {
    for members in [1, 12] {
        for change in 0..3 {
            let cache = PositiveCache::new(16);
            let mut any_request = request(QueryType::ANY);
            any_request.headers.id = 0x5353;
            let mut aggregate = any_request.clone();
            aggregate.headers.qr = true;
            aggregate.headers.aa = true;
            for kind in [QueryType::A, QueryType::AAAA, QueryType::TXT] {
                aggregate.answers.extend(reply(kind, members).answers);
            }
            assert!(cache.insert(&any_request, &aggregate, LIMIT));
            for kind in [QueryType::A, QueryType::AAAA, QueryType::TXT] {
                assert!(cache.insert(&request(kind), &reply(kind, members), LIMIT));
            }
            assert!(
                cache.get(&any_request).is_some(),
                "identical covered signatures preserve aggregate"
            );
            let mut replacement = reply(QueryType::A, members);
            match change {
                0 => {
                    let RData::RRSIG(sig) = &mut replacement.answers[members].rdata else {
                        unreachable!()
                    };
                    sig.signature[0] ^= 1;
                }
                1 => {
                    replacement.answers.pop();
                }
                2 => replacement
                    .answers
                    .push(signature(QueryType::A.value(), 15, 30)),
                _ => unreachable!(),
            }
            assert!(cache.insert(&request(QueryType::A), &replacement, LIMIT));
            assert!(
                cache.get(&any_request).is_none(),
                "changed covered signature family must invalidate aggregate"
            );
            assert_eq!(
                cache.get(&request(QueryType::A)).unwrap().answers.len(),
                replacement.answers.len()
            );
            for other in [QueryType::AAAA, QueryType::TXT] {
                assert!(
                    cache.get(&request(other)).is_some(),
                    "unrelated covered type evicted"
                );
            }
        }
    }
}

#[test]
fn covered_signature_grouping_does_not_relax_cname_exclusivity_or_source_rank() {
    let cache = PositiveCache::new(16);
    let a = request(QueryType::A);
    assert!(cache.insert(&a, &reply(QueryType::A, 1), LIMIT));
    let cname = request(QueryType::CNAME);
    let mut alias = cname.clone();
    alias.headers.qr = true;
    alias.answers.extend([
        ResourceRecord {
            name: cname.questions[0].qname.clone(),
            rtype: RecordType::CNAME,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::CNAME(DomainName::from_dotted("target.example.").unwrap()),
        },
        signature(QueryType::CNAME.value(), 13, 20),
    ]);
    assert!(
        !cache.insert(&cname, &alias, LIMIT),
        "lower-rank CNAME must not replace authoritative A"
    );
    assert!(cache.get(&a).is_some());
    alias.headers.aa = true;
    assert!(cache.insert(&cname, &alias, LIMIT));
    assert!(
        cache.get(&a).is_none(),
        "CNAME still excludes ordinary same-owner data"
    );
    assert!(cache.get(&cname).is_some());
}
