use super::*;

const MEMBERS: usize = 512;
const LIMIT: Duration = Duration::from_secs(300);

fn request(qtype: QueryType) -> Message {
    let mut request = question(1);
    request.questions[0].qtype = qtype;
    request
}

fn addresses(request: &Message, ttl: u32) -> Message {
    let mut reply = request.clone();
    reply.headers.qr = true;
    reply.headers.aa = true;
    reply.answers = (0..MEMBERS)
        .map(|index| ResourceRecord {
            name: request.questions[0].qname.clone(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl,
            rdata: RData::A(Ipv4Addr::from(0xc0000200 + index as u32)),
        })
        .collect();
    reply
}

fn text(request: &Message) -> ResourceRecord {
    ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::TXT,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::TXT(vec![b"independent RRset".to_vec()]),
    }
}

#[test]
fn identical_large_rrsets_coexist_across_aggregate_keys_order_case_and_ttl() {
    let cache = PositiveCache::new(16);
    let a = request(QueryType::A);
    let any = request(QueryType::ANY);
    assert!(cache.insert(&a, &addresses(&a, 60), LIMIT));
    let mut aggregate = addresses(&any, 30);
    aggregate.answers.reverse();
    for record in &mut aggregate.answers {
        record.name = DomainName::from_dotted("www.EXAMPLE.").unwrap();
    }
    aggregate.answers.push(text(&any));
    assert!(cache.insert(&any, &aggregate, LIMIT));
    assert_eq!(cache.get(&a).unwrap().answers.len(), MEMBERS);
    assert_eq!(cache.get(&any).unwrap().answers.len(), MEMBERS + 1);
}

#[test]
fn actual_large_rrset_changes_invalidate_aggregate_but_keep_unrelated_types() {
    for change in 0..3 {
        let cache = PositiveCache::new(16);
        let a = request(QueryType::A);
        let any = request(QueryType::ANY);
        let txt = request(QueryType::TXT);
        let mut aggregate = addresses(&any, 60);
        aggregate.answers.push(text(&any));
        assert!(cache.insert(&any, &aggregate, LIMIT));
        let mut txt_reply = txt.clone();
        txt_reply.headers.qr = true;
        txt_reply.headers.aa = true;
        txt_reply.answers.push(text(&txt));
        assert!(cache.insert(&txt, &txt_reply, LIMIT));
        let mut replacement = addresses(&a, 60);
        match change {
            0 => {
                replacement.answers.pop();
            }
            1 => replacement.answers.push(ResourceRecord {
                rdata: RData::A(Ipv4Addr::from(0xc0010000)),
                ..replacement.answers[0].clone()
            }),
            2 => replacement.answers[MEMBERS - 1].rdata = RData::A(Ipv4Addr::from(0xc0010000)),
            _ => unreachable!(),
        }
        assert!(cache.insert(&a, &replacement, LIMIT));
        assert!(
            cache.get(&any).is_none(),
            "changed aggregate survived case {change}"
        );
        assert_eq!(
            cache.get(&a).unwrap().answers.len(),
            replacement.answers.len()
        );
        assert_eq!(cache.get(&txt).unwrap().answers.len(), 1);
    }
}

#[test]
fn lower_trust_large_projection_cannot_replace_authoritative_aggregate() {
    let cache = PositiveCache::new(16);
    let a = request(QueryType::A);
    let any = request(QueryType::ANY);
    assert!(cache.insert(&any, &addresses(&any, 60), LIMIT));
    let mut untrusted = addresses(&a, 60);
    untrusted.headers.aa = false;
    untrusted.answers[MEMBERS - 1].rdata = RData::A(Ipv4Addr::from(0xc0010000));
    assert!(!cache.insert(&a, &untrusted, LIMIT));
    assert!(cache.get(&a).is_none());
    assert_eq!(cache.get(&any).unwrap().answers.len(), MEMBERS);
}

#[test]
fn same_owner_large_different_class_data_does_not_overlap_or_invalidate() {
    let cache = PositiveCache::new(16);
    let any = request(QueryType::ANY);
    assert!(cache.insert(&any, &addresses(&any, 60), LIMIT));
    let mut chaos = request(QueryType::A);
    chaos.questions[0].qclass = QClassType::Class(ClassType::CH);
    let mut reply = addresses(&chaos, 60);
    reply.headers.aa = false;
    for (index, record) in reply.answers.iter_mut().enumerate() {
        record.class = ClassType::CH;
        // A's standardized four-octet schema is IN-specific; other classes
        // retain their data opaquely rather than inheriting IN semantics.
        record.rdata = RData::Unknown((index as u32).to_be_bytes().to_vec());
    }
    assert!(cache.insert(&chaos, &reply, LIMIT));
    assert_eq!(cache.get(&any).unwrap().answers.len(), MEMBERS);
    assert_eq!(cache.get(&chaos).unwrap().answers.len(), MEMBERS);
}

#[test]
fn large_embedded_dns_name_members_compare_case_insensitively() {
    let cache = PositiveCache::new(16);
    let ns = request(QueryType::NS);
    let any = request(QueryType::ANY);
    let make = |request: &Message, upper: bool| {
        let mut reply = request.clone();
        reply.headers.qr = true;
        reply.headers.aa = true;
        reply.answers = (0..128)
            .map(|index| ResourceRecord {
                name: request.questions[0].qname.clone(),
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: if upper { 30 } else { 60 },
                rdata: RData::NS(
                    DomainName::from_dotted(&if upper {
                        format!("NS{index}.EXAMPLE.")
                    } else {
                        format!("ns{index}.example.")
                    })
                    .unwrap(),
                ),
            })
            .collect();
        reply
    };
    assert!(cache.insert(&ns, &make(&ns, false), LIMIT));
    let mut aggregate = make(&any, true);
    aggregate.answers.reverse();
    assert!(cache.insert(&any, &aggregate, LIMIT));
    assert!(cache.get(&ns).is_some());
    assert!(cache.get(&any).is_some());
}

fn signature(request: &Message, ttl: u32, value: u8) -> ResourceRecord {
    ResourceRecord {
        name: request.questions[0].qname.clone(),
        rtype: RecordType::RRSIG,
        class: ClassType::IN,
        ttl,
        rdata: RData::RRSIG(dns::Rrsig {
            type_covered: RecordType::A.into(),
            algorithm: 15,
            labels: 2,
            original_ttl: 60,
            signature_expiration: 2,
            signature_inception: 1,
            key_tag: 1,
            signer_name: DomainName::from_dotted("example.").unwrap(),
            signature: vec![value],
        }),
    }
}

#[test]
fn large_signature_members_exclude_outer_ttl_but_retain_signature_identity() {
    let cache = PositiveCache::new(16);
    let a = request(QueryType::A);
    let any = request(QueryType::ANY);
    let mut aggregate = addresses(&any, 60);
    aggregate.answers.push(signature(&any, 60, 1));
    assert!(cache.insert(&any, &aggregate, LIMIT));
    let mut projection = addresses(&a, 60);
    projection.answers.push(signature(&a, 30, 1));
    assert!(cache.insert(&a, &projection, LIMIT));
    assert!(cache.get(&any).is_some());
    projection.answers[MEMBERS] = signature(&a, 30, 2);
    assert!(cache.insert(&a, &projection, LIMIT));
    assert!(cache.get(&any).is_none());
}
