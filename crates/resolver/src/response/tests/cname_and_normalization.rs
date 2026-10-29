use super::*;

#[test]
fn restarts_at_the_final_target_of_a_single_packet_cname_chain() {
    let query = question(&["www", "example"]);
    let first = name(&["origin", "example"]);
    let second = name(&["canonical", "example"]);
    let answers = vec![
        cname_record(query.qname.clone(), first.clone()),
        cname_record(first.clone(), second.clone()),
    ];

    let (chain, target) = cname_restart(&answers, &query).unwrap().unwrap();

    assert_eq!(chain.len(), 2);
    assert!(target.eq_dns(&second));
}

#[test]
fn rejects_a_cname_loop_within_one_response() {
    let query = question(&["www", "example"]);
    let other = name(&["other", "example"]);
    let answers = vec![
        cname_record(query.qname.clone(), other.clone()),
        cname_record(other, query.qname.clone()),
    ];

    assert!(matches!(
        cname_restart(&answers, &query),
        Err(CnameError::Loop)
    ));
}

#[test]
fn rejects_multiple_cname_targets_and_coexisting_data() {
    let query = question(&["www", "example"]);
    let first = name(&["first", "example"]);
    let second = name(&["second", "example"]);
    let multiple = vec![
        cname_record(query.qname.clone(), first),
        cname_record(query.qname.clone(), second),
    ];
    assert!(matches!(
        cname_restart(&multiple, &query),
        Err(CnameError::MultipleTargets)
    ));

    let coexisting = vec![
        cname_record(query.qname.clone(), name(&["target", "example"])),
        a_record(query.qname.clone(), 1),
    ];
    assert!(matches!(
        cname_restart(&coexisting, &query),
        Err(CnameError::CoexistingData)
    ));

    let signed = vec![
        cname_record(query.qname.clone(), name(&["target", "example"])),
        rrsig_record(query.qname.clone(), RecordType::CNAME, 1),
    ];
    let (chain, _) = cname_restart(&signed, &query).unwrap().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].rtype, RecordType::CNAME);
    assert_eq!(chain[1].rtype, RecordType::RRSIG);
    assert!(matches!(&chain[1].rdata, RData::RRSIG(rrsig) if rrsig.signature == [1]));
}

#[test]
fn never_restarts_a_query_that_cname_or_any_answers_directly() {
    let mut query = question(&["www", "example"]);
    let target = name(&["origin", "example"]);
    let answers = vec![cname_record(query.qname.clone(), target)];

    query.qtype = QueryType::CNAME;
    assert!(cname_restart(&answers, &query).unwrap().is_none());

    query.qtype = QueryType::ANY;
    assert!(cname_restart(&answers, &query).unwrap().is_none());
}

#[test]
fn normalizes_rrsets_without_merging_section_trust_levels() {
    let query = question(&["www", "example"]);
    let other = name(&["other", "example"]);
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![
            a_record(query.qname.clone(), 1),
            a_record(query.qname.clone(), 2),
        ],
        authorities: Vec::new(),
        additionals: vec![
            a_record(query.qname.clone(), 3),
            a_record(other.clone(), 4),
            a_record(other, 5),
        ],
    };
    reply.answers[0].ttl = 60;
    reply.answers[1].ttl = 45;
    reply.additionals[0].ttl = 1;
    reply.additionals[1].ttl = 30;
    reply.additionals[2].ttl = 20;

    assert!(normalize_response_rrsets(&mut reply, &query));
    assert!(reply.answers.iter().all(|record| record.ttl == 45));
    assert!(reply.additionals.is_empty());

    reply.headers.aa = false;
    reply.answers[0].ttl = 60;
    assert!(!normalize_response_rrsets(&mut reply, &query));

    let zone = name(&["example"]);
    let mut first_ns = record(
        zone.clone(),
        RecordType::NS,
        RData::NS(name(&["ns1", "example"])),
    );
    first_ns.ttl = 60;
    let mut second_ns = record(zone, RecordType::NS, RData::NS(name(&["ns2", "example"])));
    second_ns.ttl = 30;
    let mut unrelated = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 9)],
        authorities: vec![first_ns, second_ns],
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut unrelated, &query));
    assert_eq!(unrelated.answers.len(), 1);
    assert!(unrelated.authorities.is_empty());
}

#[test]
fn discards_malformed_external_cname_target_authority_from_an_aa_response() {
    let query = question(&["www", "example"]);
    let target = name(&["missing", "other"]);
    let mut first_soa = soa_record(name(&["other"]));
    first_soa.ttl = 60;
    let mut second_soa = first_soa.clone();
    second_soa.ttl = 30;
    let mut first_proof = nsec_record(target.clone(), "next-one");
    first_proof.ttl = 45;
    let mut second_proof = nsec_record(target.clone(), "next-two");
    second_proof.ttl = 20;
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![cname_record(query.qname.clone(), target)],
        authorities: vec![first_soa, second_soa, first_proof, second_proof],
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut reply, &query));
    assert!(reply.authorities.is_empty());
}

#[test]
fn accepts_different_ttls_for_same_owner_rrsigs() {
    let query = question(&["www", "example"]);
    let mut first = rrsig_record(query.qname.clone(), RecordType::A, 1);
    first.ttl = 60;
    let mut second = rrsig_record(query.qname.clone(), RecordType::AAAA, 2);
    second.ttl = 30;
    let mut reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 1), first, second],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    assert!(normalize_response_rrsets(&mut reply, &query));
    let signatures = reply
        .answers
        .iter()
        .filter(|record| u16::from(record.rtype) == 46)
        .collect::<Vec<_>>();
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0].ttl, 60);
    assert_eq!(signatures[1].ttl, 30);
}

#[test]
fn preserves_distinct_rrsigs_across_sections() {
    let query = question(&["www", "example"]);
    let answer_signature = rrsig_record(query.qname.clone(), RecordType::A, 1);
    let authority_signature = rrsig_record(query.qname.clone(), RecordType::NS, 2);
    let additional_signature = rrsig_record(query.qname.clone(), RecordType::AAAA, 3);
    let mut reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 1), answer_signature],
        authorities: vec![authority_signature],
        additionals: vec![additional_signature],
    };

    assert!(normalize_response_rrsets(&mut reply, &query));
    assert_eq!(reply.authorities.len(), 1);
    assert_eq!(reply.additionals.len(), 1);
    assert!(
        matches!(reply.authorities[0].rdata, RData::RRSIG(ref rrsig) if rrsig.signature == [2])
    );
    assert!(
        matches!(reply.additionals[0].rdata, RData::RRSIG(ref rrsig) if rrsig.signature == [3])
    );
}

#[test]
fn treats_high_bit_ttls_as_zero() {
    let query = question(&["www", "example"]);
    let mut reply = Message {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![query.clone()],
        answers: vec![a_record(query.qname.clone(), 1)],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    reply.answers[0].ttl = 0x8000_0001;

    assert!(normalize_response_rrsets(&mut reply, &query));
    assert_eq!(reply.answers[0].ttl, 0);
}

#[test]
fn high_edns_extended_rcodes_are_metadata_and_not_negative_ttls() {
    let query = question(&["www", "example"]);
    for extended_rcode in [128, 255] {
        let opt = dns::Edns {
            extended_rcode,
            dnssec_ok: true,
            z: 1,
            ..dns::Edns::default()
        }
        .into_record();
        let expected_control_word = opt.ttl;
        let mut reply = Message {
            headers: Headers {
                qr: true,
                aa: true,
                ..Headers::default()
            },
            questions: vec![query.clone()],
            answers: vec![a_record(query.qname.clone(), 1)],
            authorities: Vec::new(),
            additionals: vec![opt],
        };
        let expected_rcode = u16::from(extended_rcode) << 4;
        assert_eq!(reply.extended_rcode(), expected_rcode);
        assert!(normalize_response_rrsets(&mut reply, &query));
        assert_eq!(reply.extended_rcode(), expected_rcode);
        assert_eq!(reply.additionals[0].ttl, expected_control_word);
    }
}

#[test]
fn schedules_eligible_retries_after_untried_candidates_in_input_order() {
    let untried_first = "192.0.2.1:53".parse().unwrap();
    let untried_second = "192.0.2.2:53".parse().unwrap();
    let retry_first = "192.0.2.3:53".parse().unwrap();
    let exhausted = "192.0.2.4:53".parse().unwrap();
    let retry_second = "192.0.2.5:53".parse().unwrap();
    let mut candidates = vec![untried_second, untried_first];
    let attempts = [(retry_first, 1_u8), (exhausted, 2_u8)]
        .into_iter()
        .collect();

    schedule_retries(
        &mut candidates,
        &attempts,
        [retry_first, exhausted, retry_second],
        Some(2),
    );

    let mut pop_order = Vec::new();
    while let Some(candidate) = candidates.pop() {
        pop_order.push(candidate);
    }
    assert_eq!(
        pop_order,
        [untried_first, untried_second, retry_first, retry_second]
    );
}

#[test]
fn cname_restart_retains_dname_and_signature_and_rejects_a_forged_target() {
    let question = question(&["www", "old", "example"]);
    let owner = name(&["old", "example"]);
    let dname = ResourceRecord {
        name: owner.clone(),
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::DNAME(name(&["new", "other"])),
    };
    let sig = rrsig_record(owner, RecordType::DNAME, 1);
    let cname = cname_record(question.qname.clone(), name(&["www", "new", "other"]));
    let (chain, target) = cname_restart(&[dname.clone(), sig, cname], &question)
        .unwrap()
        .unwrap();
    assert!(target.eq_dns(&name(&["www", "new", "other"])));
    assert_eq!(
        chain.iter().map(|r| r.rtype).collect::<Vec<_>>(),
        vec![RecordType::DNAME, RecordType::RRSIG, RecordType::CNAME]
    );
    let forged = cname_record(question.qname.clone(), name(&["wrong", "other"]));
    assert!(matches!(
        cname_restart(&[dname, forged], &question),
        Err(CnameError::InvalidDname)
    ));
}

#[test]
fn repeated_dname_proof_keeps_earliest_ttl_during_composition() {
    let owner = name(&["old", "example"]);
    let first = ResourceRecord {
        name: owner,
        rtype: RecordType::DNAME,
        class: ClassType::IN,
        ttl: 10,
        rdata: RData::DNAME(name(&["new", "other"])),
    };
    let mut later = first.clone();
    later.ttl = 40;
    let mut records = vec![first];
    super::super::append_distinct(&mut records, [later]);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].ttl, 10);
}
