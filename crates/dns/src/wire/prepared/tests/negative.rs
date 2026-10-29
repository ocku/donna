use super::*;

#[test]
fn prepared_reply_matches_checked_bytes_across_headers_and_name_error_qtypes() {
    let original = reply();
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    for id in [0, 65535] {
        for cd in [false, true] {
            for ad in [false, true] {
                for allowed in [false, true] {
                    for qtype in [
                        QueryType::A,
                        QueryType::TXT,
                        QueryType::ANY,
                        QueryType::Unknown(65000),
                    ] {
                        let mut request = query();
                        request.headers.id = id;
                        request.headers.cd = cd;
                        request.headers.ad = ad;
                        request.questions[0].qtype = qtype;
                        let ttls = [20, 21, 22, 23];
                        let encoded = prepared.render(&request, &ttls, 1232, allowed).unwrap();
                        assert!(encoded.matches_request(&request));
                        let mut expected = original.clone();
                        expected.headers.id = id;
                        expected.headers.cd = cd;
                        expected.headers.ad = allowed && !cd;
                        expected.questions.clone_from(&request.questions);
                        for (record, ttl) in expected.authorities.iter_mut().zip(ttls) {
                            record.ttl = ttl;
                        }
                        assert_eq!(encoded.as_bytes(), expected.into_wire().unwrap());
                    }
                }
            }
        }
    }
}

#[test]
fn unsupported_requests_decline_without_mutating_the_prototype() {
    let original = reply();
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let mut variations = Vec::new();
    let mut request = query();
    request.questions[0].qname = name("MISSING.example.test.");
    variations.push(request);
    let mut request = query();
    request.questions[0].qclass = QClassType::Class(ClassType::CH);
    variations.push(request);
    let mut request = query();
    request.headers.rd = false;
    variations.push(request);
    let mut request = query();
    request.headers.qr = true;
    variations.push(request);
    let mut request = query();
    request.headers.opcode = OpCode::Notify;
    variations.push(request);
    let mut request = query();
    request.questions[0].qtype = QueryType::AXFR;
    variations.push(request);
    let mut request = query();
    request.questions[0].qtype = QueryType::IXFR;
    variations.push(request);
    let mut request = query();
    request.questions[0].qtype = QueryType::Unknown(1);
    variations.push(request);
    let mut request = query();
    request.questions.push(request.questions[0].clone());
    variations.push(request);
    let mut request = query();
    request.additionals.clear();
    variations.push(request);
    let mut request = query();
    request.additionals[0] = Edns::new(1232).into_record();
    variations.push(request);
    let mut request = query();
    request.additionals.push(request.additionals[0].clone());
    variations.push(request);
    let mut request = query();
    request.additionals[0] = Edns {
        version: 1,
        dnssec_ok: true,
        ..Edns::new(1232)
    }
    .into_record();
    variations.push(request);
    for request in variations {
        assert!(prepared.render(&request, &[20; 4], 1232, true).is_none());
    }
    assert!(prepared.render(&query(), &[31; 4], 1232, true).is_none());
    assert!(prepared.render(&query(), &[20; 3], 1232, true).is_none());
    assert!(prepared.render(&query(), &[20; 4], 12, true).is_none());
    assert!(prepared.render(&query(), &[20; 4], 1232, true).is_some());
}

#[test]
fn prepared_ttls_cannot_split_an_ordinary_rrset() {
    let mut original = reply();
    let mut second = ns();
    original.authorities.push(second.clone());
    second.rdata = RData::NS(name("other.example.test."));
    original.authorities.push(second);
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    assert!(
        prepared
            .render(&query(), &[20, 20, 20, 20, 10, 11], 1232, true)
            .is_none()
    );
    assert!(
        prepared
            .render(&query(), &[20, 20, 20, 20, 10, 10], 1232, true)
            .is_some()
    );
}

#[test]
fn prepared_nodata_retains_its_exact_question_type() {
    let mut original = reply();
    original.headers.rcode = RCode::Ok;
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let mut request = query();
    request.questions[0].qtype = QueryType::TXT;
    assert!(prepared.render(&request, &[20; 4], 1232, true).is_none());
}

#[test]
fn malformed_prototypes_keep_normal_encoder_errors() {
    let mut original = reply();
    original.authorities[0].rdata = RData::Unknown(vec![]);
    assert_eq!(
        PreparedNegativeReply::from_message(&original).unwrap_err(),
        original.into_wire().unwrap_err()
    );
    let mut original = reply();
    original.answers.push(ns());
    assert!(
        PreparedNegativeReply::from_message(&original)
            .unwrap()
            .is_none()
    );
}

#[test]
fn prepared_reply_cannot_upgrade_an_unauthenticated_prototype() {
    let mut original = reply();
    original.headers.ad = false;
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    let response = prepared
        .render(&query(), &[20; 4], 1232, true)
        .unwrap()
        .into_message()
        .unwrap();
    assert!(!response.headers.ad);
}

#[test]
fn encoded_context_binds_do_version_options_but_transport_still_checks_payload() {
    let prepared = PreparedNegativeReply::from_message(&reply())
        .unwrap()
        .unwrap();
    let encoded = prepared.render(&query(), &[20; 4], 1232, true).unwrap();
    let mut changed = query();
    changed.additionals[0] = Edns::new(1232).into_record();
    assert!(!encoded.matches_request(&changed));
    let mut changed = query();
    changed.additionals[0] = Edns {
        version: 1,
        dnssec_ok: true,
        ..Edns::new(1232)
    }
    .into_record();
    assert!(!encoded.matches_request(&changed));
    let mut changed = query();
    changed.additionals[0] = Edns {
        dnssec_ok: true,
        options: vec![crate::EdnsOption {
            code: 65000,
            data: vec![],
        }],
        ..Edns::new(1232)
    }
    .into_record();
    assert!(!encoded.matches_request(&changed));
    let mut changed = query();
    changed.additionals[0] = Edns {
        dnssec_ok: true,
        ..Edns::new(512)
    }
    .into_record();
    assert!(encoded.matches_request(&changed)); // Listener enforces the actual smaller budget.
}

#[test]
fn nsec3_binary_and_maximum_question_names_keep_offsets_and_ns_spelling() {
    let mut long = vec![vec![b'x']; 120];
    long.extend([b"example".to_vec(), b"test".to_vec()]);
    for labels in [
        vec![
            vec![0, 0xc0, 255, b'A'],
            b"example".to_vec(),
            b"test".to_vec(),
        ],
        long,
    ] {
        let mut request = query();
        request.questions[0].qname = DomainName::from_labels(labels).unwrap();
        let mut original = reply();
        original.questions.clone_from(&request.questions);
        let owner = name("00000000000000000000000000000000.example.test.");
        original.authorities[1] = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::NSEC3,
            class: ClassType::IN,
            ttl: 30,
            rdata: RData::NSEC3(crate::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 0,
                salt: vec![1, 2],
                next_hashed_owner_name: vec![0; 20],
                type_bitmap: Some(TypeBitmap::new([6, 46, 50]).unwrap()),
            }),
        };
        original.authorities[3] = signature(50);
        original.authorities[3].name = owner;
        if let RData::RRSIG(signature) = &mut original.authorities[3].rdata {
            signature.labels = 3;
        }
        let prepared = PreparedNegativeReply::from_message(&original)
            .unwrap()
            .unwrap();
        let mut actual = prepared
            .render(&request, &[11, 12, 13, 14], 1232, true)
            .unwrap();
        let mut nameserver = ns();
        nameserver.name = name("EXAMPLE.test.");
        nameserver.ttl = 17;
        assert!(actual.append_name_servers(std::slice::from_ref(&nameserver)));
        let mut expected = original;
        for (record, ttl) in expected.authorities.iter_mut().zip([11, 12, 13, 14]) {
            record.ttl = ttl;
        }
        expected.authorities.push(nameserver);
        assert_eq!(
            actual.into_message().unwrap().into_wire().unwrap(),
            expected.into_wire().unwrap()
        );
    }
}

#[test]
fn plain_negative_matches_checked_encoding_and_classic_ns_append() {
    let mut original = reply();
    original.authorities.truncate(1);
    original.additionals = vec![Edns::default().into_record()];
    let prepared = PreparedNegativeReply::from_message(&original)
        .unwrap()
        .unwrap();
    for classic in [false, true] {
        for cd in [false, true] {
            for ad in [false, true] {
                for allowed in [false, true] {
                    let mut request = query();
                    request.headers.cd = cd;
                    request.headers.ad = ad;
                    request.questions[0].qtype = QueryType::TXT;
                    request.additionals = if classic {
                        vec![]
                    } else {
                        vec![Edns::new(1232).into_record()]
                    };
                    let mut encoded = prepared.render(&request, &[17], 4096, allowed).unwrap();
                    let mut expected = original.clone();
                    expected.headers.cd = cd;
                    expected.headers.ad = allowed && ad && !cd;
                    expected.questions.clone_from(&request.questions);
                    expected.authorities[0].ttl = 17;
                    if classic {
                        expected.additionals.clear();
                    }
                    assert_eq!(encoded.as_bytes(), expected.into_wire().unwrap());
                    assert!(encoded.matches_request(&request));
                    assert!(encoded.append_name_servers(&[ns()]));
                    expected.authorities.push(ns());
                    assert_eq!(
                        encoded.into_message().unwrap().into_wire().unwrap(),
                        expected.into_wire().unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn non_do_negative_cannot_cross_explicit_dnssec_filter_policies() {
    for qtype in [QueryType::RRSIG, QueryType::NSEC, QueryType::NSEC3] {
        let mut ordinary = reply();
        ordinary.authorities.truncate(1);
        ordinary.additionals = vec![Edns::default().into_record()];
        let mut explicit = ordinary.clone();
        explicit.questions[0].qtype = qtype;
        // An empty proof set is still type-dependent: a later request must not
        // reuse the projection selected for an explicit DNSSEC question.
        for (prototype, target) in [(&ordinary, qtype), (&explicit, QueryType::A)] {
            let prepared = PreparedNegativeReply::from_message(prototype)
                .unwrap()
                .unwrap();
            let mut request = prototype.clone();
            request.headers.qr = false;
            request.headers.ra = false;
            request.headers.rcode = RCode::Ok;
            request.questions[0].qtype = target;
            assert!(prepared.render(&request, &[20], 1232, true).is_none());
        }
        let mut unfiltered = reply();
        unfiltered.additionals = ordinary.additionals.clone();
        assert!(
            PreparedNegativeReply::from_message(&unfiltered)
                .unwrap()
                .is_none()
        );
    }
}
