use super::*;

fn positive() -> Message {
    let mut message = reply();
    message.headers.rcode = RCode::Ok;
    let owner = message.questions[0].qname.clone();
    message.answers = vec![
        ResourceRecord {
            name: owner.clone(),
            ..record(RecordType::A, RData::A("192.0.2.1".parse().unwrap()))
        },
        ResourceRecord {
            name: owner,
            ..signature(1)
        },
    ];
    message.authorities.retain(|record| {
        record.rtype != RecordType::SOA
            && !matches!(&record.rdata, RData::RRSIG(signature) if signature.type_covered == 6)
    });
    message
}

#[test]
fn positive_render_matches_checked_encoder_with_proofs_and_all_request_fields() {
    let original = positive();
    let prepared = PreparedPositiveReply::from_message(&original)
        .unwrap()
        .unwrap();
    for id in [0, 65535] {
        for cd in [false, true] {
            for allowed in [false, true] {
                for ttl in [0, 1, 29, 30] {
                    let mut request = query();
                    request.headers.id = id;
                    request.headers.cd = cd;
                    request.headers.ad = allowed;
                    let encoded = prepared.render(&request, ttl, 1232, allowed).unwrap();
                    assert!(encoded.matches_request(&request));
                    let mut expected = original.clone();
                    expected.headers.id = id;
                    expected.headers.cd = cd;
                    expected.headers.ad = allowed && !cd;
                    for record in expected.answers.iter_mut().chain(&mut expected.authorities) {
                        record.ttl = ttl;
                    }
                    assert_eq!(encoded.into_bytes(), expected.into_wire().unwrap());
                }
            }
        }
    }
}

#[test]
fn positive_render_rejects_rewrites_larger_ttls_and_small_payloads() {
    let prepared = PreparedPositiveReply::from_message(&positive())
        .unwrap()
        .unwrap();
    assert!(prepared.render(&query(), 31, 1232, true).is_none());
    assert!(prepared.render(&query(), 10, 40, true).is_none());
    for change in 0..6 {
        let mut request = query();
        match change {
            0 => request.questions[0].qname = name("MISSING.example.test."),
            1 => request.questions[0].qtype = QueryType::AAAA,
            2 => request.questions[0].qclass = QClassType::Class(ClassType::CH),
            3 => request.headers.rd = false,
            4 => request.additionals.clear(),
            5 => request.additionals[0].ttl = 0,
            _ => unreachable!(),
        }
        assert!(prepared.render(&request, 10, 1232, true).is_none());
    }
    assert!(prepared.render(&query(), 10, 1232, true).is_some());
}

#[test]
fn positive_preparation_checks_invalid_records_and_declines_composite_shapes() {
    let mut malformed = positive();
    malformed.answers[0].rdata = RData::TXT(vec![vec![0; 256]]);
    assert!(PreparedPositiveReply::from_message(&malformed).is_err());
    let mut composite = positive();
    composite.answers[0].name = name("elsewhere.example.test.");
    composite.answers[1].name = name("elsewhere.example.test.");
    assert!(
        PreparedPositiveReply::from_message(&composite)
            .unwrap()
            .is_none()
    );
    assert!(
        PreparedPositiveReply::from_message(&reply())
            .unwrap()
            .is_none()
    );
}

fn plain_positive() -> Message {
    let mut message = positive();
    message.answers.retain(|rr| rr.rtype == RecordType::A);
    message.authorities.clear();
    message.additionals[0].ttl = 0;
    message
}

#[test]
fn plain_positive_matches_checked_classic_and_edns_bytes_across_ad_cd_and_ttls() {
    let original = plain_positive();
    let prepared = PreparedPositiveReply::from_message(&original)
        .unwrap()
        .unwrap();
    for classic in [false, true] {
        for bits in 0..16 {
            for ttl in [0, 1, 29, 30] {
                let mut request = query();
                request.headers.id = if bits & 1 == 0 { 0 } else { 65535 };
                request.headers.ad = bits & 2 != 0;
                request.headers.cd = bits & 4 != 0;
                request.additionals[0].ttl = 0;
                if classic {
                    request.additionals.clear();
                }
                let allowed = bits & 8 != 0;
                let encoded = prepared.render(&request, ttl, 4096, allowed).unwrap();
                assert!(encoded.matches_request(&request));
                let mut expected = original.clone();
                expected.headers.id = request.headers.id;
                expected.headers.ad = request.headers.ad && !request.headers.cd && allowed;
                expected.headers.cd = request.headers.cd;
                expected.answers[0].ttl = ttl;
                if classic {
                    expected.additionals.clear();
                }
                assert_eq!(encoded.into_bytes(), expected.into_wire().unwrap());
            }
        }
    }
}

#[test]
fn plain_positive_correlation_binds_both_request_ad_values() {
    let prepared = PreparedPositiveReply::from_message(&plain_positive())
        .unwrap()
        .unwrap();
    for classic in [false, true] {
        for ad in [false, true] {
            let mut request = query();
            request.headers.ad = ad;
            request.additionals[0].ttl = 0;
            if classic {
                request.additionals.clear();
            }
            let encoded = prepared.render(&request, 10, 4096, true).unwrap();
            assert!(encoded.matches_request(&request));
            request.headers.ad = !ad;
            assert!(!encoded.matches_request(&request));
        }
    }
}

#[test]
fn plain_positive_keeps_classic_limit_and_explicitly_requested_dnssec() {
    let mut original = plain_positive();
    original.questions[0].qtype = QueryType::TXT;
    original.answers = (0..4)
        .map(|n| ResourceRecord {
            name: original.questions[0].qname.clone(),
            ..record(RecordType::TXT, RData::TXT(vec![vec![n; 200]]))
        })
        .collect();
    let prepared = PreparedPositiveReply::from_message(&original)
        .unwrap()
        .unwrap();
    let mut request = query();
    request.questions[0].qtype = QueryType::TXT;
    request.additionals[0].ttl = 0;
    assert!(prepared.render(&request, 10, 1232, true).is_some());
    request.additionals.clear();
    assert!(prepared.render(&request, 10, 4096, true).is_none());
    let mut unrequested = positive();
    unrequested.additionals[0].ttl = 0;
    assert!(
        PreparedPositiveReply::from_message(&unrequested)
            .unwrap()
            .is_none()
    );
    for (qtype, mut rr) in [
        (QueryType::RRSIG, signature(1)),
        (
            QueryType::NSEC,
            record(
                RecordType::NSEC,
                RData::NSEC(Nsec {
                    next_domain_name: name("next.example.test."),
                    type_bitmap: TypeBitmap::new([1, 46, 47]).unwrap(),
                }),
            ),
        ),
    ] {
        let mut original = plain_positive();
        original.questions[0].qtype = qtype;
        rr.name = original.questions[0].qname.clone();
        original.answers = vec![rr];
        original.headers.ad = false;
        let prepared = PreparedPositiveReply::from_message(&original)
            .unwrap()
            .unwrap();
        let mut request = query();
        request.questions[0].qtype = qtype;
        request.additionals.clear();
        let actual = prepared
            .render(&request, 10, 4096, true)
            .unwrap()
            .into_message()
            .unwrap();
        assert_eq!(actual.answers.len(), 1);
        assert_eq!(u16::from(actual.answers[0].rtype), qtype.value());
        assert!(!actual.headers.ad);
    }
}

#[test]
fn composed_template_preserves_independent_ttls_and_rejects_ttl_extension() {
    let mut message = plain_positive();
    let target = name("target.example.test.");
    let mut terminal = message.answers[0].clone();
    terminal.name = target.clone();
    terminal.ttl = 90;
    message.answers[0].rtype = RecordType::CNAME;
    message.answers[0].rdata = RData::CNAME(target);
    message.answers[0].ttl = 10;
    message.answers.push(terminal);
    let template = PreparedPositiveReply::from_composed_message(&message)
        .unwrap()
        .unwrap();
    let mut request = query();
    request.additionals[0].ttl = 0;
    for ttls in [[0, 0], [1, 60], [10, 90]] {
        let encoded = template
            .render_record_ttls(&request, &ttls, 1232, true)
            .unwrap();
        let mut expected = message.clone();
        expected.headers.ad = false;
        for (record, ttl) in expected.answers.iter_mut().zip(ttls) {
            record.ttl = ttl;
        }
        assert_eq!(encoded.into_bytes(), expected.into_wire().unwrap());
    }
    for ttls in [[11, 90], [10, 91]] {
        assert!(
            template
                .render_record_ttls(&request, &ttls, 1232, true)
                .is_none()
        );
    }
    assert!(
        template
            .render_record_ttls(&request, &[1], 1232, true)
            .is_none()
    );
    let mut second_address = message.answers[1].clone();
    second_address.rdata = RData::A("192.0.2.2".parse().unwrap());
    message.answers.push(second_address);
    let rrset_template = PreparedPositiveReply::from_composed_message(&message)
        .unwrap()
        .unwrap();
    assert!(
        rrset_template
            .render_record_ttls(&request, &[1, 30, 31], 1232, true)
            .is_none()
    );
    assert!(
        rrset_template
            .render_record_ttls(&request, &[1, 30, 30], 1232, true)
            .is_some()
    );
    request.questions[0].qtype = QueryType::AAAA;
    assert!(
        template
            .render_record_ttls(&request, &[1, 60], 1232, true)
            .is_none()
    );
}
