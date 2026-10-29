use super::*;

#[test]
fn prepared_authoritative_nodata_keeps_exact_question_flags_limits_and_checked_records() {
    for dnssec_ok in [false, true] {
        let mut request = query();
        request.additionals = vec![
            Edns {
                dnssec_ok,
                ..Edns::new(1232)
            }
            .into_record(),
        ];
        let original = expected(&request, reply(), false);
        let refs: Vec<_> = original.authorities.iter().collect();
        let prepared = PreparedAuthoritativeNodataReply::from_records(&request, &refs)
            .unwrap()
            .unwrap();
        for bits in 0..16 {
            let mut current = request.clone();
            current.headers.id = 65535 - bits;
            current.headers.rd = bits & 1 != 0;
            current.headers.cd = bits & 2 != 0;
            current.headers.ad = bits & 4 != 0;
            if bits & 8 != 0 && !dnssec_ok {
                current.additionals.clear();
            }
            let encoded = prepared.render(&current, 1232).unwrap();
            assert!(encoded.matches_request(&current));
            assert_eq!(
                encoded.as_bytes(),
                expected(&current, original.clone(), false)
                    .into_wire()
                    .unwrap()
            );
            assert!(
                prepared
                    .render(&current, encoded.as_bytes().len() - 1)
                    .is_none()
            );
        }
        for mutation in 0..9 {
            let mut changed = request.clone();
            match mutation {
                0 => changed.questions[0].qname = name("MISSING.example.test."),
                1 => changed.questions[0].qtype = QueryType::AAAA,
                2 => changed.questions[0].qclass = QClassType::Class(ClassType::CH),
                3 => changed.headers.qr = true,
                4 => changed.headers.aa = true,
                5 => changed.headers.ra = true,
                6 => changed.headers.tc = true,
                7 => changed.additionals.push(changed.additionals[0].clone()),
                _ => {
                    if let RData::OPT(options) = &mut changed.additionals[0].rdata {
                        options.push(crate::EdnsOption {
                            code: 65000,
                            data: vec![1],
                        });
                    }
                }
            }
            assert!(prepared.render(&changed, 1232).is_none());
        }
        let mut broken = original.authorities.clone();
        broken[0].ttl = 31; // Exceeds this SOA's MINIMUM; never prepare unchecked bytes.
        assert!(
            PreparedAuthoritativeNodataReply::from_records(
                &request,
                &broken.iter().collect::<Vec<_>>()
            )
            .is_err()
        );
        let mut large = original.authorities.clone();
        for tag in 100..120 {
            let mut record = signature(6);
            if let RData::RRSIG(signature) = &mut record.rdata {
                signature.key_tag = tag;
            }
            large.push(record);
        }
        assert!(
            PreparedAuthoritativeNodataReply::from_records(
                &request,
                &large.iter().collect::<Vec<_>>()
            )
            .unwrap()
            .is_none()
        );
    }
}

fn expected(request: &Message, mut response: Message, name_error: bool) -> Message {
    response.headers = Headers {
        id: request.headers.id,
        qr: true,
        aa: true,
        rd: request.headers.rd,
        rcode: if name_error {
            RCode::NameError
        } else {
            RCode::Ok
        },
        ..Headers::default()
    };
    response.questions.clone_from(&request.questions);
    response.additionals = request
        .edns()
        .unwrap()
        .map(|edns| {
            Edns {
                dnssec_ok: edns.dnssec_ok,
                ..Edns::default()
            }
            .into_record()
        })
        .into_iter()
        .collect();
    response
}

#[test]
fn borrowed_authoritative_encoding_matches_checked_messages_and_correlates_requests() {
    for opt in [None, Some(false), Some(true)] {
        for rd in [false, true] {
            for cd in [false, true] {
                for ad in [false, true] {
                    for name_error in [false, true] {
                        for qtype in [
                            QueryType::A,
                            QueryType::DS,
                            QueryType::ANY,
                            QueryType::Unknown(65000),
                        ] {
                            let mut request = query();
                            request.headers.id = 65535;
                            request.headers.rd = rd;
                            request.headers.cd = cd;
                            request.headers.ad = ad;
                            request.questions[0].qtype = qtype;
                            request.additionals = opt
                                .map(|dnssec_ok| {
                                    Edns {
                                        dnssec_ok,
                                        ..Edns::new(512)
                                    }
                                    .into_record()
                                })
                                .into_iter()
                                .collect();
                            let original = expected(&request, reply(), name_error);
                            let refs: Vec<_> = original.authorities.iter().collect();
                            let encoded = EncodedReply::authoritative_negative(
                                &request, &refs, name_error, 512,
                            )
                            .unwrap()
                            .unwrap();
                            assert_eq!(encoded.as_bytes(), original.into_wire().unwrap());
                            assert!(encoded.matches_request(&request));
                            for mutation in 0..6 {
                                let mut changed = request.clone();
                                match mutation {
                                    0 => changed.headers.id ^= 1,
                                    1 => changed.headers.rd = !rd,
                                    2 => changed.headers.cd = !cd,
                                    3 => changed.questions[0].qtype = QueryType::TXT,
                                    4 => changed.questions[0].qname = name("MISSING.example.test."),
                                    _ => {
                                        changed.additionals = if opt.is_some() {
                                            Vec::new()
                                        } else {
                                            vec![Edns::default().into_record()]
                                        }
                                    }
                                }
                                assert!(!encoded.matches_request(&changed));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn borrowed_authoritative_record_errors_match_the_full_validator() {
    let request = query();
    let original = expected(&request, reply(), true);
    for mutation in 0..9 {
        let mut response = original.clone();
        match mutation {
            0 => response.authorities.push(response.authorities[1].clone()),
            1 => {
                let mut second = response.authorities[1].clone();
                second.ttl += 1;
                if let RData::NSEC(nsec) = &mut second.rdata {
                    nsec.next_domain_name = name("different.example.test.");
                }
                response.authorities.push(second);
            }
            2 => response.authorities[0].ttl = 31,
            3 => response.authorities[0].name = name("elsewhere.test."),
            4 => response.authorities[0].class = ClassType::CH,
            5 => response.authorities.push(response.authorities[2].clone()),
            6 => response.authorities[1].rdata = RData::A("192.0.2.1".parse().unwrap()),
            7 => response.authorities[1].ttl = u32::MAX,
            _ => response.authorities.clear(),
        }
        let refs: Vec<_> = response.authorities.iter().collect();
        assert_eq!(
            EncodedReply::authoritative_negative(&request, &refs, true, 1232)
                .unwrap_err()
                .to_string(),
            response.into_wire().unwrap_err().to_string(),
            "mutation {mutation}",
        );
    }
}

#[test]
fn unsupported_borrowed_shapes_keep_normal_handling_and_oversize_keeps_selected_records() {
    let request = query();
    let response = expected(&request, reply(), true);
    let refs: Vec<_> = response.authorities.iter().collect();
    for mutation in 0..7 {
        let mut query = request.clone();
        match mutation {
            0 => query.questions[0].qtype = QueryType::AXFR,
            1 => query.questions[0].qclass = QClassType::ANY,
            2 => query.headers.opcode = OpCode::Notify,
            3 => query.additionals[0].ttl |= 1 << 16,
            4 => query.additionals.push(query.additionals[0].clone()),
            5 => query.answers.push(response.authorities[0].clone()),
            _ => {
                if let RData::OPT(options) = &mut query.additionals[0].rdata {
                    options.push(crate::EdnsOption {
                        code: 65001,
                        data: vec![1],
                    });
                }
            }
        }
        assert!(
            EncodedReply::authoritative_negative(&query, &refs, true, 1232)
                .unwrap()
                .is_none()
        );
    }
    let encoded = EncodedReply::authoritative_negative(&request, &refs, true, 64)
        .unwrap()
        .unwrap();
    assert!(encoded.as_bytes().len() > 64);
    assert_eq!(
        encoded.into_message().unwrap().into_wire().unwrap(),
        response.into_wire().unwrap()
    );
}

#[test]
fn authoritative_ns_append_enforces_actual_edns_or_classic_ceiling() {
    let original = reply();
    let authorities = [&original.authorities[0]];
    let records: Vec<_> = (0..20)
        .map(|index| {
            let mut record = ns();
            record.rdata = RData::NS(name(&format!("nameserver-{index}.example.test.")));
            record
        })
        .collect();
    for opt in [None, Some(false), Some(true)] {
        let mut request = query();
        request.additionals = opt
            .map(|dnssec_ok| {
                Edns {
                    dnssec_ok,
                    ..Edns::new(512)
                }
                .into_record()
            })
            .into_iter()
            .collect();
        let mut encoded = EncodedReply::authoritative_negative(&request, &authorities, true, 4096)
            .unwrap()
            .unwrap();
        let before = encoded.as_bytes().to_vec();
        assert!(!encoded.append_name_servers(&records));
        assert_eq!(encoded.as_bytes(), before);
        assert!(encoded.append_name_servers(&records[..1]));
        assert!(encoded.as_bytes().len() <= 512);
        assert!(encoded.matches_request(&request));
        encoded
            .into_message()
            .unwrap()
            .validate_for_forwarding()
            .unwrap();
    }
}
