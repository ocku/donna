use super::*;

fn owned(records: &[(&ResourceRecord, u32)]) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|&(rr, ttl)| {
            let mut value = rr.clone();
            value.ttl = ttl;
            value
        })
        .collect()
}

fn expected(
    request: &Message,
    answers: &[(&ResourceRecord, u32)],
    authorities: &[(&ResourceRecord, u32)],
    ad: bool,
) -> Message {
    let edns = request.edns().unwrap();
    let dnssec_ok = edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
    Message {
        headers: Headers {
            id: request.headers.id,
            qr: true,
            rd: true,
            ra: true,
            ad: ad && !request.headers.cd && (dnssec_ok || request.headers.ad),
            cd: request.headers.cd,
            ..Headers::default()
        },
        questions: request.questions.clone(),
        answers: owned(answers),
        authorities: owned(authorities),
        additionals: edns
            .map(|_| {
                Edns {
                    dnssec_ok,
                    ..Edns::default()
                }
                .into_record()
            })
            .into_iter()
            .collect(),
    }
}

#[test]
fn borrowed_recursive_chain_matches_ordinary_encoding_with_independent_ttls_and_names() {
    let mut request = query();
    let mut alias = record(
        RecordType::CNAME,
        RData::CNAME(name("target.example.test.")),
    );
    let mut alias_sig = signature(5);
    let mut terminal = record(RecordType::A, RData::A("192.0.2.1".parse().unwrap()));
    terminal.name = name("target.example.test.");
    let denial = record(
        RecordType::NSEC,
        RData::NSEC(Nsec {
            next_domain_name: name("next.example.test."),
            type_bitmap: TypeBitmap::new([6, 46, 47]).unwrap(),
        }),
    );
    let denial_sig = signature(47);
    for qname in [
        name("MiSsInG.example.test."),
        DomainName::root(),
        DomainName::from_labels(vec![vec![0, b'A', 255], b"example".to_vec()]).unwrap(),
        DomainName::from_labels(vec![
            vec![b'X'; 63],
            vec![b'Y'; 63],
            vec![b'Z'; 63],
            vec![b'W'; 61],
        ])
        .unwrap(),
    ] {
        request.questions[0].qname = qname.clone();
        alias.name = qname.clone();
        alias_sig.name = qname;
        // These are ordinary checked record tests, not cryptographic fixtures.
        if let RData::RRSIG(sig) = &mut alias_sig.rdata {
            sig.labels = 0;
        }
        for bits in 0..8 {
            request.headers.id = if bits & 1 == 0 { 0 } else { 65535 };
            request.headers.cd = bits & 2 != 0;
            let ad = bits & 4 != 0;
            let answers = [(&alias, 7), (&alias_sig, 6), (&terminal, 22)];
            let authorities = [(&denial, 13), (&denial_sig, 12)];
            let actual =
                EncodedReply::recursive_positive(&request, &answers, &authorities, ad, 1232)
                    .unwrap()
                    .unwrap();
            assert!(actual.matches_request(&request));
            assert_eq!(
                actual.into_bytes(),
                expected(&request, &answers, &authorities, ad)
                    .into_wire()
                    .unwrap()
            );
        }
    }
}

fn compare(request: &Message, records: &[ResourceRecord], ttls: &[u32]) {
    let answers = records
        .iter()
        .zip(ttls)
        .map(|(rr, &ttl)| (rr, ttl))
        .collect::<Vec<_>>();
    let actual = EncodedReply::recursive_positive(request, &answers, &[], true, 1232);
    let expected = expected(request, &answers, &[], true).into_wire();
    match (actual, expected) {
        (Ok(Some(actual)), Ok(expected)) => assert_eq!(actual.into_bytes(), expected),
        (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
        _ => panic!("borrowed validation diverged from checked Message encoding"),
    }
}

#[test]
fn borrowed_recursive_rrsets_validate_effective_ttls_on_linear_and_indexed_paths() {
    let request = query();
    for count in [2, 40] {
        let mut records = (1..=count)
            .map(|n| {
                record(
                    RecordType::A,
                    RData::A(std::net::Ipv4Addr::new(192, 0, 2, n)),
                )
            })
            .collect::<Vec<_>>();
        records[1].ttl = 29;
        let mut ttls = vec![20; usize::from(count)];
        compare(&request, &records, &ttls); // Original TTLs differ, projected TTLs agree.
        *ttls.last_mut().unwrap() = 19;
        compare(&request, &records, &ttls); // Must report projected TTL inconsistency.
        *ttls.last_mut().unwrap() = 20;
        *records.last_mut().unwrap() = records[0].clone();
        compare(&request, &records, &ttls); // Exact duplicate, including promoted indexes.
    }
    let cname = record(
        RecordType::CNAME,
        RData::CNAME(name("target.example.test.")),
    );
    let other_cname = record(RecordType::CNAME, RData::CNAME(name("other.example.test.")));
    compare(&request, &[cname.clone(), other_cname], &[10, 10]);
    compare(
        &request,
        &[
            cname,
            record(RecordType::A, RData::A("192.0.2.1".parse().unwrap())),
        ],
        &[10, 10],
    );
    compare(&request, &[signature(5), signature(5)], &[10, 9]);
}

#[test]
fn borrowed_recursive_keeps_oversized_selected_rrset_and_declines_ttl_extension() {
    let request = query();
    let records = (0..8)
        .map(|n| record(RecordType::TXT, RData::TXT(vec![vec![n; 200]])))
        .collect::<Vec<_>>();
    let answers = records.iter().map(|rr| (rr, 10)).collect::<Vec<_>>();
    let encoded = EncodedReply::recursive_positive(&request, &answers, &[], false, 512)
        .unwrap()
        .unwrap();
    assert!(encoded.as_bytes().len() > 512);
    assert_eq!(encoded.into_message().unwrap().answers.len(), 8);
    assert!(
        EncodedReply::recursive_positive(&request, &[(&records[0], 31)], &[], false, 512)
            .unwrap()
            .is_none()
    );
}

#[test]
fn borrowed_recursive_plain_chain_matches_checked_encoder_and_binds_client_ad() {
    let mut alias = record(
        RecordType::CNAME,
        RData::CNAME(name("target.example.test.")),
    );
    let mut terminal = record(RecordType::A, RData::A("192.0.2.1".parse().unwrap()));
    alias.name = query().questions[0].qname.clone();
    terminal.name = name("target.example.test.");
    let answers = [(&alias, 7), (&terminal, 22)];
    for classic in [false, true] {
        for bits in 0..8 {
            let mut request = query();
            request.headers.ad = bits & 1 != 0;
            request.headers.cd = bits & 2 != 0;
            request.additionals[0].ttl = 0;
            if classic {
                request.additionals.clear();
            }
            let authenticated = bits & 4 != 0;
            let actual =
                EncodedReply::recursive_positive(&request, &answers, &[], authenticated, 4096)
                    .unwrap()
                    .unwrap();
            assert!(actual.matches_request(&request));
            let mut another = request.clone();
            another.headers.ad = !another.headers.ad;
            assert!(!actual.matches_request(&another));
            assert_eq!(
                actual.into_bytes(),
                expected(&request, &answers, &[], authenticated)
                    .into_wire()
                    .unwrap()
            );
        }
    }
}

fn cross_zone_negative_components() -> (ResourceRecord, ResourceRecord) {
    let alias = ResourceRecord {
        name: query().questions[0].qname.clone(),
        rtype: RecordType::CNAME,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::CNAME(name("missing.other.test.")),
    };
    let mut soa = reply()
        .authorities
        .into_iter()
        .find(|r| r.rtype == RecordType::SOA)
        .unwrap();
    soa.name = name("other.test.");
    soa.ttl = 60;
    (alias, soa)
}

#[test]
fn borrowed_recursive_negative_matches_checked_encoder_across_zones_and_client_flags() {
    let (alias, soa) = cross_zone_negative_components();
    let ns = ResourceRecord {
        name: name("other.test."),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::NS(name("ns.other.test.")),
    };
    for format in 0..3 {
        for cd in [false, true] {
            for ad in [false, true] {
                for authenticated in [false, true] {
                    for name_error in [false, true] {
                        let mut request = query();
                        request.headers.cd = cd;
                        request.headers.ad = ad;
                        if format == 0 {
                            request.additionals.clear();
                        }
                        if format == 1 {
                            request.additionals[0].ttl = 0;
                        }
                        let answers = [(&alias, 17)];
                        let authorities = [(&soa, 15), (&ns, 15)];
                        let mut ordinary =
                            expected(&request, &answers, &authorities, authenticated);
                        ordinary.headers.rcode = if name_error {
                            RCode::NameError
                        } else {
                            RCode::Ok
                        };
                        let mut encoded = EncodedReply::recursive_negative(
                            &request,
                            &answers,
                            &authorities,
                            name_error,
                            authenticated,
                            1232,
                        )
                        .unwrap()
                        .unwrap();
                        assert!(encoded.matches_request(&request));
                        assert_eq!(encoded.as_bytes(), ordinary.into_wire().unwrap());
                        let mut prototype = ordinary.clone();
                        prototype.headers.cd = false;
                        prototype.headers.ad = authenticated;
                        prototype.additionals = vec![
                            Edns {
                                dnssec_ok: format == 2,
                                ..Edns::default()
                            }
                            .into_record(),
                        ];
                        let prepared = PreparedNegativeReply::from_composed_message(&prototype)
                            .unwrap()
                            .unwrap();
                        let rendered = prepared
                            .render(&request, &[17, 15, 15], 1232, true)
                            .unwrap();
                        assert_eq!(rendered.as_bytes(), encoded.as_bytes());
                        assert!(
                            prepared
                                .render(&request, &[18, 15, 15], 1232, true)
                                .is_none()
                        );
                        assert!(prepared.render(&request, &[17, 15, 15], 40, true).is_none());
                        if name_error {
                            for qtype in [
                                QueryType::CNAME,
                                QueryType::ANY,
                                QueryType::MAILA,
                                QueryType::MAILB,
                                QueryType::AXFR,
                                QueryType::IXFR,
                            ] {
                                let mut changed = request.clone();
                                changed.questions[0].qtype = qtype;
                                assert!(
                                    prepared
                                        .render(&changed, &[17, 15, 15], 1232, true)
                                        .is_none()
                                );
                            }
                            let mut changed = request.clone();
                            changed.questions[0].qtype = QueryType::AAAA;
                            let rendered = prepared
                                .render(&changed, &[17, 15, 15], 1232, true)
                                .unwrap();
                            assert!(rendered.matches_request(&changed));
                            let mut expected =
                                expected(&changed, &answers, &authorities, authenticated);
                            expected.headers.rcode = RCode::NameError;
                            assert_eq!(rendered.as_bytes(), expected.into_wire().unwrap());
                        }
                        let before = encoded.as_bytes().to_vec();
                        // Keep the existing checked NS-append prohibition for
                        // nonempty Answers; NS is validated during construction.
                        assert!(!encoded.append_name_servers(std::slice::from_ref(&ns)));
                        assert_eq!(encoded.as_bytes(), before);
                        let oversized = EncodedReply::recursive_negative(
                            &request,
                            &answers,
                            &authorities,
                            name_error,
                            authenticated,
                            40,
                        )
                        .unwrap()
                        .unwrap();
                        assert!(oversized.as_bytes().len() > 40);
                        assert_eq!(oversized.as_bytes(), before);
                    }
                }
            }
        }
    }
}

#[test]
fn borrowed_recursive_negative_rejects_wrong_scope_cycles_and_effective_rrset_ttls() {
    let request = query();
    let (alias, soa) = cross_zone_negative_components();
    let mut wrong_scope = soa.clone();
    wrong_scope.name = name("example.test.");
    assert!(
        EncodedReply::recursive_negative(
            &request,
            &[(&alias, 20)],
            &[(&wrong_scope, 15)],
            true,
            false,
            1232
        )
        .is_err()
    );
    assert!(
        EncodedReply::recursive_negative(
            &request,
            &[(&alias, 20)],
            &[(&soa, 31)],
            true,
            false,
            1232
        )
        .is_err()
    );
    let mut disconnected = alias.clone();
    disconnected.name = name("disconnected.example.test.");
    assert!(
        EncodedReply::recursive_negative(
            &request,
            &[(&alias, 20), (&disconnected, 20)],
            &[(&soa, 15)],
            true,
            false,
            1232
        )
        .is_err()
    );
    let cycle = ResourceRecord {
        name: name("missing.other.test."),
        rdata: RData::CNAME(request.questions[0].qname.clone()),
        ..alias.clone()
    };
    assert!(
        EncodedReply::recursive_negative(
            &request,
            &[(&alias, 20), (&cycle, 20)],
            &[(&soa, 15)],
            true,
            false,
            1232
        )
        .is_err()
    );
    let first_ns = ResourceRecord {
        name: name("other.test."),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 30,
        rdata: RData::NS(name("ns1.other.test.")),
    };
    let second_ns = ResourceRecord {
        rdata: RData::NS(name("ns2.other.test.")),
        ..first_ns.clone()
    };
    assert!(
        EncodedReply::recursive_negative(
            &request,
            &[(&alias, 20)],
            &[(&soa, 15), (&first_ns, 10), (&second_ns, 11)],
            true,
            false,
            1232
        )
        .is_err()
    );
}
