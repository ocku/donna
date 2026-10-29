use super::*;

#[test]
fn borrowed_cname_negative_matches_structured_flags_ttls_and_implicit_ns() {
    let peer = "127.0.0.1:1234".parse().unwrap();
    for validating in [false, true] {
        for alias_secure in [false, true] {
            for terminal_secure in [false, true] {
                for rcode in [RCode::Ok, RCode::NameError] {
                    let resolver = configured(validating);
                    let q = question(QueryType::A);
                    let alias = Question {
                        qtype: QueryType::CNAME,
                        ..q.clone()
                    };
                    let terminal = Question {
                        qname: name(&["target", "example"]),
                        ..q.clone()
                    };
                    let mut first = cname(&alias, true);
                    first.headers.ad = alias_secure;
                    first.answers[0].ttl = 7;
                    resolver.cache_positive_entries(1, &first, &alias);
                    let mut last = negative(&terminal, rcode, true);
                    last.headers.ad = terminal_secure;
                    resolver.cache_response_entries(1, &last, &terminal, &terminal, true);
                    resolver.delegation_cache.insert(
                        &crate::protocol::Referral {
                            zone: name(&["example"]),
                            class: ClassType::IN,
                            candidates: vec![],
                            candidate_ttls: vec![],
                            trusted_glue: vec![],
                            name_servers: vec![name(&["ns", "example"])],
                            ttl: Duration::from_secs(60),
                        },
                        Duration::from_secs(60),
                    );
                    let server = RecursiveServer::with_resolver(resolver);
                    let warm = client_request(q.clone(), 1232, false);
                    // Cross the preparation threshold so the flag matrix also
                    // verifies prepared slots, rather than only early borrowing.
                    for _ in 0..crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS {
                        server.try_handle_udp(&warm, &[], peer, 1232).unwrap();
                    }
                    for format in ["classic", "edns", "edns-do"] {
                        for cd in [false, true] {
                            for ad in [false, true] {
                                let mut request =
                                    client_request(q.clone(), 1232, format == "edns-do");
                                request.headers.cd = cd;
                                request.headers.ad = ad;
                                if format == "classic" {
                                    request.additionals.clear();
                                }
                                let ordinary = server
                                    .try_handle(
                                        &request,
                                        &[],
                                        peer,
                                        transport::TransportProtocol::Udp,
                                    )
                                    .unwrap();
                                let ImmediateUdpResponse::Encoded(encoded) =
                                    server.try_handle_udp(&request, &[], peer, 1232).unwrap()
                                else {
                                    panic!(
                                        "small selected CNAME-negative should borrow its records"
                                    );
                                };
                                assert!(encoded.matches_request(&request));
                                let actual = encoded.into_message().unwrap();
                                assert_eq!(actual.headers.rcode, rcode);
                                assert_eq!(actual.answers.len(), 1);
                                assert!(actual.answers[0].ttl <= 7);
                                assert!(
                                    actual
                                        .authorities
                                        .iter()
                                        .any(|rr| rr.rtype == RecordType::SOA && rr.ttl > 7)
                                );
                                if actual.headers.ad {
                                    assert!(
                                        actual
                                            .authorities
                                            .iter()
                                            .all(|rr| rr.rtype != RecordType::NS)
                                    );
                                }
                                assert_eq!(normalize(actual), normalize(ordinary));
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn borrowed_cname_negative_uses_current_delegation_and_same_entry_fallback() {
    let resolver = configured(false);
    let q = question(QueryType::A);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..q.clone()
    };
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..q.clone()
    };
    resolver.cache_positive_entries(1, &cname(&alias, true), &alias);
    resolver.cache_response_entries(
        1,
        &negative(&terminal, RCode::NameError, true),
        &terminal,
        &terminal,
        true,
    );
    for label in ["old", "new"] {
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: name(&["example"]),
                class: ClassType::IN,
                candidates: vec![],
                candidate_ttls: vec![],
                trusted_glue: vec![],
                name_servers: vec![name(&[label, "example"])],
                ttl: Duration::from_secs(60),
            },
            Duration::from_secs(60),
        );
        for unsupported_options in (0..crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS + 2)
            .map(|_| false)
            .chain([true])
        {
            let mut request = client_request(q.clone(), 1232, true);
            if unsupported_options {
                request.additionals[0] = Edns {
                    dnssec_ok: true,
                    options: vec![dns::EdnsOption {
                        code: 65001,
                        data: vec![1],
                    }],
                    ..Edns::new(1232)
                }
                .into_record();
            }
            let (actual, encoded) = unwrap_reply(
                resolver
                    .try_resolve_cached_udp(&request, 1232)
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(encoded, !unsupported_options);
            let ns: Vec<_> = actual
                .authorities
                .iter()
                .filter(|rr| rr.rtype == RecordType::NS)
                .collect();
            assert_eq!(ns.len(), 1);
            assert_eq!(ns[0].rdata, RData::NS(name(&[label, "example"])));
            assert_eq!(actual.answers.len(), 1);
            assert_eq!(actual.headers.rcode, RCode::NameError);
        }
    }
}

#[test]
fn composed_negative_rechecks_replaced_alias_trust_and_ttl() {
    let resolver = configured(true);
    let q = question(QueryType::A);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..q.clone()
    };
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..q.clone()
    };
    let mut last = negative(&terminal, RCode::NameError, true);
    last.headers.ad = true;
    resolver.cache_response_entries(1, &last, &terminal, &terminal, true);
    // Popularity comes from ordinary selections, with no extra lookup/touch
    // added by the encoded path. Warm before testing slot replacement.
    let mut first = cname(&alias, true);
    first.headers.ad = true;
    resolver.cache_positive_entries(1, &first, &alias);
    for _ in 0..crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS {
        let request = client_request(q.clone(), 1232, true);
        assert!(
            resolver
                .try_resolve_cached_udp(&request, 1232)
                .unwrap()
                .is_some()
        );
    }
    for (secure, ttl) in [(true, 60), (false, 2), (true, 30)] {
        let mut first = cname(&alias, true);
        first.headers.ad = secure;
        first.answers[0].ttl = ttl;
        resolver.cache_positive_entries(1, &first, &alias);
        // Include the early borrowed replies, the popularity-gated preparation,
        // and subsequent template renders for each replacement identity.
        for _ in 0..crate::cache::store::NEGATIVE_COMPOSITION_MIN_HITS + 2 {
            let request = client_request(q.clone(), 1232, true);
            let (actual, encoded) = unwrap_reply(
                resolver
                    .try_resolve_cached_udp(&request, 1232)
                    .unwrap()
                    .unwrap(),
            );
            assert!(encoded);
            assert_eq!(actual.headers.ad, secure);
            assert_eq!(actual.headers.rcode, RCode::NameError);
            assert_eq!(actual.answers.len(), 1);
            assert!(actual.answers[0].ttl <= ttl);
            assert_eq!(
                actual.answers[0].rdata,
                RData::CNAME(terminal.qname.clone())
            );
        }
    }
}
