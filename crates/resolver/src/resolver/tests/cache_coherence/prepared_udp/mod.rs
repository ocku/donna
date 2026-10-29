use super::*;
use crate::RecursiveServer;
use dns::{Edns, IntoWire};
use transport::{DnsRequestHandler, ImmediateUdpResponse};

fn client_request(question: Question, payload: u16, do_bit: bool) -> Message {
    Message::builder()
        .headers(Headers {
            id: 123,
            rd: true,
            ..Headers::default()
        })
        .questions([question])
        .additionals([Edns {
            dnssec_ok: do_bit,
            ..Edns::new(payload)
        }
        .into_record()])
        .build()
        .unwrap()
}
fn normalize(mut reply: Message) -> Vec<u8> {
    for record in reply.answers.iter_mut().chain(&mut reply.authorities) {
        record.ttl = 0;
    }
    reply.into_wire().unwrap()
}
fn unwrap_reply(reply: ImmediateUdpResponse) -> (Message, bool) {
    match reply {
        ImmediateUdpResponse::Message(message) => (message, false),
        ImmediateUdpResponse::Encoded(message) => (message.into_message().unwrap(), true),
    }
}
fn configured(validating: bool) -> Resolver<UnusedTransport> {
    Resolver::new(
        UnusedTransport,
        ResolverConfig {
            cache_capacity: 16,
            trust_anchors: if validating {
                vec![ResourceRecord {
                    name: name(&["example"]),
                    rtype: RecordType::DNSKEY,
                    class: ClassType::IN,
                    ttl: 60,
                    rdata: RData::DNSKEY(dns::Dnskey {
                        flags: 257,
                        protocol: 3,
                        algorithm: 15,
                        public_key: vec![0; 32],
                    }),
                }]
            } else {
                vec![]
            },
            ..ResolverConfig::default()
        },
    )
}

#[test]
fn prepared_cached_negative_matches_structured_flags_questions_and_edns() {
    let peer = "127.0.0.1:1234".parse().unwrap();
    for validating in [false, true] {
        for rcode in [RCode::Ok, RCode::NameError] {
            let resolver = configured(validating);
            let q = question(QueryType::A);
            let mut denial = negative(&q, rcode, true);
            denial.headers.ad = true;
            resolver.cache_response_entries(1, &denial, &q, &q, true);
            let server = RecursiveServer::with_resolver(resolver);
            for format in ["classic", "edns", "edns-do"] {
                for bits in 0..16 {
                    let mut request = client_request(q.clone(), 1232, format == "edns-do");
                    if format == "classic" {
                        request.additionals.clear();
                    }
                    request.headers.cd = bits & 2 != 0;
                    request.headers.ad = bits & 4 != 0;
                    if bits & 8 != 0 {
                        request.questions[0].qname = name(&["OWNER", "example"]);
                    }
                    let structured = server
                        .try_handle(&request, &[], peer, transport::TransportProtocol::Udp)
                        .unwrap();
                    let (prepared, encoded) =
                        unwrap_reply(server.try_handle_udp(&request, &[], peer, 1232).unwrap());
                    assert_eq!(
                        normalize(prepared),
                        normalize(structured),
                        "flags={bits}, validating={validating}"
                    );
                    assert_eq!(encoded, bits & 8 == 0);
                }
            }
        }
    }
}

#[test]
fn prepared_negative_resets_on_replacement_and_does_not_hide_a_cname() {
    let resolver = configured(false);
    let q = question(QueryType::A);
    resolver.cache_response_entries(1, &negative(&q, RCode::NameError, true), &q, &q, true);
    let request = client_request(q.clone(), 1232, true);
    let (response, encoded) = unwrap_reply(
        resolver
            .try_resolve_cached_udp(&request, 1232)
            .unwrap()
            .unwrap(),
    );
    assert!(encoded);
    assert_eq!(response.headers.rcode, RCode::NameError);
    resolver.cache_positive_entries(1, &address(&q, true), &q);
    let (response, encoded) = unwrap_reply(
        resolver
            .try_resolve_cached_udp(&request, 1232)
            .unwrap()
            .unwrap(),
    );
    assert!(encoded);
    assert_eq!(response.answers[0].rtype, RecordType::A);
    resolver.cache_response_entries(1, &negative(&q, RCode::Ok, true), &q, &q, true);
    let (response, encoded) = unwrap_reply(
        resolver
            .try_resolve_cached_udp(&request, 1232)
            .unwrap()
            .unwrap(),
    );
    assert!(encoded);
    assert_eq!(response.headers.rcode, RCode::Ok);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..q.clone()
    };
    resolver.cache_positive_entries(1, &cname(&alias, true), &alias);
    assert!(
        resolver
            .try_resolve_cached_udp(&request, 1232)
            .unwrap()
            .is_none()
    );
}

#[test]
fn prepared_cached_positive_matches_structured_flags_questions_and_edns() {
    let peer = "127.0.0.1:1234".parse().unwrap();
    for validating in [false, true] {
        let resolver = configured(validating);
        let q = question(QueryType::A);
        let mut reply = address(&q, true);
        reply.headers.ad = true;
        resolver.cache_positive_entries(1, &reply, &q);
        let server = RecursiveServer::with_resolver(resolver);
        for format in ["classic", "edns", "edns-do"] {
            for bits in 0..16 {
                let mut request = client_request(q.clone(), 1232, format == "edns-do");
                if format == "classic" {
                    request.additionals.clear();
                }
                request.headers.cd = bits & 2 != 0;
                request.headers.ad = bits & 4 != 0;
                if bits & 8 != 0 {
                    request.questions[0].qname = name(&["OWNER", "example"]);
                }
                let structured = server
                    .try_handle(&request, &[], peer, transport::TransportProtocol::Udp)
                    .unwrap();
                let (prepared, encoded) =
                    unwrap_reply(server.try_handle_udp(&request, &[], peer, 1232).unwrap());
                assert_eq!(
                    normalize(prepared),
                    normalize(structured),
                    "flags={bits}, validating={validating}"
                );
                assert_eq!(encoded, bits & 8 == 0);
            }
        }
    }
}

#[test]
fn ordinary_cached_direct_and_cname_replies_preserve_dnssec_filtering_and_ad_policy() {
    fn signature(owner: dns::DomainName, covered: u16, labels: u8) -> ResourceRecord {
        ResourceRecord {
            name: owner,
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::RRSIG(dns::Rrsig {
                type_covered: covered,
                algorithm: 15,
                labels,
                original_ttl: 60,
                signature_expiration: 2000000000,
                signature_inception: 1,
                key_tag: 1,
                signer_name: name(&["example"]),
                signature: vec![7; 64],
            }),
        }
    }
    let proof = ResourceRecord {
        name: name(&["proof", "example"]),
        rtype: RecordType::NSEC,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NSEC(dns::Nsec {
            next_domain_name: name(&["z", "example"]),
            type_bitmap: dns::TypeBitmap::new([1, 46, 47]).unwrap(),
        }),
    };
    let peer = "127.0.0.1:1234".parse().unwrap();
    for validating in [false, true] {
        for alias in [false, true] {
            for qtype in [QueryType::A, QueryType::RRSIG, QueryType::NSEC] {
                let resolver = configured(validating);
                let original = question(qtype);
                let terminal = Question {
                    qname: if alias {
                        name(&["target", "example"])
                    } else {
                        original.qname.clone()
                    },
                    ..original.clone()
                };
                let mut reply = address(&terminal, true);
                reply.headers.ad = true;
                reply.answers = match qtype {
                    QueryType::A => vec![
                        reply.answers.remove(0),
                        signature(terminal.qname.clone(), 1, 1),
                    ],
                    QueryType::RRSIG => vec![signature(terminal.qname.clone(), 1, 1)],
                    QueryType::NSEC => vec![
                        ResourceRecord {
                            name: terminal.qname.clone(),
                            ..proof.clone()
                        },
                        signature(terminal.qname.clone(), 47, 2),
                    ],
                    _ => unreachable!(),
                };
                reply.authorities = vec![proof.clone(), signature(proof.name.clone(), 47, 2)];
                resolver.cache_positive_entries(1, &reply, &terminal);
                if alias {
                    let q = Question {
                        qtype: QueryType::CNAME,
                        ..original.clone()
                    };
                    let mut reply = cname(&q, true);
                    reply.headers.ad = true;
                    reply.answers.push(signature(q.qname.clone(), 5, 1));
                    reply.authorities = vec![proof.clone(), signature(proof.name.clone(), 47, 2)];
                    resolver.cache_positive_entries(1, &reply, &q);
                }
                let server = RecursiveServer::with_resolver(resolver);
                for format in ["classic", "edns", "edns-do"] {
                    for bits in 0..4 {
                        let mut request =
                            client_request(original.clone(), 1232, format == "edns-do");
                        if format == "classic" {
                            request.additionals.clear();
                        }
                        request.headers.ad = bits & 1 != 0;
                        request.headers.cd = bits & 2 != 0;
                        let expected = server
                            .try_handle(&request, &[], peer, transport::TransportProtocol::Udp)
                            .unwrap();
                        let (actual, encoded) =
                            unwrap_reply(server.try_handle_udp(&request, &[], peer, 1232).unwrap());
                        assert!(encoded, "format={format} qtype={qtype:?} alias={alias}");
                        assert_eq!(
                            actual.headers.ad,
                            validating
                                && qtype != QueryType::RRSIG
                                && !request.headers.cd
                                && (request.headers.ad || format == "edns-do")
                        );
                        if format != "edns-do" {
                            for rr in actual.answers.iter().chain(&actual.authorities) {
                                if matches!(
                                    rr.rtype,
                                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                                ) {
                                    assert_eq!(u16::from(rr.rtype), qtype.value());
                                }
                            }
                        }
                        assert_eq!(
                            normalize(actual),
                            normalize(expected),
                            "format={format} qtype={qtype:?} alias={alias}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn prepared_negative_uses_current_implicit_referral_and_preserves_parent_side_ds() {
    for format in ["classic", "edns", "edns-do"] {
        let resolver = configured(false);
        let q = question(QueryType::A);
        resolver.cache_response_entries(1, &negative(&q, RCode::NameError, true), &q, &q, true);
        let mut request = client_request(q.clone(), 1232, format == "edns-do");
        if format == "classic" {
            request.additionals.clear();
        }
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
            let (response, encoded) = unwrap_reply(
                resolver
                    .try_resolve_cached_udp(&request, 1232)
                    .unwrap()
                    .unwrap(),
            );
            assert!(encoded);
            assert!(response.authorities.iter().any(|record|matches!(&record.rdata,RData::NS(target) if target.eq_dns(&name(&[label,"example"])))));
        }
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: q.qname.clone(),
                class: ClassType::IN,
                candidates: vec![],
                candidate_ttls: vec![],
                trusted_glue: vec![],
                name_servers: vec![name(&["child", "example"])],
                ttl: Duration::from_secs(60),
            },
            Duration::from_secs(60),
        );
        let mut ds = request;
        ds.questions[0].qtype = QueryType::DS;
        let (response, encoded) =
            unwrap_reply(resolver.try_resolve_cached_udp(&ds, 1232).unwrap().unwrap());
        assert!(encoded);
        assert!(response.authorities.iter().any(|record|matches!(&record.rdata,RData::NS(target) if target.eq_dns(&name(&["new","example"])))));
        assert!(response.authorities.iter().all(|record|!matches!(&record.rdata,RData::NS(target) if target.eq_dns(&name(&["child","example"])))));
    }
}

#[test]
fn negative_implicit_referral_spill_and_classic_overflow_match_structured_selection() {
    let peer = "127.0.0.1:1234".parse().unwrap();
    for format in ["classic", "edns", "edns-do"] {
        let resolver = configured(false);
        let q = question(QueryType::A);
        resolver.cache_response_entries(1, &negative(&q, RCode::NameError, true), &q, &q, true);
        resolver.delegation_cache.insert(
            &crate::protocol::Referral {
                zone: name(&["example"]),
                class: ClassType::IN,
                candidates: vec![],
                candidate_ttls: vec![],
                trusted_glue: vec![],
                name_servers: (0..9)
                    .map(|index| {
                        name(&[&format!("nameserver-{index}-with-a-long-label"), "example"])
                    })
                    .collect(),
                ttl: Duration::from_secs(60),
            },
            Duration::from_secs(60),
        );
        let server = RecursiveServer::with_resolver(resolver);
        let mut request = client_request(q, 1232, format == "edns-do");
        if format == "classic" {
            request.additionals.clear();
        }
        let structured = server
            .try_handle(&request, &[], peer, transport::TransportProtocol::Udp)
            .unwrap();
        let (prepared, encoded) =
            unwrap_reply(server.try_handle_udp(&request, &[], peer, 4096).unwrap());
        assert_eq!(encoded, format != "classic");
        assert_eq!(
            prepared
                .authorities
                .iter()
                .filter(|rr| rr.rtype == RecordType::NS)
                .count(),
            9
        );
        assert_eq!(normalize(prepared), normalize(structured));
    }
}

mod composed;
