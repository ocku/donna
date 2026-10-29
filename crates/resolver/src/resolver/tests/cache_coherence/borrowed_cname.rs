use super::*;
use crate::RecursiveServer;
use dns::{Edns, IntoWire};
use transport::{DnsRequestHandler, ImmediateUdpResponse, TransportProtocol};

fn request(q: Question) -> Message {
    Message::builder()
        .headers(Headers {
            id: 123,
            rd: true,
            ..Headers::default()
        })
        .questions([q])
        .additionals([Edns {
            dnssec_ok: true,
            ..Edns::new(1232)
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

#[test]
fn borrowed_cached_chain_preserves_independent_ttls_and_original_question() {
    let resolver = new_resolver();
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
    first.answers[0].ttl = 7;
    let mut last = address(&terminal, true);
    last.answers[0].ttl = 41;
    resolver.cache_positive_entries(1, &first, &alias);
    resolver.cache_positive_entries(1, &last, &terminal);
    let server = RecursiveServer::with_resolver(resolver);
    let request = request(q);
    let peer = "127.0.0.1:1234".parse().unwrap();
    let normal = server
        .try_handle(&request, &[], peer, TransportProtocol::Udp)
        .unwrap();
    let ImmediateUdpResponse::Encoded(encoded) =
        server.try_handle_udp(&request, &[], peer, 1232).unwrap()
    else {
        panic!("complete cached chain should encode borrowed components");
    };
    assert!(encoded.matches_request(&request));
    let reply = encoded.into_message().unwrap();
    assert_eq!(
        reply.questions[0].qname.as_ref(),
        request.questions[0].qname.as_ref()
    );
    assert!(reply.answers[0].ttl <= 7);
    assert!(reply.answers[1].ttl > 7 && reply.answers[1].ttl <= 41);
    assert_eq!(normalize(reply), normalize(normal));
}

#[test]
fn borrowed_cached_chain_touches_each_component_exactly_once() {
    for terminal_first in [false, true] {
        let resolver = Resolver::new(
            UnusedTransport,
            ResolverConfig {
                cache_capacity: 3,
                ..ResolverConfig::default()
            },
        );
        let q = question(QueryType::A);
        let alias = Question {
            qtype: QueryType::CNAME,
            ..q.clone()
        };
        let terminal = Question {
            qname: name(&["target", "example"]),
            ..q.clone()
        };
        let sentinel = Question {
            qname: name(&["sentinel", "example"]),
            ..q.clone()
        };
        if terminal_first {
            resolver.cache_positive_entries(1, &address(&terminal, true), &terminal);
        }
        resolver.cache_positive_entries(1, &cname(&alias, true), &alias);
        if !terminal_first {
            resolver.cache_positive_entries(1, &address(&terminal, true), &terminal);
        }
        resolver.cache_positive_entries(1, &address(&sentinel, true), &sentinel);
        assert!(resolver.cached_positive_response(&sentinel).is_some());
        assert!(matches!(
            resolver
                .try_resolve_cached_udp(&request(q.clone()), 1232)
                .unwrap(),
            Some(ImmediateUdpResponse::Encoded(_))
        ));
        let newcomer = Question {
            qname: name(&["new", "example"]),
            ..q
        };
        resolver.cache_positive_entries(1, &address(&newcomer, true), &newcomer);
        // All three old entries should now have one hit. Tie-breaking must
        // remove the earlier component in either insertion order.
        let (earlier, later) = if terminal_first {
            (&terminal, &alias)
        } else {
            (&alias, &terminal)
        };
        assert!(resolver.cached_positive_response(earlier).is_none());
        assert!(resolver.cached_positive_response(later).is_some());
        assert!(resolver.cached_positive_response(&sentinel).is_some());
    }
}

#[test]
fn borrowed_chain_keeps_complete_oversized_rrset_for_normal_transport_truncation() {
    let resolver = new_resolver();
    let q = question(QueryType::TXT);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..q.clone()
    };
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..q.clone()
    };
    resolver.cache_positive_entries(1, &cname(&alias, true), &alias);
    let mut reply = text(&terminal, true);
    reply.answers = (0..8)
        .map(|n| ResourceRecord {
            name: terminal.qname.clone(),
            rtype: RecordType::TXT,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::TXT(vec![vec![n; 200]]),
        })
        .collect();
    resolver.cache_positive_entries(1, &reply, &terminal);
    let server = RecursiveServer::with_resolver(resolver);
    let request = request(q);
    let peer = "127.0.0.1:1234".parse().unwrap();
    let normal = server
        .try_handle(&request, &[], peer, TransportProtocol::Udp)
        .unwrap();
    let ImmediateUdpResponse::Encoded(encoded) =
        server.try_handle_udp(&request, &[], peer, 512).unwrap()
    else {
        panic!("expected borrowed encoding");
    };
    assert!(encoded.as_bytes().len() > 512);
    let reply = encoded.into_message().unwrap();
    assert_eq!(reply.answers.len(), 9);
    assert!(!reply.headers.tc);
    assert_eq!(normalize(reply), normalize(normal));
}

#[test]
fn borrowed_cached_chain_spills_inline_storage_without_a_new_hop_limit() {
    let resolver = new_resolver();
    let q = question(QueryType::A);
    let mut current = q.qname.clone();
    let mut expected = Vec::new();
    for n in 0..9 {
        let alias = Question {
            qname: current.clone(),
            qtype: QueryType::CNAME,
            ..q.clone()
        };
        let target = DomainName::from_dotted(&format!("hop{n}.example.")).unwrap();
        let reply = positive(
            &alias,
            RecordType::CNAME,
            RData::CNAME(target.clone()),
            true,
        );
        resolver.cache_positive_entries(1, &reply, &alias);
        expected.push(current);
        current = target;
    }
    let terminal = Question {
        qname: current.clone(),
        ..q.clone()
    };
    resolver.cache_positive_entries(1, &address(&terminal, true), &terminal);
    expected.push(current);
    let Some(ImmediateUdpResponse::Encoded(encoded)) =
        resolver.try_resolve_cached_udp(&request(q), 1232).unwrap()
    else {
        panic!("expected complete long cached chain");
    };
    let response = encoded.into_message().unwrap();
    assert_eq!(response.answers.len(), 10);
    for (answer, expected) in response.answers.iter().zip(expected) {
        assert_eq!(answer.name, expected);
    }
}

#[test]
fn borrowed_wildcard_chain_matches_original_authority_merge_order_and_minimum_ttl() {
    fn sig(owner: DomainName, covered: u16, labels: u8, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: owner,
            rtype: RecordType::RRSIG,
            class: ClassType::IN,
            ttl,
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
    let resolver = new_resolver();
    let q = question(QueryType::A);
    let alias = Question {
        qtype: QueryType::CNAME,
        ..q.clone()
    };
    let terminal = Question {
        qname: name(&["target", "example"]),
        ..q.clone()
    };
    for (alias_entry, proof_owner, ttl) in
        [(true, "proof.example.", 7), (false, "PrOoF.Example.", 41)]
    {
        let query = if alias_entry { &alias } else { &terminal };
        let mut reply = if alias_entry {
            cname(query, true)
        } else {
            address(query, true)
        };
        reply.answers[0].ttl = ttl;
        reply.answers.push(sig(
            query.qname.clone(),
            if alias_entry { 5 } else { 1 },
            1,
            ttl,
        ));
        let owner = DomainName::from_dotted(proof_owner).unwrap();
        reply.authorities = vec![
            ResourceRecord {
                name: owner.clone(),
                rtype: RecordType::NSEC,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NSEC(dns::Nsec {
                    next_domain_name: name(&["z", "example"]),
                    type_bitmap: dns::TypeBitmap::new([1, 46, 47]).unwrap(),
                }),
            },
            sig(owner, 47, 2, 60),
        ];
        resolver.cache_positive_entries(1, &reply, query);
    }
    let first = resolver.cached_positive_response(&alias).unwrap();
    let last = resolver.cached_positive_response(&terminal).unwrap();
    let (chain, _) = crate::response::cname_restart(&first.answers, &q)
        .unwrap()
        .unwrap();
    let proofs = crate::response::wildcard_proofs(&first, &chain);
    let mut original = crate::response::complete_cname_response(last, &q, chain, proofs);
    original.headers.id = 123;
    original.headers.rd = true;
    original.headers.ra = true;
    original.additionals.push(
        Edns {
            dnssec_ok: true,
            ..Edns::default()
        }
        .into_record(),
    );
    let Some(ImmediateUdpResponse::Encoded(encoded)) =
        resolver.try_resolve_cached_udp(&request(q), 1232).unwrap()
    else {
        panic!("expected borrowed wildcard chain");
    };
    let response = encoded.into_message().unwrap();
    assert_eq!(response.authorities.len(), 2);
    assert_eq!(response.authorities[0].name.as_ref()[0], b"PrOoF");
    assert!(response.authorities.iter().all(|rr| rr.ttl <= 7));
    assert_eq!(normalize(response), normalize(original));
}

#[test]
fn composed_cached_reply_rechecks_terminal_identity_and_client_policy() {
    let resolver = new_resolver();
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
    let mut last = address(&terminal, true);
    resolver.cache_positive_entries(1, &last, &terminal);
    for generation in 1..=2 {
        if generation == 2 {
            last.answers[0].rdata = RData::A("192.0.2.222".parse().unwrap());
            resolver.cache_positive_entries(1, &last, &terminal);
        }
        for classic in [false, true] {
            for dnssec_ok in [false, true] {
                if classic && dnssec_ok {
                    continue;
                }
                for cd in [false, true] {
                    for ad in [false, true] {
                        for repeat in 0..3 {
                            let mut request = request(q.clone());
                            request.headers.id += repeat;
                            request.headers.cd = cd;
                            request.headers.ad = ad;
                            request.additionals[0].ttl = if dnssec_ok { 0x8000 } else { 0 };
                            if classic {
                                request.additionals.clear();
                            }
                            let Some(ImmediateUdpResponse::Encoded(encoded)) =
                                resolver.try_resolve_cached_udp(&request, 1232).unwrap()
                            else {
                                panic!("expected encoded CNAME response")
                            };
                            assert!(encoded.matches_request(&request));
                            let message = encoded.into_message().unwrap();
                            assert_eq!(message.headers.id, request.headers.id);
                            assert_eq!(message.headers.cd, cd);
                            assert!(!message.headers.ad);
                            assert_eq!(message.answers.len(), 2);
                            assert_eq!(message.answers[1].rdata, last.answers[0].rdata);
                            assert_eq!(message.additionals.is_empty(), classic);
                        }
                    }
                }
            }
        }
    }
}
