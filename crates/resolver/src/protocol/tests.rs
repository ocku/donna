use std::net::{Ipv4Addr, Ipv6Addr};

use dns::{Headers, OpCode, QClassType, QueryType, RCode, RecordType};

use super::*;

fn name(labels: &[&str]) -> DomainName {
    DomainName::from_labels(
        labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

#[test]
fn iterative_queries_advertise_the_configured_edns_zero_payload() {
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };

    let request = query(42, &question, 1232);
    let edns = request.edns().unwrap().unwrap();

    assert_eq!(edns.version, Edns::VERSION);
    assert_eq!(edns.udp_payload_size, 1232);
    assert_eq!(edns.extended_rcode, 0);
    assert!(edns.options.is_empty());
    assert!(request.headers.cd);
}

#[test]
fn mixed_referral_uses_exact_ns_addresses_but_trusts_only_in_bailiwick_glue() {
    let zone = name(&["example"]);
    let in_bailiwick = name(&["ns", "example"]);
    let out_of_bailiwick = name(&["ns", "provider"]);
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let record = |owner: DomainName, address| ResourceRecord {
        name: owner,
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(address),
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![
            ResourceRecord {
                name: zone.clone(),
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NS(in_bailiwick.clone()),
            },
            ResourceRecord {
                name: zone,
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NS(out_of_bailiwick.clone()),
            },
        ],
        additionals: vec![
            record(in_bailiwick.clone(), Ipv4Addr::new(192, 0, 2, 1)),
            ResourceRecord {
                name: in_bailiwick.clone(),
                rtype: RecordType::AAAA,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::AAAA(Ipv6Addr::LOCALHOST),
            },
            record(out_of_bailiwick.clone(), Ipv4Addr::new(192, 0, 2, 2)),
        ],
    };

    let referral = referral(&reply, &question).unwrap();
    let in_bailiwick_v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53));
    let in_bailiwick_v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 53));
    let out_of_bailiwick_address = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 53));
    let mut expected = vec![in_bailiwick_v4, in_bailiwick_v6, out_of_bailiwick_address];
    expected.sort_unstable();
    assert_eq!(referral.candidates, expected);
    assert_eq!(referral.trusted_glue.len(), 2);
    assert!(
        referral
            .trusted_glue
            .iter()
            .all(|record| record.name.eq_dns(&in_bailiwick))
    );
    let matching = referral.matching_glue(&Question {
        qname: in_bailiwick.clone(),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    });
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].rtype, RecordType::A);
    assert_eq!(referral.candidate_ttls.len(), 2);
    assert!(
        referral
            .candidate_ttls
            .iter()
            .all(|(candidate, _)| *candidate != out_of_bailiwick_address)
    );
    assert_eq!(referral.name_servers.len(), 2);
    assert!(
        referral
            .name_servers
            .iter()
            .any(|name| name.eq_dns(&in_bailiwick))
    );
    assert!(
        referral
            .name_servers
            .iter()
            .any(|name| name.eq_dns(&out_of_bailiwick))
    );
}

#[test]
fn out_of_bailiwick_ns_addresses_are_provisional_candidates_only() {
    let zone = name(&["victim", "example"]);
    let name_server = name(&["ns", "provider"]);
    let question = Question {
        qname: name(&["www", "victim", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: zone,
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name_server.clone()),
        }],
        additionals: vec![
            ResourceRecord {
                name: name_server.clone(),
                rtype: RecordType::A,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::A(Ipv4Addr::new(198, 51, 100, 53)),
            },
            ResourceRecord {
                name: name_server.clone(),
                rtype: RecordType::AAAA,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::AAAA(Ipv6Addr::LOCALHOST),
            },
        ],
    };

    let referral = referral(&reply, &question).unwrap();

    let mut expected = vec![
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 53), 53)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
    ];
    expected.sort_unstable();
    assert_eq!(referral.candidates, expected);
    assert!(referral.trusted_glue.is_empty());
    assert!(referral.candidate_ttls.is_empty());
    assert!(
        referral
            .matching_glue(&Question {
                qname: name_server.clone(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            })
            .is_empty()
    );
    assert_eq!(referral.name_servers, [name_server]);
}

#[test]
fn provisional_candidates_require_exact_in_class_address_records() {
    let zone = name(&["com"]);
    let name_server = name(&["a", "gtld-servers", "net"]);
    let question = Question {
        qname: name(&["www", "example", "com"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let wrong_class = ResourceRecord {
        name: name_server.clone(),
        rtype: RecordType::A,
        class: ClassType::CH,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    };
    let wrong_type = ResourceRecord {
        name: name_server.clone(),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["other", "example"])),
    };
    let unrelated = ResourceRecord {
        name: name(&["unrelated", "net"]),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: zone,
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name_server),
        }],
        additionals: vec![wrong_class, wrong_type, unrelated],
    };

    let referral = referral(&reply, &question).unwrap();
    assert!(referral.candidates.is_empty());
    assert!(referral.candidate_ttls.is_empty());
    assert!(referral.trusted_glue.is_empty());
}

#[test]
fn ignores_additional_records_not_matching_a_delegated_name_server() {
    let zone = name(&["example"]);
    let name_server = name(&["ns", "example"]);
    let unrelated = name(&["host", "provider"]);
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: zone,
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name_server),
        }],
        additionals: vec![ResourceRecord {
            name: unrelated,
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 9)),
        }],
    };

    let referral = referral(&reply, &question).unwrap();
    assert!(referral.candidates.is_empty());
    assert!(referral.candidate_ttls.is_empty());
    assert_eq!(referral.name_servers.len(), 1);
}

fn usable_reply(id: u16, question: &Question) -> Message {
    Message {
        headers: Headers {
            id,
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

#[test]
fn accepts_only_responses_matching_the_outstanding_query() {
    // RFC 1035 §7.3: check the header for reasonableness, then match the
    // response to the outstanding request via ID and question section.
    let query = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    assert!(is_usable_response(&usable_reply(7, &query), 7, &query));

    // A datagram that is itself a query is discarded.
    let mut reply = usable_reply(7, &query);
    reply.headers.qr = false;
    assert!(!is_usable_response(&reply, 7, &query));

    // A truncated response is never usable; only its TCP retry is.
    let mut reply = usable_reply(7, &query);
    reply.headers.tc = true;
    assert!(!is_usable_response(&reply, 7, &query));

    // The response must answer a standard query.
    let mut reply = usable_reply(7, &query);
    reply.headers.opcode = OpCode::IQuery;
    assert!(!is_usable_response(&reply, 7, &query));

    // A stale or foreign transaction ID does not match.
    assert!(!is_usable_response(&usable_reply(8, &query), 7, &query));

    // The echoed question must match in name, type, and class.
    let mut reply = usable_reply(7, &query);
    reply.questions[0].qname = name(&["other", "example"]);
    assert!(!is_usable_response(&reply, 7, &query));
    let mut reply = usable_reply(7, &query);
    reply.questions[0].qtype = QueryType::TXT;
    assert!(!is_usable_response(&reply, 7, &query));
    let mut reply = usable_reply(7, &query);
    reply.questions[0].qclass = QClassType::Class(ClassType::CH);
    assert!(!is_usable_response(&reply, 7, &query));
}

#[test]
fn picks_the_closest_zone_cut_from_a_multi_cut_referral() {
    let parent = name(&["example"]);
    let child = name(&["child", "example"]);
    let question = Question {
        qname: name(&["www", "child", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let reply = Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: vec![
            ResourceRecord {
                name: parent,
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NS(name(&["ns", "provider"])),
            },
            ResourceRecord {
                name: child.clone(),
                rtype: RecordType::NS,
                class: ClassType::IN,
                ttl: 60,
                rdata: RData::NS(name(&["ns", "child", "example"])),
            },
        ],
        additionals: vec![ResourceRecord {
            name: name(&["ns", "child", "example"]),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }],
    };

    let referral = referral(&reply, &question).unwrap();

    assert!(referral.zone.eq_dns(&child));
    assert_eq!(
        referral.candidates,
        [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 53))]
    );
}

#[test]
fn rejects_type_one_nodata_as_a_referral() {
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut reply = referral_response_for_test(&question);
    reply.authorities.push(ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: name(&["ns", "example"]),
            rname: name(&["hostmaster", "example"]),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 30,
        },
    });

    assert!(referral(&reply, &question).is_none());
}

fn referral_response_for_test(question: &Question) -> Message {
    Message {
        headers: Headers {
            qr: true,
            ..Headers::default()
        },
        questions: vec![question.clone()],
        answers: Vec::new(),
        authorities: vec![ResourceRecord {
            name: name(&["example"]),
            rtype: RecordType::NS,
            class: ClassType::IN,
            ttl: 60,
            rdata: RData::NS(name(&["ns", "example"])),
        }],
        additionals: Vec::new(),
    }
}

#[test]
fn rejects_authoritative_no_data_answers_and_failures_as_referrals() {
    let question = Question {
        qname: name(&["www", "example"]),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let authority = ResourceRecord {
        name: name(&["example"]),
        rtype: RecordType::NS,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::NS(name(&["ns", "example"])),
    };

    // An authoritative no-data answer carries NS RRs for the current zone;
    // replacing the SLIST with them would loop forever.
    let mut reply = usable_reply(1, &question);
    reply.headers.aa = true;
    reply.authorities = vec![authority.clone()];
    assert!(referral(&reply, &question).is_none());

    // Only NOERROR responses delegate; a failure must not revise the SLIST.
    let mut reply = usable_reply(1, &question);
    reply.headers.rcode = RCode::ServerFailure;
    reply.authorities = vec![authority];
    assert!(referral(&reply, &question).is_none());
}
