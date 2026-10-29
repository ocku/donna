use super::*;
use crate::{ClassType, DomainName, QClassType, QueryType, RData, RecordType};

fn name(value: &str) -> crate::DomainName {
    DomainName::from_dotted(value).unwrap()
}

pub(super) fn record(last_octet: u8) -> ResourceRecord {
    ResourceRecord {
        name: name("host.local"),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
    }
}

#[test]
fn packet_round_trip_preserves_qu_and_cache_flush() {
    let packet = MdnsPacket {
        headers: Headers {
            qr: true,
            aa: true,
            ..Headers::default()
        },
        questions: vec![MdnsQuestion {
            question: Question {
                qname: name("host.local"),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            },
            unicast_response: true,
        }],
        answers: vec![MdnsRecord {
            record: record(1),
            cache_flush: true,
        }],
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let wire = packet.into_wire().unwrap();
    let decoded = MdnsPacket::from_datagram(
        &wire,
        SocketAddr::from(([192, 0, 2, 1], MDNS_PORT)),
        SocketAddr::from((MDNS_IPV4_GROUP, MDNS_PORT)),
        MDNS_HOP_LIMIT,
    )
    .unwrap();
    assert!(decoded.questions[0].unicast_response);
    assert!(decoded.answers[0].cache_flush);
    assert!(decoded.answers[0].record.eq_dns(&record(1)));
}

#[test]
fn rejects_off_link_datagrams() {
    let packet = MdnsPacket {
        headers: Headers::default(),
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    assert!(matches!(
        MdnsPacket::from_datagram(
            &packet.into_wire().unwrap(),
            SocketAddr::from(([192, 0, 2, 1], MDNS_PORT)),
            SocketAddr::from((MDNS_IPV4_GROUP, MDNS_PORT)),
            64,
        ),
        Err(MdnsError::InvalidHopLimit(64))
    ));
}

#[test]
fn accepts_truncated_query_sequences_and_ignores_received_id() {
    let packet = MdnsPacket {
        headers: Headers {
            tc: true,
            ..Headers::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let mut wire = packet.into_wire().unwrap();
    wire[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    let decoded = MdnsPacket::from_datagram(
        &wire,
        SocketAddr::from(([192, 0, 2, 1], MDNS_PORT)),
        SocketAddr::from((MDNS_IPV4_GROUP, MDNS_PORT)),
        MDNS_HOP_LIMIT,
    )
    .unwrap();
    assert!(decoded.headers.tc);
    assert_eq!(decoded.headers.id, 0x1234);
}

#[test]
fn receives_ignored_flags_but_rejects_authoring_them() {
    // RD, RA, Z, AD, CD, and all five together (RFC 6762 sections 18.6-18.10).
    for flags in [0x0100_u16, 0x0080, 0x0040, 0x0020, 0x0010, 0x01f0] {
        for response in [false, true] {
            let mut packet = MdnsPacket {
                headers: Headers {
                    qr: response,
                    aa: response,
                    ..Headers::default()
                },
                questions: vec![MdnsQuestion {
                    question: Question {
                        qname: name("host.local"),
                        qtype: QueryType::A,
                        qclass: QClassType::Class(ClassType::IN),
                    },
                    unicast_response: false,
                }],
                answers: if response {
                    vec![MdnsRecord {
                        record: record(1),
                        cache_flush: true,
                    }]
                } else {
                    Vec::new()
                },
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let mut wire = packet.into_wire().unwrap();
            let original_flags = u16::from_be_bytes([wire[2], wire[3]]);
            wire[2..4].copy_from_slice(&(original_flags | flags).to_be_bytes());
            let decoded = MdnsPacket::from_datagram(
                &wire,
                SocketAddr::from(([192, 0, 2, 1], MDNS_PORT)),
                SocketAddr::from((MDNS_IPV4_GROUP, MDNS_PORT)),
                MDNS_HOP_LIMIT,
            )
            .unwrap();
            assert_eq!(decoded.headers.qr, response);
            assert!(
                decoded.questions[0]
                    .question
                    .qname
                    .eq_dns(&name("host.local"))
            );
            assert_eq!(decoded.answers.len(), usize::from(response));
            assert_eq!(decoded.headers.rd, flags & 0x0100 != 0);
            assert_eq!(decoded.headers.ra, flags & 0x0080 != 0);
            assert_eq!(decoded.headers.ad, flags & 0x0020 != 0);
            assert_eq!(decoded.headers.cd, flags & 0x0010 != 0);

            packet.headers = decoded.headers;
            if flags == 0x0040 {
                // Headers cannot represent Z; authoring always clears it.
                assert_eq!(packet.into_wire().unwrap()[3] & 0x40, 0);
            } else {
                assert!(matches!(packet.into_wire(), Err(MdnsError::InvalidHeaders)));
            }
        }
    }
}

#[test]
fn cache_flush_uses_a_one_second_grace_and_goodbyes_expire() {
    let now = Instant::now();
    let mut cache = MdnsCache::new(4);
    cache.insert_packet(
        &[MdnsRecord {
            record: record(1),
            cache_flush: true,
        }],
        now,
    );
    cache.insert_packet(
        &[MdnsRecord {
            record: record(2),
            cache_flush: true,
        }],
        now + Duration::from_secs(2),
    );
    assert_eq!(cache.records(now + Duration::from_secs(2)).len(), 2);
    assert_eq!(cache.records(now + Duration::from_secs(4)).len(), 1);

    let mut goodbye = record(2);
    goodbye.ttl = 0;
    cache.insert_packet(
        &[MdnsRecord {
            record: goodbye,
            cache_flush: true,
        }],
        now + Duration::from_secs(4),
    );
    assert_eq!(cache.records(now + Duration::from_millis(4_500)).len(), 1);
    assert!(cache.records(now + Duration::from_secs(6)).is_empty());
}

#[test]
fn cache_flush_preserves_records_from_the_same_packet_burst() {
    let now = Instant::now();
    let mut cache = MdnsCache::new(4);
    cache.insert_packet(
        &[MdnsRecord {
            record: record(1),
            cache_flush: true,
        }],
        now,
    );
    cache.insert_packet(
        &[MdnsRecord {
            record: record(2),
            cache_flush: true,
        }],
        now + Duration::from_millis(500),
    );
    assert_eq!(cache.records(now + Duration::from_secs(2)).len(), 2);
}

#[test]
fn suppresses_only_known_answers_with_at_least_half_the_ttl() {
    let candidate = record(1);
    let mut known = candidate.clone();
    known.ttl = 60;
    assert!(known_answer_suppresses(&candidate, &known));
    known.ttl = 59;
    assert!(!known_answer_suppresses(&candidate, &known));
    assert!(is_local_name(&candidate.name));
}

#[test]
fn duplicate_questions_are_suppressed_for_one_second() {
    let now = Instant::now();
    let question = Question {
        qname: name("host.local"),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    };
    let mut cache = MdnsDuplicateQuestionCache::new(2);
    assert!(!cache.observe(&question, now));
    assert!(cache.observe(&question, now + Duration::from_millis(999)));
    assert!(!cache.observe(&question, now + Duration::from_secs(1)));
}
