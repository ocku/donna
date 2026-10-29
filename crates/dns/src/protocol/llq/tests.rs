use std::net::Ipv4Addr;

use super::*;
use crate::{ClassType, QClassType, RData, RecordType};

fn question() -> Question {
    Question {
        qname: DomainName::from_dotted("_printer._tcp.example").unwrap(),
        qtype: QueryType::PTR,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn challenge(id: u64, lease: u32) -> LlqOption {
    LlqOption {
        version: LLQ_VERSION,
        opcode: LlqOpcode::Setup,
        response_code: LlqResponseCode::NoError,
        id,
        lease,
    }
}

#[test]
fn option_and_service_owner_round_trip() {
    let value = challenge(0x0102_0304_0506_0708, 7_200);
    assert_eq!(
        LlqOption::from_edns_option(&value.into_edns_option()).unwrap(),
        value
    );
    assert_eq!(
        llq_service_name(&DomainName::from_dotted("example.com").unwrap()).unwrap(),
        DomainName::from_dotted("_dns-llq._udp.example.com").unwrap()
    );
}

#[test]
fn four_way_setup_refresh_event_and_expiry() {
    let start = Instant::now();
    let (mut client, request) = LlqClient::start(question(), 100, start).unwrap();
    assert_eq!(request.id, 0);
    let echo = client
        .accept_challenge(challenge(42, 100), start + Duration::from_secs(1))
        .unwrap()
        .unwrap();
    client
        .accept_setup_ack(echo, start + Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        client.refresh(start + Duration::from_secs(81)).unwrap(),
        None
    );
    let refresh = client
        .refresh(start + Duration::from_secs(82))
        .unwrap()
        .unwrap();
    assert_eq!(refresh.opcode, LlqOpcode::Refresh);
    client
        .accept_refresh_ack(refresh, start + Duration::from_secs(83))
        .unwrap();
    let event = LlqOption {
        opcode: LlqOpcode::Event,
        lease: 0,
        ..challenge(42, 100)
    };
    let ack = client
        .acknowledge_event(0xbeef, event, start + Duration::from_secs(84))
        .unwrap();
    assert_eq!(ack.message_id, 0xbeef);
    assert_eq!(
        client.status(start + Duration::from_secs(183)),
        LlqClientStatus::Expired
    );
}

#[test]
fn retransmission_and_server_full_delay_are_enforced() {
    let start = Instant::now();
    let (mut client, _) = LlqClient::start(question(), 60, start).unwrap();
    assert!(
        client
            .retry_setup(start + Duration::from_secs(1))
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .retry_setup(start + Duration::from_secs(2))
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .retry_setup(start + Duration::from_secs(6))
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .retry_setup(start + Duration::from_secs(14))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client.status(start + Duration::from_secs(14)),
        LlqClientStatus::Failed
    );

    let (mut client, _) = LlqClient::start(question(), 60, start).unwrap();
    let full = LlqOption {
        response_code: LlqResponseCode::ServerFull,
        id: 0,
        lease: 30,
        ..challenge(1, 1)
    };
    client.accept_challenge(full, start).unwrap();
    assert!(matches!(
        client.retry_after_delay(start + Duration::from_secs(29)),
        Err(LlqError::RetryTooEarly)
    ));
    client
        .retry_after_delay(start + Duration::from_secs(30))
        .unwrap();
}

#[test]
fn event_wire_round_trip_preserves_add_and_remove_semantics() {
    let record = ResourceRecord {
        name: DomainName::from_dotted("printer.example").unwrap(),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 10)),
    };
    let option = LlqOption {
        version: LLQ_VERSION,
        opcode: LlqOpcode::Event,
        response_code: LlqResponseCode::NoError,
        id: 42,
        lease: 0,
    };
    let event = LlqEventMessage {
        message_id: 0xbeef,
        questions: vec![question()],
        changes: vec![
            LlqEventChange::Add(record.clone()),
            LlqEventChange::Remove(record),
        ],
        options: vec![option],
    };
    let decoded = LlqEventMessage::from_wire(&event.into_wire().unwrap()).unwrap();
    assert_eq!(decoded.message_id, 0xbeef);
    assert!(matches!(decoded.changes[0], LlqEventChange::Add(_)));
    assert!(matches!(decoded.changes[1], LlqEventChange::Remove(_)));
    let LlqEventChange::Remove(record) = &decoded.changes[1] else {
        unreachable!()
    };
    assert_eq!(record.ttl, 0);
}

#[test]
fn subscriptions_reject_none_any_and_noncanonical_question_aliases() {
    let cases = [
        ("NONE", QueryType::PTR, QClassType::Unknown(254)),
        ("ANY type", QueryType::ANY, QClassType::Class(ClassType::IN)),
        (
            "ANY type alias",
            QueryType::Unknown(255),
            QClassType::Class(ClassType::IN),
        ),
        ("ANY class", QueryType::PTR, QClassType::ANY),
        ("ANY class alias", QueryType::PTR, QClassType::Unknown(255)),
        (
            "nested ANY class alias",
            QueryType::PTR,
            QClassType::Class(ClassType::Unknown(255)),
        ),
        (
            "reserved zero class",
            QueryType::PTR,
            QClassType::Unknown(0),
        ),
        (
            "nested reserved zero class",
            QueryType::PTR,
            QClassType::Class(ClassType::Unknown(0)),
        ),
        (
            "known type alias",
            QueryType::Unknown(12),
            QClassType::Class(ClassType::IN),
        ),
        ("known class alias", QueryType::PTR, QClassType::Unknown(1)),
    ];
    for (label, qtype, qclass) in cases {
        let mut request = question();
        request.qtype = qtype;
        request.qclass = qclass;
        assert!(
            matches!(
                LlqClient::start(request, 60, Instant::now()),
                Err(LlqError::InvalidQuestion)
            ),
            "accepted {label}",
        );
    }
}

#[test]
fn subscriptions_preserve_canonical_specific_and_unknown_questions() {
    for (qtype, qclass) in [
        (QueryType::PTR, QClassType::Class(ClassType::IN)),
        (QueryType::Unknown(65280), QClassType::Unknown(65280)),
    ] {
        let mut request = question();
        request.qtype = qtype;
        request.qclass = qclass;
        assert!(request.is_wire_canonical());
        let (client, setup) = LlqClient::start(request, 60, Instant::now()).unwrap();
        assert_eq!(client.question().qtype, qtype);
        assert_eq!(client.question().qclass, qclass);
        assert_eq!(setup.lease, 60);
    }
}

#[test]
fn lost_setup_responses_and_acknowledgments_retry_then_complete() {
    let start = Instant::now();
    let (mut client, _) = LlqClient::start(question(), 600, start).unwrap();
    // Consume request retries first: response retries get their own timer/budget.
    client.retry_setup(start + Duration::from_secs(2)).unwrap();
    client.retry_setup(start + Duration::from_secs(6)).unwrap();
    let response_time = start + Duration::from_secs(7);
    let response = client
        .accept_challenge(challenge(42, 60), response_time)
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .retry_setup(response_time + Duration::from_secs(1))
            .unwrap(),
        None
    );
    // Message 3 was lost. Its replacement must retain the granted ID and lease.
    assert_eq!(
        client
            .retry_setup(response_time + Duration::from_secs(2))
            .unwrap(),
        Some(response)
    );
    assert_eq!(
        client
            .retry_setup(response_time + Duration::from_secs(5))
            .unwrap(),
        None
    );
    // Message 4 was lost. Retransmit the response again, allowing another ACK.
    assert_eq!(
        client
            .retry_setup(response_time + Duration::from_secs(6))
            .unwrap(),
        Some(response)
    );
    let ack_time = response_time + Duration::from_secs(13);
    assert_eq!(client.retry_setup(ack_time).unwrap(), None);
    assert_eq!(client.status(ack_time), LlqClientStatus::AwaitingSetupAck);
    client.accept_setup_ack(response, ack_time).unwrap();
    assert_eq!(client.status(ack_time), LlqClientStatus::Active);
    assert_eq!(
        client.status(ack_time + Duration::from_secs(60)),
        LlqClientStatus::Expired
    );
    assert!(matches!(
        client.retry_setup(ack_time),
        Err(LlqError::InvalidState)
    ));
}

#[test]
fn missing_setup_ack_fails_after_final_eight_second_wait() {
    let start = Instant::now();
    let (mut client, _) = LlqClient::start(question(), 60, start).unwrap();
    client.accept_challenge(challenge(42, 60), start).unwrap();
    for seconds in [2, 6] {
        assert!(
            client
                .retry_setup(start + Duration::from_secs(seconds))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        client.retry_setup(start + Duration::from_secs(13)).unwrap(),
        None
    );
    assert_eq!(
        client.status(start + Duration::from_secs(13)),
        LlqClientStatus::AwaitingSetupAck
    );
    assert_eq!(
        client.retry_setup(start + Duration::from_secs(14)).unwrap(),
        None
    );
    assert_eq!(
        client.status(start + Duration::from_secs(14)),
        LlqClientStatus::Failed
    );
}

#[test]
fn complete_event_message_enforces_wire_length_boundary() {
    let record = ResourceRecord {
        name: DomainName::from_dotted("printer.example").unwrap(),
        rtype: RecordType::Unknown(65000),
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::Unknown(Vec::new()),
    };
    let mut event = LlqEventMessage {
        message_id: 1,
        questions: vec![question()],
        changes: vec![LlqEventChange::Add(record)],
        options: vec![LlqOption {
            opcode: LlqOpcode::Event,
            lease: 0,
            ..challenge(42, 60)
        }],
    };
    let overhead = event.into_wire().unwrap().len();
    let LlqEventChange::Add(record) = &mut event.changes[0] else {
        unreachable!()
    };
    record.rdata = RData::Unknown(vec![0; 65535 - overhead]);
    let mut bytes = event.into_wire().unwrap();
    assert_eq!(bytes.len(), 65535);
    assert!(LlqEventMessage::from_wire(&bytes).is_ok());
    let LlqEventChange::Add(record) = &mut event.changes[0] else {
        unreachable!()
    };
    let RData::Unknown(data) = &mut record.rdata else {
        unreachable!()
    };
    data.push(0);
    assert!(matches!(
        event.into_wire(),
        Err(LlqError::Wire(WireError::LengthOverflow { .. }))
    ));
    bytes.push(0);
    assert!(matches!(
        LlqEventMessage::from_wire(&bytes),
        Err(LlqError::Wire(WireError::LengthOverflow { .. }))
    ));
}
