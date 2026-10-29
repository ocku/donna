use std::net::Ipv4Addr;

use super::*;
use crate::{QClassType, QueryType, RData};

fn name(value: &str) -> DomainName {
    DomainName::from_dotted(value).unwrap()
}

fn question() -> Question {
    Question {
        qname: name("service.example"),
        qtype: QueryType::A,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn record() -> ResourceRecord {
    ResourceRecord {
        name: name("service.example"),
        rtype: RecordType::A,
        class: ClassType::IN,
        ttl: 120,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    }
}

#[test]
fn dso_subscribe_round_trips_with_zero_section_counts() {
    let message = DsoMessage {
        id: 7,
        response: false,
        rcode: 0,
        tlvs: vec![push_subscribe_tlv(&question()).unwrap()],
    };
    let wire = message.into_wire().unwrap();
    assert_eq!(&wire[4..12], &[0; 8]);
    let decoded = DsoMessage::from_wire(&wire).unwrap();
    let parsed = parse_push_subscribe(decoded.primary().unwrap()).unwrap();
    assert!(same_question(&parsed, &question()));
}

#[test]
fn dso_accepts_empty_success_response_and_ignores_received_z_bits() {
    let response = DsoMessage {
        id: 7,
        response: true,
        rcode: 0,
        tlvs: Vec::new(),
    };
    let mut wire = response.into_wire().unwrap();
    wire[2] |= 0x07;
    wire[3] |= 0xf0;
    assert_eq!(DsoMessage::from_wire(&wire).unwrap(), response);

    let mut truncated = wire;
    truncated.truncate(9);
    assert!(matches!(
        DsoMessage::from_wire(&truncated),
        Err(DsoError::Wire(WireError::Truncated { .. }))
    ));
}

#[test]
fn push_changes_round_trip_every_add_and_remove_form() {
    let changes = vec![
        PushChange::Add(record()),
        PushChange::RemoveRecord(record()),
        PushChange::RemoveRrset {
            name: name("service.example"),
            rtype: RecordType::A,
            class: ClassType::IN,
        },
        PushChange::RemoveNameClass {
            name: name("service.example"),
            class: ClassType::IN,
        },
        PushChange::RemoveName {
            name: name("service.example"),
        },
    ];
    let tlv = push_update_tlv(&changes).unwrap();
    assert_eq!(parse_push_update(&tlv).unwrap().len(), changes.len());
    let message = DsoMessage {
        id: 0,
        response: false,
        rcode: 0,
        tlvs: vec![tlv],
    };
    DsoMessage::from_wire(&message.into_wire().unwrap()).unwrap();
}

#[test]
fn reconfirm_round_trips_one_record_without_a_ttl() {
    let mut disputed = record();
    disputed.ttl = 9_999;
    let tlv = push_reconfirm_tlv(&disputed).unwrap();
    let decoded = parse_push_reconfirm(&tlv).unwrap();
    assert!(decoded.name.eq_dns(&disputed.name));
    assert_eq!(decoded.rtype, disputed.rtype);
    assert_eq!(decoded.class, disputed.class);
    assert_eq!(decoded.ttl, 0);
    assert!(matches!(decoded.rdata, RData::A(address) if address == Ipv4Addr::new(192, 0, 2, 1)));
}

#[test]
fn push_ignores_reserved_ttl_change_and_keeps_following_change() {
    let mut tlv = push_update_tlv(&[PushChange::Add(record())]).unwrap();
    let name_length = name("service.example").wire_len();
    let ttl_offset = name_length + 4;
    tlv.data[ttl_offset..ttl_offset + 4].copy_from_slice(&0x8000_0000_u32.to_be_bytes());
    let valid = push_update_tlv(&[PushChange::Add(record())]).unwrap();
    tlv.data.extend_from_slice(&valid.data);
    assert_eq!(parse_push_update(&tlv).unwrap().len(), 1);
}

#[test]
fn subscription_registry_enforces_uniqueness_authorization_limits_and_retry() {
    let subscribe = |id| DsoMessage {
        id,
        response: false,
        rcode: 0,
        tlvs: vec![push_subscribe_tlv(&question()).unwrap()],
    };
    let mut subscriptions = DnsPushSubscriptions::new(1);
    subscriptions.subscribe(&subscribe(1), |_| true).unwrap();
    assert!(matches!(
        subscriptions.subscribe(&subscribe(2), |_| true),
        Err(DsoError::DuplicateSubscription)
    ));
    let unsubscribe = DsoMessage {
        id: 0,
        response: false,
        rcode: 0,
        tlvs: vec![push_unsubscribe_tlv(1)],
    };
    subscriptions.unsubscribe(&unsubscribe).unwrap();
    assert!(subscriptions.is_empty());

    let now = Instant::now();
    subscriptions
        .disconnect_with_retry(&DsoTlv::retry_delay(Duration::from_secs(2)), now)
        .unwrap();
    assert!(!subscriptions.can_reconnect(now + Duration::from_secs(1)));
    assert!(subscriptions.can_reconnect(now + Duration::from_secs(2)));
}

#[test]
fn session_timers_distinguish_maintenance_and_active_operations() {
    let now = Instant::now();
    let mut client = DsoSession::new(DsoEndpoint::Client, now);
    client.set_active_operations(1);
    assert_eq!(
        client.action(now + Duration::from_secs(15)),
        DsoSessionAction::SendKeepalive
    );
    client.record_message(now + Duration::from_secs(15), true);
    assert_eq!(
        client.action(now + Duration::from_secs(16)),
        DsoSessionAction::None
    );
    client.set_active_operations_at(0, now + Duration::from_secs(16));
    assert_eq!(
        client.action(now + Duration::from_secs(16)),
        DsoSessionAction::None
    );

    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    server.set_active_operations(1);
    assert_eq!(
        server.action(now + Duration::from_secs(30)),
        DsoSessionAction::Abort
    );
}

#[test]
fn client_applies_keepalive_minimum_and_infinite_values() {
    let now = Instant::now();
    let mut client = DsoSession::new(DsoEndpoint::Client, now);
    assert!(matches!(
        client.apply_server_keepalive(
            &DsoTlv::keepalive(Duration::from_secs(30), Duration::from_secs(9)),
            now
        ),
        Err(DsoError::InvalidKeepaliveInterval(9_000))
    ));
    let infinite = DsoTlv {
        code: DSO_KEEPALIVE,
        data: [u32::MAX.to_be_bytes(), u32::MAX.to_be_bytes()].concat(),
    };
    client.apply_server_keepalive(&infinite, now).unwrap();
    assert_eq!(
        client.action(now + Duration::from_secs(365 * 24 * 60 * 60)),
        DsoSessionAction::None
    );
}

#[test]
fn complete_dso_message_enforces_wire_length_boundary() {
    let mut message = DsoMessage {
        id: 1,
        response: false,
        rcode: 0,
        tlvs: vec![DsoTlv {
            code: 65000,
            data: vec![0; 65519],
        }],
    };
    let bytes = message.into_wire().unwrap();
    assert_eq!(bytes.len(), 65535);
    assert_eq!(DsoMessage::from_wire(&bytes).unwrap(), message);
    message.tlvs[0].data.push(0);
    assert!(matches!(
        message.into_wire(),
        Err(DsoError::Wire(WireError::LengthOverflow { .. }))
    ));
    let mut oversized = bytes;
    oversized[14..16].copy_from_slice(&65520u16.to_be_bytes());
    oversized.push(0);
    assert!(matches!(
        DsoMessage::from_wire(&oversized),
        Err(DsoError::Wire(WireError::LengthOverflow { .. }))
    ));
}

#[test]
fn push_tlv_response_context_enforces_sender_and_receiver_rules() {
    let push_tlvs = [
        push_subscribe_tlv(&question()).unwrap(),
        push_update_tlv(&[PushChange::Add(record())]).unwrap(),
        push_unsubscribe_tlv(7),
        push_reconfirm_tlv(&record()).unwrap(),
    ];
    for push in push_tlvs {
        for additional in [false, true] {
            let mut tlvs = Vec::new();
            if additional {
                tlvs.push(DsoTlv::keepalive(
                    Duration::from_secs(60),
                    Duration::from_secs(15),
                ));
            }
            tlvs.push(push.clone());
            let message = DsoMessage {
                id: 7,
                response: true,
                rcode: 0,
                tlvs,
            };
            assert!(matches!(message.into_wire(), Err(DsoError::InvalidHeader)));
            // Build independently: outbound validation must not conceal a
            // decoder regression, and nonzero ID avoids the ID rejection.
            let mut wire = vec![0, 7, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            for tlv in &message.tlvs {
                wire.extend_from_slice(&tlv.code.to_be_bytes());
                wire.extend_from_slice(&(tlv.data.len() as u16).to_be_bytes());
                wire.extend_from_slice(&tlv.data);
            }
            if push.code == DNS_PUSH_SUBSCRIBE {
                let decoded = DsoMessage::from_wire(&wire).unwrap();
                assert_eq!(decoded.id, 7);
                assert!(
                    decoded
                        .tlvs
                        .iter()
                        .all(|tlv| tlv.code != DNS_PUSH_SUBSCRIBE)
                );
                assert_eq!(decoded.tlvs.len(), usize::from(additional));
            } else {
                assert!(matches!(
                    DsoMessage::from_wire(&wire),
                    Err(DsoError::InvalidHeader)
                ));
            }
        }
    }
}

#[test]
fn keepalive_responses_and_retry_delay_additionals_remain_valid() {
    for tlvs in [
        vec![DsoTlv::keepalive(
            Duration::from_secs(60),
            Duration::from_secs(15),
        )],
        vec![
            DsoTlv::keepalive(Duration::from_secs(60), Duration::from_secs(15)),
            DsoTlv::retry_delay(Duration::from_secs(30)),
        ],
    ] {
        let message = DsoMessage {
            id: 7,
            response: true,
            rcode: 2,
            tlvs,
        };
        assert_eq!(
            DsoMessage::from_wire(&message.into_wire().unwrap()).unwrap(),
            message
        );
    }
}

#[test]
fn all_reserved_ttl_changes_are_ignored_without_rejecting_update() {
    let mut tlv = push_update_tlv(&[PushChange::Add(record())]).unwrap();
    let ttl_offset = name("service.example").wire_len() + 4;
    tlv.data[ttl_offset..ttl_offset + 4].copy_from_slice(&0x8000_0000_u32.to_be_bytes());
    assert!(parse_push_update(&tlv).unwrap().is_empty());
    assert!(matches!(
        parse_push_update(&DsoTlv {
            code: DNS_PUSH_UPDATE,
            data: Vec::new()
        }),
        Err(DsoError::EmptyPushUpdate)
    ));
}

#[test]
fn base_tlv_contexts_reject_invalid_outbound_combinations() {
    let keepalive = DsoTlv::keepalive(Duration::from_secs(60), Duration::from_secs(15));
    let retry = DsoTlv::retry_delay(Duration::from_secs(30));
    let padding = DsoTlv {
        code: 3,
        data: Vec::new(),
    };
    let unknown = DsoTlv {
        code: 65000,
        data: Vec::new(),
    };
    for (response, tlvs) in [
        (true, vec![keepalive.clone(), keepalive.clone()]),
        (true, vec![unknown.clone(), keepalive]),
        (
            false,
            vec![push_subscribe_tlv(&question()).unwrap(), retry.clone()],
        ),
        (false, vec![padding.clone()]),
    ] {
        let message = DsoMessage {
            id: 7,
            response,
            rcode: 0,
            tlvs,
        };
        assert!(matches!(message.into_wire(), Err(DsoError::InvalidHeader)));
    }
    // Additional response TLVs are valid without a Response Primary TLV.
    for tlv in [retry.clone(), padding.clone()] {
        let response = DsoMessage {
            id: 7,
            response: true,
            rcode: 2,
            tlvs: vec![tlv],
        };
        assert_eq!(
            DsoMessage::from_wire(&response.into_wire().unwrap()).unwrap(),
            response
        );
    }
    let response = DsoMessage {
        id: 7,
        response: true,
        rcode: 2,
        tlvs: vec![retry, padding.clone()],
    };
    assert_eq!(
        DsoMessage::from_wire(&response.into_wire().unwrap()).unwrap(),
        response
    );
    let request = DsoMessage {
        id: 7,
        response: false,
        rcode: 0,
        tlvs: vec![unknown, padding],
    };
    assert_eq!(
        DsoMessage::from_wire(&request.into_wire().unwrap()).unwrap(),
        request
    );
}

#[test]
fn public_push_message_enforces_wire_size_in_both_directions() {
    let mut message = DsoMessage {
        id: 0,
        response: false,
        rcode: 0,
        tlvs: vec![DsoTlv {
            code: DNS_PUSH_UPDATE,
            data: vec![0; 16_366],
        }],
    };
    let mut bytes = message.into_wire().unwrap();
    assert_eq!(bytes.len(), 16_382);
    message.tlvs[0].data.push(0);
    assert!(matches!(
        message.into_wire(),
        Err(DsoError::PushMessageTooLong(16_383))
    ));
    bytes[14..16].copy_from_slice(&16_367u16.to_be_bytes());
    bytes.push(0);
    assert!(matches!(
        DsoMessage::from_wire(&bytes),
        Err(DsoError::PushMessageTooLong(16_383))
    ));
}
