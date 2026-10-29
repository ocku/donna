use super::*;

#[test]
fn round_trips_rfc1996_notify_request_and_response() {
    let request = notify_message();
    let request_wire = request.into_wire().unwrap();
    let decoded = Message::from_wire(&request_wire).unwrap();
    assert_eq!(decoded.headers.opcode, crate::OpCode::Notify);
    assert!(decoded.headers.aa);
    assert!(!decoded.headers.qr);
    assert_eq!(decoded.answers.len(), 1);

    let mut response = decoded;
    response.headers.qr = true;
    let response_wire = response.into_wire().unwrap();
    let response = Message::from_wire(&response_wire).unwrap();
    assert!(response.headers.qr && response.headers.aa);
    assert_eq!(response.questions.len(), 1);
}

#[test]
fn notify_ignores_received_future_sections_but_does_not_author_them() {
    let mut received = notify_message();
    received.authorities.push(notify_soa(update_zone(), 2));
    assert!(matches!(
        received.validate_strict(),
        Err(MessageValidationError::InvalidNotifyMessage)
    ));
    assert!(received.validate_for_forwarding().is_ok());
    let wire = received.into_wire().unwrap();
    assert_eq!(Message::from_wire(&wire).unwrap().authorities.len(), 1);
}

#[test]
fn rejects_malformed_rfc1996_notify_messages() {
    let invalid = [
        {
            let mut message = notify_message();
            message.headers.aa = false;
            message
        },
        {
            let mut message = notify_message();
            message.headers.rd = true;
            message
        },
        {
            let mut message = notify_message();
            message.questions[0].qtype = QueryType::A;
            message
        },
        {
            let mut message = notify_message();
            message.answers[0].name = name(&[b"other", b"example", b"com"]);
            message
        },
    ];
    for message in invalid {
        assert!(matches!(
            message.validate_for_forwarding(),
            Err(MessageValidationError::InvalidNotifyMessage)
        ));
        assert!(message.into_wire().is_err());
    }
}
