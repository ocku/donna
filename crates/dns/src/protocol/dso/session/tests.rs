use super::*;

#[test]
fn ending_operations_with_zero_timeout_closes_immediately() {
    let now = Instant::now();
    for endpoint in [DsoEndpoint::Client, DsoEndpoint::Server] {
        let mut session = DsoSession::new(endpoint, now);
        let keepalive = DsoTlv::keepalive(Duration::ZERO, Duration::from_secs(60));
        match endpoint {
            DsoEndpoint::Client => session.apply_server_keepalive(&keepalive, now).unwrap(),
            DsoEndpoint::Server => session.configure_server_keepalive(&keepalive, now).unwrap(),
        }
        session.set_active_operations_at(1, now);
        let ended = now + Duration::from_secs(10);
        assert_eq!(session.action(ended), DsoSessionAction::None);
        session.set_active_operations_at(0, ended);
        match endpoint {
            DsoEndpoint::Client => {
                assert_eq!(session.action(ended), DsoSessionAction::GracefulClose)
            }
            DsoEndpoint::Server => {
                assert_eq!(
                    session.action(ended + Duration::from_millis(4999)),
                    DsoSessionAction::None
                );
                assert_eq!(
                    session.action(ended + Duration::from_secs(5)),
                    DsoSessionAction::Abort
                );
            }
        }
    }
}

#[test]
fn revised_timeout_uses_elapsed_inactivity_after_last_operation() {
    let now = Instant::now();
    let infinity = Duration::from_millis(u64::from(u32::MAX));
    for endpoint in [DsoEndpoint::Client, DsoEndpoint::Server] {
        let mut session = DsoSession::new(endpoint, now);
        let unlimited = DsoTlv::keepalive(infinity, infinity);
        let finite = DsoTlv::keepalive(Duration::from_secs(10), infinity);
        match endpoint {
            DsoEndpoint::Client => session.apply_server_keepalive(&unlimited, now).unwrap(),
            DsoEndpoint::Server => session.configure_server_keepalive(&unlimited, now).unwrap(),
        }
        session.set_active_operations_at(1, now);
        session.set_active_operations_at(0, now + Duration::from_secs(100));
        let revised = now + Duration::from_secs(105);
        match endpoint {
            DsoEndpoint::Client => session.apply_server_keepalive(&finite, revised).unwrap(),
            DsoEndpoint::Server => session
                .configure_server_keepalive(&finite, revised)
                .unwrap(),
        }
        let (limit, action) = match endpoint {
            DsoEndpoint::Client => (10, DsoSessionAction::GracefulClose),
            DsoEndpoint::Server => (20, DsoSessionAction::Abort),
        };
        assert_eq!(
            session.action(now + Duration::from_secs(100 + limit) - Duration::from_millis(1)),
            DsoSessionAction::None
        );
        assert_eq!(
            session.action(now + Duration::from_secs(100 + limit)),
            action
        );
    }
}

#[test]
fn client_keepalive_remains_due_during_active_operations() {
    let now = Instant::now();
    let mut session = DsoSession::new(DsoEndpoint::Client, now);
    session.set_active_operations_at(1, now);
    assert_eq!(
        session.action(now + Duration::from_secs(15)),
        DsoSessionAction::SendKeepalive
    );
    session.record_message(now + Duration::from_secs(15), true);
    assert_eq!(
        session.action(now + Duration::from_secs(29)),
        DsoSessionAction::None
    );
    assert_eq!(
        session.action(now + Duration::from_secs(30)),
        DsoSessionAction::SendKeepalive
    );
}

#[test]
fn inactivity_begins_when_the_last_long_lived_operation_ends() {
    let now = Instant::now();
    for endpoint in [DsoEndpoint::Client, DsoEndpoint::Server] {
        let mut session = DsoSession::new(endpoint, now);
        let keepalive = DsoTlv::keepalive(Duration::from_secs(15), Duration::from_secs(60));
        match endpoint {
            DsoEndpoint::Client => session.apply_server_keepalive(&keepalive, now).unwrap(),
            DsoEndpoint::Server => session.configure_server_keepalive(&keepalive, now).unwrap(),
        }
        session.set_active_operations_at(2, now);
        session.record_message(now + Duration::from_secs(100), true);
        session.set_active_operations_at(1, now + Duration::from_secs(100));
        assert_eq!(
            session.action(now + Duration::from_secs(100)),
            DsoSessionAction::None
        );
        session.set_active_operations_at(0, now + Duration::from_secs(100));
        let limit = match endpoint {
            DsoEndpoint::Client => Duration::from_secs(15),
            DsoEndpoint::Server => Duration::from_secs(30),
        };
        assert_eq!(
            session.action(now + Duration::from_secs(100) + limit - Duration::from_millis(1)),
            DsoSessionAction::None
        );
        // Repeating the zero count must not postpone the deadline.
        session.set_active_operations_at(0, now + Duration::from_secs(101));
        let expected = match endpoint {
            DsoEndpoint::Client => DsoSessionAction::GracefulClose,
            DsoEndpoint::Server => DsoSessionAction::Abort,
        };
        assert_eq!(
            session.action(now + Duration::from_secs(100) + limit),
            expected
        );
    }
}

#[test]
fn server_uses_granted_keepalive_interval_with_active_operations() {
    let now = Instant::now();
    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    server.set_active_operations(1);
    let granted = DsoTlv::keepalive(Duration::from_secs(15), Duration::from_secs(60));
    server.configure_server_keepalive(&granted, now).unwrap();
    assert_eq!(
        server.action(now + Duration::from_secs(30)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(now + Duration::from_millis(119_999)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(now + Duration::from_secs(120)),
        DsoSessionAction::Abort
    );
    let revised = now + Duration::from_secs(100);
    server
        .configure_server_keepalive(&granted, revised)
        .unwrap();
    assert_eq!(
        server.action(revised + Duration::from_millis(119_999)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(revised + Duration::from_secs(120)),
        DsoSessionAction::Abort
    );
}

#[test]
fn server_timeout_infinity_and_finite_values_are_independent() {
    let now = Instant::now();
    let infinity = Duration::from_millis(u64::from(u32::MAX));
    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    server
        .configure_server_keepalive(&DsoTlv::keepalive(infinity, infinity), now)
        .unwrap();
    assert_eq!(
        server.action(now + Duration::from_secs(365 * 24 * 60 * 60)),
        DsoSessionAction::None
    );
    server
        .configure_server_keepalive(&DsoTlv::keepalive(Duration::from_secs(60), infinity), now)
        .unwrap();
    assert_eq!(
        server.action(now + Duration::from_secs(119)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(now + Duration::from_secs(120)),
        DsoSessionAction::Abort
    );
    server
        .configure_server_keepalive(&DsoTlv::keepalive(infinity, Duration::from_secs(60)), now)
        .unwrap();
    assert_eq!(
        server.action(now + Duration::from_secs(119)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(now + Duration::from_secs(120)),
        DsoSessionAction::Abort
    );
}

#[test]
fn server_keepalive_does_not_reset_inactivity_and_allows_zero_inactivity() {
    let now = Instant::now();
    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    let keepalive = DsoTlv::keepalive(Duration::from_secs(60), Duration::from_secs(60));
    server
        .configure_server_keepalive(&keepalive, now + Duration::from_secs(100))
        .unwrap();
    assert_eq!(
        server.action(now + Duration::from_secs(120)),
        DsoSessionAction::Abort
    );
    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    server
        .configure_server_keepalive(
            &DsoTlv::keepalive(Duration::ZERO, Duration::from_secs(10)),
            now,
        )
        .unwrap();
    assert_eq!(
        server.action(now + Duration::from_millis(4999)),
        DsoSessionAction::None
    );
    assert_eq!(
        server.action(now + Duration::from_secs(5)),
        DsoSessionAction::Abort
    );
}

#[test]
fn timeout_configuration_rejects_wrong_roles_and_invalid_tlvs_atomically() {
    let now = Instant::now();
    let valid = DsoTlv::keepalive(Duration::from_secs(60), Duration::from_secs(60));
    let mut client = DsoSession::new(DsoEndpoint::Client, now);
    assert!(matches!(
        client.configure_server_keepalive(&valid, now),
        Err(DsoError::WrongDirection)
    ));
    let mut server = DsoSession::new(DsoEndpoint::Server, now);
    assert!(matches!(
        server.apply_server_keepalive(&valid, now),
        Err(DsoError::WrongDirection)
    ));
    server.set_active_operations(1);
    server.configure_server_keepalive(&valid, now).unwrap();
    for invalid in [
        DsoTlv::keepalive(Duration::ZERO, Duration::from_millis(9999)),
        DsoTlv {
            code: DSO_KEEPALIVE,
            data: vec![0; 7],
        },
        DsoTlv::retry_delay(Duration::ZERO),
    ] {
        assert!(
            server
                .configure_server_keepalive(&invalid, now + Duration::from_secs(100))
                .is_err()
        );
        assert_eq!(
            server.action(now + Duration::from_secs(120)),
            DsoSessionAction::Abort
        );
    }
}
