use super::*;
use std::collections::VecDeque;

#[tokio::test(start_paused = true)]
async fn transient_errors_delay_then_deliver_the_next_event() {
    let mut events = VecDeque::from([
        Err(io::ErrorKind::ConnectionRefused.into()),
        Err(io::ErrorKind::NetworkUnreachable.into()),
        Err(io::ErrorKind::ConnectionReset.into()),
        Ok(42),
    ]);
    let started = tokio::time::Instant::now();
    let event = next(|_| Poll::Ready(events.pop_front().unwrap()))
        .await
        .unwrap();
    assert_eq!(event, 42);
    assert!(events.is_empty());
    assert_eq!(started.elapsed(), INITIAL_RETRY_DELAY * 7);
}

#[tokio::test(start_paused = true)]
async fn fatal_errors_propagate_unchanged_without_delay_or_another_attempt() {
    let mut attempts = 0;
    let started = tokio::time::Instant::now();
    let error = next::<()>(|_| {
        attempts += 1;
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "closed listener",
        )))
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "closed listener");
    assert_eq!(attempts, 1);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[test]
fn backoff_is_capped_and_success_resets_it() {
    let mut retry = Retry::default();
    for _ in 0..100 {
        let delay = retry.next_delay(io::ErrorKind::OutOfMemory.into()).unwrap();
        assert!((INITIAL_RETRY_DELAY..=MAX_RETRY_DELAY).contains(&delay));
    }
    assert_eq!(
        retry.next_delay(io::ErrorKind::OutOfMemory.into()).unwrap(),
        MAX_RETRY_DELAY
    );
    retry.reset();
    assert_eq!(
        retry
            .next_delay(io::ErrorKind::ConnectionAborted.into())
            .unwrap(),
        INITIAL_RETRY_DELAY
    );
}

#[test]
fn packet_and_resource_errors_recover_but_invalid_listeners_do_not() {
    use io::ErrorKind::*;

    for kind in [
        Interrupted,
        WouldBlock,
        TimedOut,
        ConnectionAborted,
        ConnectionReset,
        ConnectionRefused,
        NetworkDown,
        NetworkUnreachable,
        HostUnreachable,
        OutOfMemory,
    ] {
        assert!(recoverable(&kind.into()), "{kind:?}");
    }
    for kind in [
        InvalidInput,
        PermissionDenied,
        Unsupported,
        NotConnected,
        Other,
    ] {
        assert!(!recoverable(&kind.into()), "{kind:?}");
    }

    #[cfg(unix)]
    {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(recoverable(&io::Error::from_raw_os_error(code)));
        }
        assert!(!recoverable(&io::Error::from_raw_os_error(libc::EBADF)));
    }
}

#[tokio::test]
async fn accept_delivers_a_connection_and_reports_bind_conflicts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        accept(&listener).await.unwrap().1,
        peer.local_addr().unwrap()
    );
    assert_eq!(
        TcpListener::bind(listener.local_addr().unwrap())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrInUse
    );
}

#[cfg(any(feature = "udp", feature = "dnscrypt"))]
#[tokio::test]
async fn udp_receive_preserves_empty_and_nonempty_datagrams() {
    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for packet in [b"".as_slice(), b"healthy"] {
        peer.send_to(packet, listener.local_addr().unwrap())
            .await
            .unwrap();
        let mut buffer = [0; 32];
        let (length, address) = recv_from(&listener, &mut buffer).await.unwrap();
        assert_eq!(address, peer.local_addr().unwrap());
        assert_eq!(&buffer[..length], packet);
    }
}
