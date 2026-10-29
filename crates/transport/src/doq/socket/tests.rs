use super::*;
use std::{collections::VecDeque, future::poll_fn};

#[tokio::test(start_paused = true)]
async fn recoverable_receive_errors_wake_after_backoff_and_deliver_next_packet() {
    let mut receive = ReceiveRetry::default();
    let mut packets = VecDeque::from([
        Err(io::ErrorKind::ConnectionRefused.into()),
        Err(io::ErrorKind::NetworkDown.into()),
        Ok(1),
    ]);
    let started = time::Instant::now();
    let count = poll_fn(|cx| receive.poll(cx, |_| Poll::Ready(packets.pop_front().unwrap())))
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(packets.is_empty());
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(30));

    // A successful receive resets the delay rather than carrying the previous
    // error burst into an unrelated packet's retry period.
    let mut packets = VecDeque::from([Err(io::ErrorKind::ConnectionReset.into()), Ok(2)]);
    let started = time::Instant::now();
    assert_eq!(
        poll_fn(|cx| receive.poll(cx, |_| Poll::Ready(packets.pop_front().unwrap())))
            .await
            .unwrap(),
        2
    );
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn fatal_receive_errors_return_without_spinning_or_delaying() {
    let mut receive = ReceiveRetry::default();
    let mut attempts = 0;
    let started = time::Instant::now();
    let error = poll_fn(|cx| {
        receive.poll::<()>(cx, |_| {
            attempts += 1;
            Poll::Ready(Err(io::ErrorKind::InvalidInput.into()))
        })
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(attempts, 1);
    assert_eq!(started.elapsed(), std::time::Duration::ZERO);
}

#[tokio::test]
async fn quic_socket_preserves_datagrams_peer_addresses_and_metadata() {
    let socket = ServerSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(b"datagram", socket.local_addr().unwrap())
        .await
        .unwrap();
    let mut buffer = [0; 64];
    let mut buffers = [IoSliceMut::new(&mut buffer)];
    let mut meta = [RecvMeta::default()];
    assert_eq!(
        poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta))
            .await
            .unwrap(),
        1
    );
    assert_eq!(meta[0].addr, peer.local_addr().unwrap());
    assert_eq!(&buffer[..meta[0].len], b"datagram");
    assert!(socket.max_receive_segments() > 0);
    assert!(socket.max_transmit_segments() > 0);
}
