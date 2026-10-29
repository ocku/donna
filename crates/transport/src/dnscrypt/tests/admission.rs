use super::*;
use std::{future, sync::atomic::AtomicBool};

use super::super::server::send_datagram;

struct Cancellation(Arc<AtomicBool>);

#[tokio::test]
async fn udp_listener_rejects_wildcard_addresses_before_binding() {
    let (_, config, _) = configurations();
    for address in ["0.0.0.0:0", "[::]:0"] {
        let result = time::timeout(
            Duration::from_secs(1),
            DnscryptUdpTransportServer::new(config.clone())
                .serve(address.parse().unwrap(), LargeHandler),
        )
        .await
        .expect("wildcard validation must finish before receiving packets");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn blocked_udp_send_times_out_cancels_io_and_releases_admission() {
    let admission = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&admission).acquire_owned().await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let guard = Cancellation(Arc::clone(&cancelled));
    let sending = tokio::spawn(send_datagram(
        async move {
            let _guard = guard;
            future::pending().await
        },
        permit,
    ));

    tokio::task::yield_now().await;
    assert_eq!(admission.available_permits(), 0);
    assert!(!sending.is_finished());

    time::advance(SERVER_OPERATION_TIMEOUT - Duration::from_millis(1)).await;
    assert!(!sending.is_finished());
    assert!(!cancelled.load(Ordering::SeqCst));

    time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        sending.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(cancelled.load(Ordering::SeqCst));
    assert!(admission.try_acquire_owned().is_ok());
}

#[tokio::test(start_paused = true)]
async fn completed_or_failed_udp_send_releases_admission_without_waiting() {
    for result in [Ok(32), Err(io::ErrorKind::ConnectionRefused.into())] {
        let expected = result
            .as_ref()
            .map(|length| *length)
            .map_err(io::Error::kind);
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission).acquire_owned().await.unwrap();
        let started = time::Instant::now();

        let result = send_datagram(future::ready(result), permit).await;

        assert_eq!(result.map_err(|error| error.kind()), expected);
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(admission.try_acquire_owned().is_ok());
    }
}

#[tokio::test]
async fn cancelled_udp_send_drops_io_and_releases_admission() {
    let admission = Arc::new(Semaphore::new(1));
    let permit = Arc::clone(&admission).acquire_owned().await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let guard = Cancellation(Arc::clone(&cancelled));
    let sending = tokio::spawn(send_datagram(
        async move {
            let _guard = guard;
            future::pending().await
        },
        permit,
    ));

    tokio::task::yield_now().await;
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    assert!(cancelled.load(Ordering::SeqCst));
    assert!(admission.try_acquire_owned().is_ok());
}
