//! Exercise downstream-style object safety, borrowing, Send and cancellation.
use crate::{BoxFuture, Transport, TransportError, TransportRoute};
use dns::Message;
use std::{
    future::{Future, pending},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

#[derive(Default)]
struct Observations {
    started: AtomicUsize,
    canceled: AtomicUsize,
    address: AtomicUsize,
}

#[derive(Default)]
struct ApplicationTransport(Arc<Observations>);

struct CancelGuard<'a>(&'a AtomicUsize);
impl Drop for CancelGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl Transport for ApplicationTransport {
    fn exchange<'a>(
        &'a self,
        _: SocketAddr,
        query: &'a Message,
        _: Duration,
    ) -> BoxFuture<'a, Result<Message, TransportError>> {
        let future: BoxFuture<'a, Result<Message, TransportError>> = Box::pin(async move {
            self.0.started.fetch_add(1, Ordering::Relaxed);
            let _guard = CancelGuard(&self.0.canceled);
            pending::<()>().await;
            Ok(query.clone())
        });
        self.0.address.store(address(&future), Ordering::Relaxed);
        future
    }
}

fn address<T>(future: &BoxFuture<'_, T>) -> usize {
    future.as_ref().get_ref() as *const (dyn Future<Output = T> + Send) as *const () as usize
}

#[test]
fn object_safe_future_borrows_inputs_is_send_and_cancels_when_dropped() {
    let application = ApplicationTransport::default();
    let transport: &dyn Transport = &application;
    let query = Message::builder().build().unwrap();
    let mut future = transport.exchange(
        "192.0.2.53:53".parse().unwrap(),
        &query,
        Duration::from_secs(1),
    );
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    assert_eq!(application.0.started.load(Ordering::Relaxed), 0);
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        Future::poll(future.as_mut(), &mut context),
        Poll::Pending
    ));
    assert_eq!(application.0.started.load(Ordering::Relaxed), 1);
    assert_eq!(application.0.canceled.load(Ordering::Relaxed), 0);
    drop(future);
    assert_eq!(application.0.canceled.load(Ordering::Relaxed), 1);
}

#[test]
fn transport_route_reuses_the_inner_box_and_preserves_lazy_drop_semantics() {
    let application = ApplicationTransport::default();
    let observations = application.0.clone();
    let route = TransportRoute::new(application);
    let transport: &dyn Transport = &route;
    let query = Message::builder().build().unwrap();
    let mut future = transport.exchange(
        "192.0.2.53:53".parse().unwrap(),
        &query,
        Duration::from_secs(1),
    );
    // The inner future is still live. Its identical data pointer proves the
    // route returned that same allocation instead of allocating a wrapper.
    assert_eq!(
        address(&future),
        observations.address.load(Ordering::Relaxed)
    );
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    assert_eq!(observations.started.load(Ordering::Relaxed), 0);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Future::poll(future.as_mut(), &mut context).is_pending());
    assert_eq!(observations.started.load(Ordering::Relaxed), 1);
    assert_eq!(observations.canceled.load(Ordering::Relaxed), 0);
    drop(future);
    assert_eq!(observations.canceled.load(Ordering::Relaxed), 1);
}
