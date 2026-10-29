use super::*;

#[derive(Debug, Default)]
pub(super) struct MemoryUpdatePersistence {
    pub(super) snapshots: Mutex<Vec<Vec<ResourceRecord>>>,
    pub(super) fail: AtomicBool,
}

impl UpdatePersistence for MemoryUpdatePersistence {
    fn persist<'future>(
        &'future self,
        zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>> {
        Box::pin(async move {
            if self.fail.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("injected persistence failure").into());
            }
            self.snapshots.lock().unwrap().push(zone.records().to_vec());
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct RecordingNotifyTransport {
    state: Arc<RecordingNotifyState>,
}

#[derive(Debug)]
struct RecordingNotifyState {
    calls: Mutex<Vec<(SocketAddr, Message)>>,
    failures_before_success: usize,
    response_rcode: RCode,
    protocol: Option<TransportProtocol>,
    changed: Notify,
    call_count: AtomicUsize,
}

impl RecordingNotifyTransport {
    pub(super) fn new(failures_before_success: usize, response_rcode: RCode) -> Self {
        Self::with_protocol(failures_before_success, response_rcode, None)
    }

    pub(super) fn with_protocol(
        failures_before_success: usize,
        response_rcode: RCode,
        protocol: Option<TransportProtocol>,
    ) -> Self {
        Self {
            state: Arc::new(RecordingNotifyState {
                calls: Mutex::new(Vec::new()),
                failures_before_success,
                response_rcode,
                protocol,
                changed: Notify::new(),
                call_count: AtomicUsize::new(0),
            }),
        }
    }

    pub(super) async fn wait_for_calls(&self, expected: usize) {
        loop {
            let notified = self.state.changed.notified();
            if self.state.call_count.load(Ordering::SeqCst) >= expected {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn calls(&self) -> Vec<(SocketAddr, Message)> {
        self.state.calls.lock().unwrap().clone()
    }
}

impl Transport for RecordingNotifyTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        self.state.protocol
    }

    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.state
                .calls
                .lock()
                .unwrap()
                .push((server, query.clone()));
            let call = self.state.call_count.fetch_add(1, Ordering::SeqCst) + 1;
            self.state.changed.notify_waiters();
            if call <= self.state.failures_before_success {
                return Err(TransportError::Timeout);
            }
            let mut response = query.clone();
            response.headers.qr = true;
            response.headers.rcode = self.state.response_rcode;
            if self.state.response_rcode != RCode::Ok {
                response.headers.aa = false;
                response.answers.clear();
            }
            Ok(response)
        })
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct BlockingNotifyTransport {
    state: Arc<BlockingNotifyState>,
}

#[derive(Debug, Default)]
struct BlockingNotifyState {
    calls: Mutex<Vec<(SocketAddr, Message)>>,
    changed: Notify,
    call_count: AtomicUsize,
}

impl BlockingNotifyTransport {
    pub(super) async fn wait_for_calls(&self, expected: usize) {
        loop {
            let notified = self.state.changed.notified();
            if self.state.call_count.load(Ordering::SeqCst) >= expected {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn calls(&self) -> Vec<(SocketAddr, Message)> {
        self.state.calls.lock().unwrap().clone()
    }
}

impl Transport for BlockingNotifyTransport {
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        _timeout: Duration,
    ) -> transport::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            self.state
                .calls
                .lock()
                .unwrap()
                .push((server, query.clone()));
            self.state.call_count.fetch_add(1, Ordering::SeqCst);
            self.state.changed.notify_waiters();
            std::future::pending().await
        })
    }
}
