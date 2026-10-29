use super::*;

pub(super) async fn serve_listener<H>(listener: TcpListener, handler: H) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    serve_listener_with_policy(listener, handler, SERVER_POLICY, None).await
}

/// Test seam for small deterministic limits and deadlines. A permit is acquired
/// before `accept`, so the kernel backlog—not unbounded user-space sockets or
/// tasks—holds connections while all admitted tasks are busy.
pub(super) async fn serve_listener_with_policy<H>(
    listener: TcpListener,
    handler: H,
    policy: TcpServerPolicy,
    activity: Option<Arc<ConnectionActivity>>,
) -> Result<(), io::Error>
where
    H: DnsRequestHandler + 'static,
{
    if policy.connection_limit == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP connection limit must be non-zero",
        ));
    }

    let handler = Arc::new(handler);
    let permits = Arc::new(Semaphore::new(policy.connection_limit));

    loop {
        if permits.available_permits() == 0 {
            tracing::debug!(
                connection_limit = policy.connection_limit,
                "TCP connection limit reached; pausing accepts"
            );
        }
        let permit = Arc::clone(&permits).acquire_owned().await.map_err(|_| {
            io::Error::other("TCP connection admission semaphore unexpectedly closed")
        })?;
        let (stream, peer) = crate::listener_io::accept(&listener).await?;
        spawn_connection(
            stream,
            peer,
            Arc::clone(&handler),
            policy,
            permit,
            activity.clone(),
        );
    }
}

pub(super) fn spawn_connection<S, H>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<H>,
    policy: TcpServerPolicy,
    permit: OwnedSemaphorePermit,
    activity: Option<Arc<ConnectionActivity>>,
) -> tokio::task::JoinHandle<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: DnsRequestHandler + 'static,
{
    let span = tracing::debug_span!("tcp_connection", %peer);
    tokio::spawn(
        async move {
            let _activity = activity.map(ConnectionActivity::start);
            // Declared after the observer so the permit is released before a
            // test observer reports that the task has ended.
            let _permit = permit;
            serve_connection(stream, peer, handler, policy).await;
        }
        .instrument(span),
    )
}

#[derive(Default)]
pub(super) struct ConnectionActivity {
    pub(super) active: AtomicUsize,
    pub(super) maximum: AtomicUsize,
    changed: Notify,
}

impl ConnectionActivity {
    fn start(activity: Arc<Self>) -> ConnectionActivityGuard {
        let active = activity.active.fetch_add(1, Ordering::SeqCst) + 1;
        activity.maximum.fetch_max(active, Ordering::SeqCst);
        activity.changed.notify_waiters();
        ConnectionActivityGuard(activity)
    }

    #[cfg(test)]
    pub(super) async fn wait_for(&self, expected: usize) {
        loop {
            let notified = self.changed.notified();
            if self.active.load(Ordering::SeqCst) == expected {
                return;
            }
            notified.await;
        }
    }
}

struct ConnectionActivityGuard(Arc<ConnectionActivity>);

impl Drop for ConnectionActivityGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

#[instrument(level = "debug", skip(stream, handler, policy))]
pub(super) async fn serve_connection<S, H>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<H>,
    policy: TcpServerPolicy,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    H: DnsRequestHandler + 'static,
{
    serve_connection_for(stream, peer, handler, policy, TransportProtocol::Tcp).await;
}

async fn serve_connection_for<S, H>(
    mut stream: S,
    peer: SocketAddr,
    handler: Arc<H>,
    policy: TcpServerPolicy,
    protocol: TransportProtocol,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    H: DnsRequestHandler + 'static,
{
    serve_connection_loop(&mut stream, peer, handler, policy, protocol).await;
    // TLS close_notify is required for a clean encrypted shutdown. Plain TCP
    // connections may still have unread partial-frame bytes; calling shutdown
    // in that case can turn the peer-visible EOF into a reset on some systems.
    if protocol == TransportProtocol::Tls {
        let _ = time::timeout(policy.response_write_timeout, stream.shutdown()).await;
    }
}

async fn serve_connection_loop<S, H>(
    stream: &mut S,
    peer: SocketAddr,
    handler: Arc<H>,
    policy: TcpServerPolicy,
    protocol: TransportProtocol,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    H: DnsRequestHandler + 'static,
{
    loop {
        let packet = match read_frame_with_timeout(&mut *stream, policy.frame_read_timeout).await {
            Ok(packet) => packet,
            Err(error) => {
                if error.kind() == io::ErrorKind::TimedOut {
                    tracing::debug!(%peer, "TCP frame read timed out");
                }
                // EOF, malformed framing, and local idle expiry all terminate
                // only this client connection; the listener remains available.
                return;
            }
        };
        let query = match Message::from_wire(&packet) {
            Ok(query) if query.headers.qr => return,
            Ok(query) => query,
            Err(_) => {
                let Some(response) = format_error_response(&packet) else {
                    return;
                };
                if !write_response_frame(
                    &mut *stream,
                    peer,
                    &response,
                    policy.response_write_timeout,
                )
                .await
                {
                    return;
                }
                continue;
            }
        };
        if !write_handler_response_for(
            &mut *stream,
            peer,
            Arc::clone(&handler),
            query,
            packet,
            policy,
            protocol,
        )
        .await
        {
            return;
        }
    }
}

#[cfg(test)]
pub(super) async fn write_handler_response<S, H>(
    stream: &mut S,
    peer: SocketAddr,
    handler: Arc<H>,
    query: Message,
    policy: TcpServerPolicy,
) -> bool
where
    S: AsyncWrite + Unpin,
    H: DnsRequestHandler + 'static,
{
    let wire_query = query.clone().into_wire().unwrap_or_default();
    write_handler_response_for(
        stream,
        peer,
        handler,
        query,
        wire_query,
        policy,
        TransportProtocol::Tcp,
    )
    .await
}

async fn write_handler_response_for<S, H>(
    stream: &mut S,
    peer: SocketAddr,
    handler: Arc<H>,
    query: Message,
    wire_query: Vec<u8>,
    policy: TcpServerPolicy,
    protocol: TransportProtocol,
) -> bool
where
    S: AsyncWrite + Unpin,
    H: DnsRequestHandler + 'static,
{
    let request_headers = query.headers.clone();
    let request_questions = query.questions.clone();
    let is_axfr = is_axfr_request(&query);
    let is_ixfr = is_ixfr_request(&query);
    let request_message = query.clone();
    let (request, response) = DnsRequest::channel_with_wire(query, wire_query, peer, protocol);
    let mut handler_tasks = JoinSet::new();
    handler_tasks.spawn(async move { handler.handle(request).await });
    let Some(handler_deadline) = time::Instant::now().checked_add(policy.handler_reply_timeout)
    else {
        tracing::debug!(%peer, "TCP request handler deadline overflowed");
        return false;
    };

    let response = match time::timeout_at(handler_deadline, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return false,
        Err(_) => {
            tracing::debug!(%peer, "TCP request handler timed out");
            return false;
        }
    };

    match response {
        DnsResponse::Buffered(responses) => {
            let responses = responses.into_vec();
            match time::timeout_at(handler_deadline, handler_tasks.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => {
                    tracing::debug!(%peer, ?error, "TCP request handler failed");
                    return false;
                }
                Ok(None) => return false,
                Err(_) => {
                    tracing::debug!(%peer, "TCP request handler timed out");
                    return false;
                }
            }
            let responses = if is_axfr {
                prepare_axfr_responses(
                    responses,
                    &request_headers,
                    &request_questions,
                    policy.max_axfr_validation_rrsets,
                    Some((&request_message, protocol)),
                )
            } else if is_ixfr {
                prepare_ixfr_response(
                    responses,
                    &request_headers,
                    request_questions,
                    &request_message,
                    Some(protocol),
                )
            } else {
                prepare_standard_response_for(
                    responses,
                    &request_headers,
                    request_questions,
                    Some((&request_message, protocol)),
                )
            };
            let Some(responses) = responses else {
                return false;
            };
            for response in responses {
                if !write_response_frame(stream, peer, &response, policy.response_write_timeout)
                    .await
                {
                    return false;
                }
            }
            true
        }
        DnsResponse::Stream(mut responses) => {
            if !is_axfr && !is_ixfr {
                return false;
            }
            let Some(question) = request_questions.first().cloned() else {
                return false;
            };
            let request_questions_are_safe_to_echo =
                request_questions_are_safe_to_echo(&request_questions);
            let mut validator = TransferSeriesValidator::new(
                question,
                request_questions_are_safe_to_echo,
                policy.max_axfr_validation_rrsets,
                &request_message,
            );

            loop {
                let response =
                    match time::timeout(policy.handler_reply_timeout, responses.recv()).await {
                        Ok(Some(response)) => response,
                        Ok(None) => break,
                        Err(_) => {
                            tracing::debug!(%peer, "TCP AXFR producer timed out");
                            return false;
                        }
                    };
                let Some(response) = validator.prepare(
                    response,
                    &request_headers,
                    &request_questions,
                    Some((&request_message, protocol)),
                ) else {
                    return false;
                };
                if !write_response_frame(stream, peer, &response, policy.response_write_timeout)
                    .await
                {
                    return false;
                }
            }

            if !validator.finish() {
                return false;
            }
            handler_tasks.shutdown().await;
            true
        }
    }
}

pub(super) async fn write_response_frame<W>(
    stream: &mut W,
    peer: SocketAddr,
    response: &[u8],
    timeout: Duration,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    if let Err(error) = write_frame_with_timeout(stream, response, timeout).await {
        if error.kind() == io::ErrorKind::TimedOut {
            tracing::debug!(%peer, "TCP response frame write timed out");
        }
        return false;
    }
    true
}
