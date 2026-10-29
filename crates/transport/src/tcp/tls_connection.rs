use super::*;

pub(crate) async fn serve_tls_connection<S, H>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<H>,
    transfers_allowed: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: DnsRequestHandler + 'static,
{
    let policy = SERVER_POLICY;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (response_sender, mut response_receiver) =
        mpsc::channel::<Vec<u8>>(TLS_RESPONSE_QUEUE_CAPACITY);
    let writer_task = tokio::spawn(async move {
        while let Some(response) = response_receiver.recv().await {
            if !write_response_frame(&mut writer, peer, &response, policy.response_write_timeout)
                .await
            {
                return writer;
            }
        }
        writer
    });
    let mut request_tasks = JoinSet::new();

    loop {
        let mut request_failed = false;
        while let Some(completed) = request_tasks.try_join_next() {
            if !matches!(completed, Ok(true)) {
                request_failed = true;
                break;
            }
        }
        if request_failed {
            break;
        }
        if request_tasks.len() >= MAX_CONCURRENT_TLS_REQUESTS {
            match request_tasks.join_next().await {
                Some(Ok(true)) => continue,
                Some(Ok(false)) | Some(Err(_)) | None => break,
            }
        }

        // Keep each frame read cancellation-safe. Dropping read_exact after it
        // consumed only part of a length or payload would desynchronize every
        // subsequent frame on this persistent connection.
        let packet = match read_frame_with_timeout(&mut reader, policy.frame_read_timeout).await {
            Ok(packet) => packet,
            Err(error) => {
                if error.kind() == io::ErrorKind::TimedOut {
                    tracing::debug!(%peer, "TLS DNS frame read timed out");
                }
                break;
            }
        };
        let query = match Message::from_wire(&packet) {
            Ok(query) if query.headers.qr => break,
            Ok(query) => query,
            Err(_) => {
                let Some(response) = format_error_response(&packet) else {
                    break;
                };
                if !queue_response_frame(&response_sender, response, policy.response_write_timeout)
                    .await
                {
                    break;
                }
                continue;
            }
        };
        if !transfers_allowed && (is_axfr_request(&query) || is_ixfr_request(&query)) {
            tracing::debug!(%peer, "rejecting a TLS transfer without dot ALPN");
            break;
        }
        let response_sender = response_sender.clone();
        let handler = Arc::clone(&handler);
        request_tasks.spawn(async move {
            queue_handler_response_for(
                response_sender,
                peer,
                handler,
                query,
                packet,
                policy,
                TransportProtocol::Tls,
            )
            .await
        });
    }

    request_tasks.shutdown().await;
    drop(response_sender);
    let Ok(writer) = writer_task.await else {
        return;
    };
    let mut stream = reader.unsplit(writer);
    // Emit close_notify before closing the underlying TCP connection.
    let _ = time::timeout(policy.response_write_timeout, stream.shutdown()).await;
}

async fn queue_handler_response_for<H>(
    sender: mpsc::Sender<Vec<u8>>,
    peer: SocketAddr,
    handler: Arc<H>,
    query: Message,
    wire_query: Vec<u8>,
    policy: TcpServerPolicy,
    protocol: TransportProtocol,
) -> bool
where
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
        tracing::debug!(%peer, "TLS request handler deadline overflowed");
        return false;
    };

    let response = match time::timeout_at(handler_deadline, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return false,
        Err(_) => {
            tracing::debug!(%peer, "TLS request handler timed out");
            return false;
        }
    };

    match response {
        DnsResponse::Buffered(responses) => {
            let responses = responses.into_vec();
            match time::timeout_at(handler_deadline, handler_tasks.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => {
                    tracing::debug!(%peer, ?error, "TLS request handler failed");
                    return false;
                }
                Ok(None) => return false,
                Err(_) => {
                    tracing::debug!(%peer, "TLS request handler timed out");
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
                if !queue_response_frame(&sender, response, policy.response_write_timeout).await {
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
                            tracing::debug!(%peer, "TLS AXFR producer timed out");
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
                if !queue_response_frame(&sender, response, policy.response_write_timeout).await {
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

async fn queue_response_frame(
    sender: &mpsc::Sender<Vec<u8>>,
    response: Vec<u8>,
    timeout: Duration,
) -> bool {
    matches!(
        time::timeout(timeout, sender.send(response)).await,
        Ok(Ok(()))
    )
}
