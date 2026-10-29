use super::*;

/// A server cannot cancel the client's query direction with STOP_SENDING.
/// Watch it during writes and reads so it cannot become a timeout or a retry
/// on a fresh connection. A normally acknowledged FIN needs no further watch.
pub(super) async fn with_peer_stop<T>(
    connection: &Connection,
    stopped: impl std::future::Future<Output = Result<Option<VarInt>, quinn::StoppedError>>,
    operation: impl std::future::Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    let failure = async {
        match stopped.await {
            Ok(Some(_)) => {
                connection.close(DOQ_PROTOCOL_ERROR, b"server sent STOP_SENDING");
                TransportError::InvalidQuicProtocol("server sent STOP_SENDING")
            }
            Ok(None) => std::future::pending().await,
            Err(error) => quic_io_error(error),
        }
    };
    tokio::select! {
        biased;
        error = failure => Err(error),
        result = operation => result,
    }
}

pub(super) fn validate_message(message: &Message) -> Result<(), TransportError> {
    let edns = message
        .edns()
        .map_err(|_| TransportError::InvalidQuicProtocol("malformed EDNS metadata"))?;
    if edns.is_some_and(|edns| edns.options.iter().any(|option| option.code == 11)) {
        return Err(TransportError::InvalidQuicProtocol(
            "EDNS TCP keepalive is forbidden in DoQ",
        ));
    }
    Ok(())
}

pub(super) fn reject_port_53(server: SocketAddr) -> Result<(), TransportError> {
    if server.port() == 53 {
        Err(TransportError::InvalidQuicProtocol(
            "DoQ must not use UDP port 53",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn prepare_query(query: &Message) -> Result<Message, TransportError> {
    validate_message(query)?;
    if has_tsig(query) && query.headers.id != 0 {
        return Err(TransportError::InvalidQuicProtocol(
            "an authenticated DoQ query must already use message ID zero",
        ));
    }
    let authenticated = has_tsig(query);
    let mut query = query.clone();
    query.headers.id = 0;
    if !authenticated
        && query
            .edns()
            .map_err(|_| {
                TransportError::InvalidQuicProtocol("query contains malformed EDNS metadata")
            })?
            .is_some()
    {
        crate::message::pad_query_for_encrypted_stream(&mut query)?;
    }
    Ok(query)
}

/// Apply connection-level consequences only to errors in peer DNS framing or
/// contents. Local resource limits, DNS rejection, and stream resets do not
/// establish a violation of the DoQ connection protocol.
pub(super) fn peer_result<T>(
    connection: &Connection,
    result: Result<T, TransportError>,
) -> Result<T, TransportError> {
    let fatal = match &result {
        Err(TransportError::Io(error)) => error.kind() == io::ErrorKind::UnexpectedEof,
        Err(TransportError::Decode(_) | TransportError::InvalidQuicProtocol(_)) => true,
        Err(TransportError::InvalidTransfer(reason)) => !matches!(
            *reason,
            "AXFR wire-byte limit exceeded"
                | "AXFR record limit exceeded"
                | "server rejected transfer"
        ),
        _ => false,
    };
    if fatal {
        connection.close(DOQ_PROTOCOL_ERROR, b"invalid DNS response");
    }
    result
}

pub(super) async fn require_fin(
    connection: &Connection,
    receive: &mut quinn::RecvStream,
    deadline: time::Instant,
) -> Result<(), TransportError> {
    match time::timeout_at(deadline, receive.read_to_end(0)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(quinn::ReadToEndError::TooLong)) => {
            connection.close(DOQ_PROTOCOL_ERROR, b"data follows terminal response");
            Err(TransportError::InvalidQuicProtocol(
                "data follows terminal response",
            ))
        }
        Ok(Err(quinn::ReadToEndError::Read(error))) => Err(quic_io_error(error)),
        Err(_) => {
            receive.stop(DOQ_REQUEST_CANCELLED).ok();
            Err(TransportError::Timeout)
        }
    }
}
