use super::*;

/// Exchanges and serves DNS messages over TCP.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpTransport;

impl Transport for TcpTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Tcp)
    }

    #[instrument(
        level = "debug",
        skip(query),
        fields(server = %server, transaction_id = query.headers.id, timeout = ?timeout)
    )]
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            reject_cleartext_padding(query)?;
            // `into_wire` rejects messages larger than the two-octet TCP frame
            // length can express (RFC 1035 §4.2.2).
            let request = query.into_wire().map_err(TransportError::encode)?;
            let deadline = checked_deadline(timeout)?;
            let mut stream = time::timeout_at(deadline, TcpStream::connect(server))
                .await
                .map_err(|_| TransportError::Timeout)??;

            time::timeout_at(deadline, write_frame(&mut stream, &request))
                .await
                .map_err(|_| TransportError::Timeout)??;

            loop {
                let packet = time::timeout_at(deadline, read_frame(&mut stream))
                    .await
                    .map_err(|_| TransportError::Timeout)??;
                let mut response = Message::from_wire(&packet).map_err(TransportError::decode)?;
                if matches_tcp_query(&response, query) {
                    if response.questions.is_empty() && !crate::has_tsig(&response) {
                        response.questions.clone_from(&query.questions);
                    }
                    return Ok(response);
                }
            }
        })
    }
}

impl TransportServer for TcpTransport {
    /// Serves RFC 1035 TCP queries using its required two-octet length prefix.
    #[instrument(level = "debug", skip(handler), fields(address = %address))]
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), std::io::Error>>
    where
        H: DnsRequestHandler + 'static,
        Self: 'future,
    {
        Box::pin(async move { serve_listener(TcpListener::bind(address).await?, handler).await })
    }
}

pub(crate) fn matches_tcp_query(reply: &Message, query: &Message) -> bool {
    // RFC 7766 §6.2.1.1 requires response correlation by ID and question.
    // RFC 1035 also permits a TCP response to omit the question section, so an
    // empty section cannot be rejected here.
    reply.headers.qr
        && reply.headers.opcode == query.headers.opcode
        && reply.headers.id == query.headers.id
        && ((!reply.questions.is_empty() && crate::message::response_questions_match(reply, query))
            || (reply.questions.is_empty()
                && (!is_questionless_padding_only_response(reply)
                    || matches!(
                        query.questions.as_slice(),
                        [question]
                            if matches!(
                                question.qtype,
                                dns::QueryType::AXFR | dns::QueryType::IXFR
                            )
                    ))))
}

fn is_questionless_padding_only_response(response: &Message) -> bool {
    response.headers.qr
        && response.headers.aa
        && !response.headers.tc
        && response.headers.opcode == dns::OpCode::Query
        && response.extended_rcode() == 0
        && response.questions.is_empty()
        && response.answers.is_empty()
        && response.authorities.is_empty()
        && matches!(response.additionals.as_slice(), [record]
            if record.rtype == dns::RecordType::OPT
                && response
                    .edns()
                    .ok()
                    .flatten()
                    .is_some_and(|edns| edns.padding().is_some()))
}
