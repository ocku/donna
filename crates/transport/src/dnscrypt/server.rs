use super::*;

/// A resolver certificate paired with its short-term X25519 secret key.
#[derive(Clone)]
pub struct DnscryptResolverIdentity {
    pub(super) certificate: DnscryptCertificate,
    secret_key: SecretKey,
}

impl std::fmt::Debug for DnscryptResolverIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnscryptResolverIdentity")
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl DnscryptResolverIdentity {
    /// Pairs a signed certificate with its resolver secret key.
    pub fn new(
        certificate: DnscryptCertificate,
        resolver_secret_key: [u8; 32],
    ) -> Result<Self, DnscryptConfigError> {
        let secret_key = SecretKey::from(resolver_secret_key);
        if secret_key.public_key().as_bytes() != &certificate.resolver_public_key {
            return Err(DnscryptConfigError::ResolverKeyMismatch);
        }
        Ok(Self {
            certificate,
            secret_key,
        })
    }
}

/// DNSCrypt resolver configuration with one provider name and rotating identities.
#[derive(Debug, Clone)]
pub struct DnscryptServerConfig {
    pub(super) provider_name: dns::DomainName,
    pub(super) identities: Vec<DnscryptResolverIdentity>,
    pub(super) nonce_sequence: Arc<NonceSequence>,
}

impl DnscryptServerConfig {
    /// Builds a resolver configuration. At least one certificate identity is required.
    pub fn new(
        provider_name: dns::DomainName,
        identities: Vec<DnscryptResolverIdentity>,
    ) -> Result<Self, DnscryptConfigError> {
        if identities.is_empty() {
            return Err(DnscryptConfigError::InvalidCertificate(
                "resolver has no certificate identities",
            ));
        }
        for (index, identity) in identities.iter().enumerate() {
            if identities[..index]
                .iter()
                .any(|other| identity.certificate.client_magic == other.certificate.client_magic)
            {
                return Err(DnscryptConfigError::InvalidCertificate(
                    "resolver identities share a client magic",
                ));
            }
        }
        let nonce_sequence = NonceSequence::random().map_err(|_| {
            DnscryptConfigError::InvalidCertificate("cannot initialize resolver nonce source")
        })?;
        Ok(Self {
            provider_name,
            identities,
            nonce_sequence: Arc::new(nonce_sequence),
        })
    }

    fn identity(&self, magic: &[u8]) -> Option<&DnscryptResolverIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.certificate.client_magic == magic)
    }

    pub(super) fn next_resolver_nonce(&self) -> Option<[u8; 12]> {
        self.nonce_sequence.next()
    }
}

/// Dedicated DNSCrypt-over-TCP listener.
#[derive(Debug, Clone)]
pub struct DnscryptTransportServer {
    config: DnscryptServerConfig,
}

impl DnscryptTransportServer {
    /// Creates a DNSCrypt listener from resolver identities.
    pub fn new(config: DnscryptServerConfig) -> Self {
        Self { config }
    }
}

impl TransportServer for DnscryptTransportServer {
    #[instrument(level = "debug", skip(self, handler), fields(address = %address))]
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), io::Error>>
    where
        H: DnsRequestHandler + 'static,
        Self: 'future,
    {
        Box::pin(async move {
            let listener = TcpListener::bind(address).await?;
            let handler = Arc::new(handler);
            let config = Arc::new(self.config);
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
            loop {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("DNSCrypt admission semaphore closed"))?;
                let (stream, peer) = crate::listener_io::accept(&listener).await?;
                let handler = Arc::clone(&handler);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_connection(stream, peer, &config, handler).await;
                });
            }
        })
    }
}

/// Dedicated DNSCrypt-over-UDP listener with response anti-amplification.
///
/// Bind a concrete local IP so replies preserve the query's destination address.
/// Wildcard IPv4 and IPv6 bindings return [`io::ErrorKind::InvalidInput`].
#[derive(Debug, Clone)]
pub struct DnscryptUdpTransportServer {
    config: DnscryptServerConfig,
}

impl DnscryptUdpTransportServer {
    /// Creates a UDP DNSCrypt listener from resolver identities.
    pub fn new(config: DnscryptServerConfig) -> Self {
        Self { config }
    }
}

impl TransportServer for DnscryptUdpTransportServer {
    #[instrument(level = "debug", skip(self, handler), fields(address = %address))]
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), io::Error>>
    where
        H: DnsRequestHandler + 'static,
        Self: 'future,
    {
        Box::pin(async move {
            crate::listener_io::require_concrete_udp_address(address)?;
            let socket = Arc::new(UdpSocket::bind(address).await?);
            let handler = Arc::new(handler);
            let config = Arc::new(self.config);
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
            let mut buffer = vec![0; MAX_PACKET_LENGTH + 1];
            loop {
                let (length, peer) = crate::listener_io::recv_from(&socket, &mut buffer).await?;
                if length > MAX_PACKET_LENGTH {
                    continue;
                }
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .map_err(|_| io::Error::other("DNSCrypt UDP semaphore closed"))?;
                let packet = buffer[..length].to_vec();
                let socket = Arc::clone(&socket);
                let handler = Arc::clone(&handler);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let Some(response) = serve_datagram(peer, &packet, &config, handler).await
                    else {
                        return;
                    };

                    if let Err(error) = send_datagram(socket.send_to(&response, peer), permit).await
                    {
                        tracing::debug!(%peer, ?error, "DNSCrypt UDP response send failed");
                    }
                });
            }
        })
    }
}

pub(super) async fn send_datagram<F>(
    send: F,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> io::Result<usize>
where
    F: std::future::Future<Output = io::Result<usize>>,
{
    // Backpressure must release admission even if the socket never becomes writable.
    let _permit = permit;
    time::timeout(SERVER_OPERATION_TIMEOUT, send)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sending DNSCrypt UDP response"))?
}

pub(super) async fn serve_datagram<H>(
    peer: SocketAddr,
    packet: &[u8],
    config: &DnscryptServerConfig,
    handler: Arc<H>,
) -> Option<Vec<u8>>
where
    H: DnsRequestHandler + 'static,
{
    if let Ok(query) = Message::from_wire(packet)
        && is_certificate_query(&query, &config.provider_name)
    {
        let mut response = certificate_response(&query, config);
        let wire = response.clone().into_wire().ok()?;
        if wire.len() <= packet.len() {
            return Some(wire);
        }
        response.headers.tc = true;
        response.answers.clear();
        response.authorities.clear();
        response.additionals.clear();
        return response
            .into_wire()
            .ok()
            .filter(|wire| wire.len() <= packet.len());
    }
    let (query_wire, query, client_nonce, client_public, identity) = decrypt_query(config, packet)?;
    let response = handler_response(query_wire, query, peer, handler).await?;
    let maximum_plaintext = packet
        .len()
        .saturating_sub(RESPONSE_HEADER_LENGTH + TAG_LENGTH)
        .min(MAX_RESPONSE_PLAINTEXT);
    if maximum_plaintext == 0 {
        return None;
    }
    let response_wire = response_wire(response, maximum_plaintext - 1)?;
    let resolver_nonce = config.next_resolver_nonce()?;
    encrypt_response(
        identity,
        client_public,
        client_nonce,
        resolver_nonce,
        &response_wire,
        packet.len(),
    )
    .ok()
}

pub(super) async fn serve_connection<H>(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: &DnscryptServerConfig,
    handler: Arc<H>,
) where
    H: DnsRequestHandler + 'static,
{
    let packet = match time::timeout(SERVER_OPERATION_TIMEOUT, read_packet(&mut stream)).await {
        Ok(Ok(packet)) => packet,
        _ => return,
    };
    if let Ok(query) = Message::from_wire(&packet)
        && is_certificate_query(&query, &config.provider_name)
    {
        let response = certificate_response(&query, config);
        if let Ok(wire) = response.into_wire() {
            let _ = time::timeout(SERVER_OPERATION_TIMEOUT, write_frame(&mut stream, &wire)).await;
        }
        let _ = stream.shutdown().await;
        return;
    }
    let Some((query_wire, query, client_nonce, client_public, identity)) =
        decrypt_query(config, &packet)
    else {
        return;
    };
    let Some(response) = handler_response(query_wire, query, peer, handler).await else {
        return;
    };
    let Some(response_wire) = response_wire(response, MAX_RESPONSE_PLAINTEXT - 1) else {
        return;
    };
    let Some(resolver_nonce) = config.next_resolver_nonce() else {
        return;
    };
    let Ok(packet) = encrypt_response(
        identity,
        client_public,
        client_nonce,
        resolver_nonce,
        &response_wire,
        MAX_PACKET_LENGTH,
    ) else {
        return;
    };
    let _ = time::timeout(SERVER_OPERATION_TIMEOUT, write_frame(&mut stream, &packet)).await;
    let _ = stream.shutdown().await;
}

// Authentication covers the complete DNS message, so signed responses cannot be truncated.
fn response_wire(mut response: Message, maximum: usize) -> Option<Vec<u8>> {
    if let Ok(wire) = response.into_wire()
        && wire.len() <= maximum
    {
        return Some(wire);
    }
    if has_tsig(&response) {
        return None;
    }
    // DNSCrypt requires TC whenever a response must be shortened to fit its
    // packet budget, including omissions from Additional. Keep this separate
    // from ordinary DNS-over-UDP's optional-RRSet omission policy.
    response.headers.tc = true;
    truncate_response(response, maximum).ok()
}

async fn handler_response<H>(
    query_wire: Vec<u8>,
    query: Message,
    peer: SocketAddr,
    handler: Arc<H>,
) -> Option<Message>
where
    H: DnsRequestHandler + 'static,
{
    let request_headers = query.headers.clone();
    let request_questions = query.questions.clone();
    let (request, response) =
        DnsRequest::channel_with_wire(query, query_wire, peer, TransportProtocol::Dnscrypt);
    let mut response = match time::timeout(SERVER_OPERATION_TIMEOUT, async {
        handler.handle(request).await;
        response.await
    })
    .await
    {
        Ok(Ok(DnsResponse::Buffered(responses))) => responses.into_single()?,
        _ => return None,
    };
    if has_tsig(&response) {
        if !authenticated_response_headers_match(&request_headers, &response)
            || (request_headers.opcode == dns::OpCode::Query
                && !same_questions(&response.questions, &request_questions))
        {
            return None;
        }
    } else {
        normalize_response_headers(&request_headers, &mut response);
        if request_headers.opcode == dns::OpCode::Query {
            if request_questions_are_safe_to_echo(&request_questions) {
                response.questions = request_questions;
            } else {
                response.questions.clear();
            }
        }
    }
    Some(response)
}

fn is_certificate_query(query: &Message, provider_name: &dns::DomainName) -> bool {
    !query.headers.qr
        && query.headers.opcode == dns::OpCode::Query
        && matches!(query.questions.as_slice(), [question]
            if question.qname.eq_dns(provider_name)
                && question.qtype == dns::QueryType::TXT
                && question.qclass == dns::QClassType::Class(dns::ClassType::IN))
}

fn certificate_response(query: &Message, config: &DnscryptServerConfig) -> Message {
    let answers = config
        .identities
        .iter()
        .map(|identity| dns::ResourceRecord {
            name: config.provider_name.clone(),
            rtype: dns::RecordType::TXT,
            class: dns::ClassType::IN,
            ttl: 3600,
            rdata: dns::RData::TXT(
                identity
                    .certificate
                    .wire
                    .chunks(255)
                    .map(<[u8]>::to_vec)
                    .collect(),
            ),
        })
        .collect();
    Message {
        headers: dns::Headers {
            id: query.headers.id,
            qr: true,
            aa: true,
            opcode: query.headers.opcode,
            rd: query.headers.rd,
            ..dns::Headers::default()
        },
        questions: query.questions.clone(),
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

type DecryptedQuery<'a> = (
    Vec<u8>,
    Message,
    [u8; 12],
    [u8; 32],
    &'a DnscryptResolverIdentity,
);

fn decrypt_query<'a>(
    config: &'a DnscryptServerConfig,
    packet: &[u8],
) -> Option<DecryptedQuery<'a>> {
    if packet.len() < QUERY_HEADER_LENGTH + TAG_LENGTH || packet.len() > MAX_PACKET_LENGTH {
        return None;
    }
    let identity = config.identity(&packet[..8])?;
    let client_public: [u8; 32] = packet[8..40].try_into().ok()?;
    let client_nonce: [u8; 12] = packet[40..52].try_into().ok()?;
    let mut nonce = [0; 24];
    nonce[..12].copy_from_slice(&client_nonce);
    let cipher = checked_box(client_public, &identity.secret_key).ok()?;
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), &packet[52..])
        .ok()?;
    let query_wire = unpad(&plaintext).ok()?;
    let query = Message::from_wire(&query_wire).ok()?;
    (!query.headers.qr).then_some((query_wire, query, client_nonce, client_public, identity))
}

fn encrypt_response(
    identity: &DnscryptResolverIdentity,
    client_public: [u8; 32],
    client_nonce: [u8; 12],
    resolver_nonce: [u8; 12],
    response_wire: &[u8],
    maximum_packet_length: usize,
) -> Result<Vec<u8>, TransportError> {
    let maximum_plaintext = maximum_packet_length
        .saturating_sub(RESPONSE_HEADER_LENGTH + TAG_LENGTH)
        .min(MAX_RESPONSE_PLAINTEXT);
    if maximum_plaintext == 0 {
        return Err(TransportError::MessageTooLong {
            length: RESPONSE_HEADER_LENGTH + TAG_LENGTH + response_wire.len() + 1,
            maximum: maximum_packet_length,
        });
    }
    let extra_blocks = usize::from(client_nonce[11] & 3);
    let plaintext = pad(response_wire, maximum_plaintext, extra_blocks)?;
    let mut nonce = [0; 24];
    nonce[..12].copy_from_slice(&client_nonce);
    nonce[12..].copy_from_slice(&resolver_nonce);
    let cipher = checked_box(client_public, &identity.secret_key)?;
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| TransportError::InvalidDnscryptProtocol("response encryption failed"))?;
    let mut packet = Vec::with_capacity(RESPONSE_HEADER_LENGTH + encrypted.len());
    packet.extend_from_slice(&RESOLVER_MAGIC);
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&encrypted);
    if packet.len() > maximum_packet_length {
        return Err(TransportError::MessageTooLong {
            length: packet.len(),
            maximum: maximum_packet_length,
        });
    }
    Ok(packet)
}
