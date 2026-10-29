use super::*;

#[derive(Clone)]
struct CachedCertificate {
    server: SocketAddr,
    certificate: DnscryptCertificate,
    fetched_at: time::Instant,
}

/// DNSCrypt v2 client using one transaction per TCP connection.
#[derive(Clone)]
pub struct DnscryptTransport {
    config: DnscryptClientConfig,
    client_secret: SecretKey,
    pub(super) nonce_sequence: Arc<NonceSequence>,
    certificate: Arc<Mutex<Option<CachedCertificate>>>,
}

impl std::fmt::Debug for DnscryptTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnscryptTransport")
            .field("provider_name", &self.config.provider_name)
            .finish_non_exhaustive()
    }
}

impl DnscryptTransport {
    /// Creates a client with a fresh X25519 key and random nonce source.
    pub fn new(config: DnscryptClientConfig) -> Result<Self, io::Error> {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).map_err(io::Error::other)?;
        Self::with_client_key(config, secret)
    }

    /// Creates a client from explicit key material and a fresh random nonce source.
    ///
    /// Recreating a client with the same key remains safe because each instance
    /// obtains independent 96-bit nonces from the operating system.
    pub fn with_client_key(
        config: DnscryptClientConfig,
        client_secret: [u8; 32],
    ) -> Result<Self, io::Error> {
        Ok(Self {
            config,
            client_secret: SecretKey::from(client_secret),
            nonce_sequence: Arc::new(NonceSequence::random().map_err(io::Error::other)?),
            certificate: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(super) fn with_deterministic_nonce(
        config: DnscryptClientConfig,
        client_secret: [u8; 32],
        nonce_prefix: [u8; 4],
    ) -> Self {
        Self {
            config,
            client_secret: SecretKey::from(client_secret),
            nonce_sequence: Arc::new(NonceSequence::deterministic(nonce_prefix)),
            certificate: Arc::new(Mutex::new(None)),
        }
    }

    async fn certificate(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<DnscryptCertificate, TransportError> {
        let mut cached = time::timeout_at(deadline, self.certificate.lock())
            .await
            .map_err(|_| TransportError::Timeout)?;
        let now = unix_time()?;
        if let Some(cached) = cached.as_ref()
            && cached.server == server
            && cached.fetched_at.elapsed() < CERTIFICATE_REFRESH
            && cached.certificate.is_valid_at(now)
        {
            return Ok(cached.certificate.clone());
        }
        let certificate = self.fetch_certificate(server, deadline).await?;
        *cached = Some(CachedCertificate {
            server,
            certificate: certificate.clone(),
            fetched_at: time::Instant::now(),
        });
        Ok(certificate)
    }

    async fn fetch_certificate(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<DnscryptCertificate, TransportError> {
        let id = self.next_client_counter()? as u16;
        let query = certificate_query(&self.config.provider_name, id)?;
        let wire = query.into_wire().map_err(TransportError::encode)?;
        let mut stream = time::timeout_at(deadline, TcpStream::connect(server))
            .await
            .map_err(|_| TransportError::Timeout)??;
        time::timeout_at(deadline, write_frame(&mut stream, &wire))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let packet = time::timeout_at(deadline, read_packet(&mut stream))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let response = Message::from_wire(&packet).map_err(TransportError::decode)?;
        select_certificate(&response, &query, &self.config, unix_time()?)
    }

    pub(super) fn next_client_nonce(&self) -> Result<[u8; 12], TransportError> {
        self.nonce_sequence
            .next()
            .ok_or(TransportError::InvalidDnscryptProtocol(
                "client nonce space exhausted",
            ))
    }

    #[allow(deprecated, reason = "Retain the atomic API supported by Rust 1.88.")]
    fn next_client_counter(&self) -> Result<u64, TransportError> {
        self.nonce_sequence
            .generated
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
                counter.checked_add(1)
            })
            .map_err(|_| TransportError::InvalidDnscryptProtocol("client nonce space exhausted"))
    }
}

pub(super) fn select_certificate(
    response: &Message,
    query: &Message,
    config: &DnscryptClientConfig,
    now: u32,
) -> Result<DnscryptCertificate, TransportError> {
    if !matches_tcp_query(response, query) {
        return Err(TransportError::InvalidDnscryptProtocol(
            "certificate response does not match its query",
        ));
    }
    let mut certificates = response
        .answers
        .iter()
        .filter(|record| {
            record.name.eq_dns(&config.provider_name)
                && record.rtype == dns::RecordType::TXT
                && record.class == dns::ClassType::IN
        })
        .filter_map(|record| match &record.rdata {
            dns::RData::TXT(strings) => {
                let blob = strings.concat();
                DnscryptCertificate::verify(&blob, &config.provider_public_key, now).ok()
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    certificates.sort_by_key(DnscryptCertificate::serial);
    certificates
        .pop()
        .ok_or(TransportError::InvalidDnscryptProtocol(
            "resolver supplied no valid supported certificate",
        ))
}

impl Transport for DnscryptTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Dnscrypt)
    }

    #[instrument(
        level = "debug",
        skip(self, query),
        fields(server = %server, transaction_id = query.headers.id, timeout = ?timeout)
    )]
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let deadline = checked_deadline(timeout)?;
            let certificate = self.certificate(server, deadline).await?;
            let query_wire = query.into_wire().map_err(TransportError::encode)?;
            let client_nonce = self.next_client_nonce()?;
            let packet =
                encrypt_query(&certificate, &self.client_secret, client_nonce, &query_wire)?;
            let mut stream = time::timeout_at(deadline, TcpStream::connect(server))
                .await
                .map_err(|_| TransportError::Timeout)??;
            time::timeout_at(deadline, write_frame(&mut stream, &packet))
                .await
                .map_err(|_| TransportError::Timeout)??;
            let response_packet = time::timeout_at(deadline, read_packet(&mut stream))
                .await
                .map_err(|_| TransportError::Timeout)??;
            let response_wire = decrypt_response(
                &certificate,
                &self.client_secret,
                client_nonce,
                &response_packet,
            )?;
            let response = Message::from_wire(&response_wire).map_err(TransportError::decode)?;
            if !matches_tcp_query(&response, query) {
                return Err(TransportError::InvalidDnscryptProtocol(
                    "decrypted response does not match the query",
                ));
            }
            Ok(response)
        })
    }
}

/// DNSCrypt v2 client that prefers UDP and retries authenticated truncated
/// responses over the mandatory TCP transport.
#[derive(Debug, Clone)]
pub struct DnscryptUdpTransport {
    tcp: DnscryptTransport,
    pub(super) padding_target: Arc<AtomicUsize>,
}

impl DnscryptUdpTransport {
    /// Creates a UDP-first client with a fresh X25519 key and random nonce source.
    pub fn new(config: DnscryptClientConfig) -> Result<Self, io::Error> {
        Ok(Self {
            tcp: DnscryptTransport::new(config)?,
            padding_target: Arc::new(AtomicUsize::new(256)),
        })
    }

    /// Creates a UDP-first client from explicit key material and a fresh random
    /// nonce source.
    pub fn with_client_key(
        config: DnscryptClientConfig,
        client_secret: [u8; 32],
    ) -> Result<Self, io::Error> {
        Ok(Self {
            tcp: DnscryptTransport::with_client_key(config, client_secret)?,
            padding_target: Arc::new(AtomicUsize::new(256)),
        })
    }

    #[cfg(test)]
    pub(super) fn with_deterministic_nonce(
        config: DnscryptClientConfig,
        client_secret: [u8; 32],
        nonce_prefix: [u8; 4],
    ) -> Self {
        Self {
            tcp: DnscryptTransport::with_deterministic_nonce(config, client_secret, nonce_prefix),
            padding_target: Arc::new(AtomicUsize::new(256)),
        }
    }

    async fn certificate(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<DnscryptCertificate, TransportError> {
        let mut cached = time::timeout_at(deadline, self.tcp.certificate.lock())
            .await
            .map_err(|_| TransportError::Timeout)?;
        let now = unix_time()?;
        if let Some(cached) = cached.as_ref()
            && cached.server == server
            && cached.fetched_at.elapsed() < CERTIFICATE_REFRESH
            && cached.certificate.is_valid_at(now)
        {
            return Ok(cached.certificate.clone());
        }
        // A lost datagram must leave time to retrieve the certificate over
        // TCP and perform the encrypted exchange within the original deadline.
        let now = time::Instant::now();
        let udp_budget = (deadline.saturating_duration_since(now) / 2).min(CERTIFICATE_UDP_TIMEOUT);
        let udp_deadline = now + udp_budget;
        let certificate = match time::timeout_at(
            udp_deadline,
            self.fetch_certificate_udp(server, udp_deadline),
        )
        .await
        {
            Ok(Ok(Some(certificate))) => certificate,
            _ => self.tcp.fetch_certificate(server, deadline).await?,
        };
        *cached = Some(CachedCertificate {
            server,
            certificate: certificate.clone(),
            fetched_at: time::Instant::now(),
        });
        Ok(certificate)
    }

    async fn fetch_certificate_udp(
        &self,
        server: SocketAddr,
        deadline: time::Instant,
    ) -> Result<Option<DnscryptCertificate>, TransportError> {
        let id = self.tcp.next_client_counter()? as u16;
        let query = padded_certificate_query(&self.tcp.config.provider_name, id)?;
        let wire = query.into_wire().map_err(TransportError::encode)?;
        let socket = udp_socket(server).await?;
        time::timeout_at(deadline, socket.send(&wire))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
        let length = time::timeout_at(deadline, socket.recv(&mut packet))
            .await
            .map_err(|_| TransportError::Timeout)??;
        if length > wire.len() || length > MAX_PACKET_LENGTH {
            return Err(TransportError::InvalidDnscryptProtocol(
                "certificate response exceeds its UDP request",
            ));
        }
        packet.truncate(length);
        let response = Message::from_wire(&packet).map_err(TransportError::decode)?;
        if response.headers.tc {
            return Ok(None);
        }
        select_certificate(&response, &query, &self.tcp.config, unix_time()?).map(Some)
    }
}

impl Transport for DnscryptUdpTransport {
    fn protocol(&self) -> Option<TransportProtocol> {
        Some(TransportProtocol::Dnscrypt)
    }

    #[instrument(
        level = "debug",
        skip(self, query),
        fields(server = %server, transaction_id = query.headers.id, timeout = ?timeout)
    )]
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        Box::pin(async move {
            let deadline = checked_deadline(timeout)?;
            let certificate = self.certificate(server, deadline).await?;
            let query_wire = query.into_wire().map_err(TransportError::encode)?;
            let client_nonce = self.tcp.next_client_nonce()?;
            let encrypted_query = encrypt_query_with_minimum(
                &certificate,
                &self.tcp.client_secret,
                client_nonce,
                &query_wire,
                self.padding_target.load(Ordering::Relaxed),
            )?;
            let socket = udp_socket(server).await?;
            time::timeout_at(deadline, socket.send(&encrypted_query))
                .await
                .map_err(|_| TransportError::Timeout)??;
            let mut packet = vec![0; MAX_PACKET_LENGTH + 1];
            loop {
                let length = time::timeout_at(deadline, socket.recv(&mut packet))
                    .await
                    .map_err(|_| TransportError::Timeout)??;
                if length > encrypted_query.len() || length > MAX_PACKET_LENGTH {
                    continue;
                }
                let Ok(response_wire) = decrypt_response(
                    &certificate,
                    &self.tcp.client_secret,
                    client_nonce,
                    &packet[..length],
                ) else {
                    continue;
                };
                let Ok(response) = Message::from_wire(&response_wire) else {
                    continue;
                };
                if !matches_tcp_query(&response, query) {
                    continue;
                }
                if response.headers.tc {
                    let maximum_target = QUERY_HEADER_LENGTH + TAG_LENGTH + MAX_QUERY_PLAINTEXT;
                    let larger_target = encrypted_query.len().saturating_mul(2).min(maximum_target);
                    self.padding_target
                        .fetch_max(larger_target, Ordering::Relaxed);
                    let remaining = deadline.saturating_duration_since(time::Instant::now());
                    return self.tcp.exchange(server, query, remaining).await;
                }
                return Ok(response);
            }
        })
    }
}

async fn udp_socket(server: SocketAddr) -> Result<UdpSocket, TransportError> {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    Ok(socket)
}

pub(super) fn padded_certificate_query(
    provider_name: &dns::DomainName,
    id: u16,
) -> Result<Message, TransportError> {
    let mut query = certificate_query(provider_name, id)?;
    let mut edns = dns::Edns::new(4096);
    edns.options.push(dns::EdnsOption::padding(0));
    query.additionals.push(edns.into_record());
    let base_length = query
        .clone()
        .into_wire()
        .map_err(TransportError::encode)?
        .len();
    let padding = 512_usize.saturating_sub(base_length);
    if let dns::RData::OPT(options) = &mut query.additionals[0].rdata {
        *options = vec![dns::EdnsOption::padding(u16::try_from(padding).map_err(
            |_| TransportError::InvalidDnscryptProtocol("certificate padding is too long"),
        )?)];
    }
    Ok(query)
}

pub(super) fn certificate_query(
    provider_name: &dns::DomainName,
    id: u16,
) -> Result<Message, TransportError> {
    Message::builder()
        .headers(dns::Headers {
            id,
            rd: true,
            ..dns::Headers::default()
        })
        .questions([dns::Question {
            qname: provider_name.clone(),
            qtype: dns::QueryType::TXT,
            qclass: dns::QClassType::Class(dns::ClassType::IN),
        }])
        .build()
        .map_err(|_| TransportError::InvalidDnscryptProtocol("cannot build certificate query"))
}
