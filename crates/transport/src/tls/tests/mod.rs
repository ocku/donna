use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use dns::{
    ClassType, FromWire, Headers, IntoWire, Message, QClassType, QueryType, Question, RData,
    RecordType, ResourceRecord,
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
        UnixTime,
    },
    sign::CertifiedKey,
};
use tokio::{io::AsyncWriteExt, sync::Notify};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::*;
use crate::{
    Transport, TransportProtocol,
    tcp::{read_frame, write_frame},
};

// A fixed self-signed P-256 certificate for `localhost`, valid from 2026-10-25
// through 2036-10-22. Keeping DER bytes here avoids certificate-generation and
// general-purpose ASN.1 parser dependencies in the test graph.
const CERTIFICATE_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x35, 0x30, 0x81, 0xdd, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00, 0xd3,
    0x00, 0x35, 0x5f, 0x4a, 0x55, 0xeb, 0xdd, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09,
    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31,
    0x30, 0x32, 0x35, 0x31, 0x35, 0x34, 0x33, 0x30, 0x33, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x30,
    0x32, 0x32, 0x31, 0x35, 0x34, 0x33, 0x30, 0x33, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x99, 0xad, 0x2f, 0xb9, 0xeb, 0x80,
    0x45, 0xa2, 0x9f, 0xb3, 0xf9, 0x5b, 0x66, 0x23, 0x78, 0x5c, 0xbf, 0xa1, 0xe8, 0x43, 0x99, 0x97,
    0xe4, 0xff, 0xb2, 0x75, 0xc3, 0x4e, 0x4e, 0xbf, 0x5c, 0xab, 0x1d, 0x38, 0x00, 0x20, 0xf7, 0xb3,
    0x2c, 0x68, 0xf4, 0x74, 0x33, 0xd1, 0x08, 0x8a, 0x37, 0x76, 0x44, 0x45, 0x3c, 0xd3, 0xf7, 0x68,
    0x5c, 0xc1, 0x26, 0x7e, 0x94, 0x6f, 0x56, 0xc1, 0xe9, 0x81, 0xa3, 0x18, 0x30, 0x16, 0x30, 0x14,
    0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
    0x68, 0x6f, 0x73, 0x74, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x6d, 0xc3, 0x2f, 0x99, 0x4f, 0x23, 0xa8, 0xb7, 0x12,
    0xf7, 0xf1, 0xfe, 0xc1, 0x96, 0xcb, 0x3f, 0x60, 0x8c, 0x76, 0x61, 0x9b, 0xd2, 0x8d, 0x71, 0x09,
    0x67, 0x28, 0x4e, 0xc7, 0x83, 0xaf, 0x02, 0x02, 0x20, 0x7c, 0xaa, 0x18, 0x7e, 0xc0, 0xbe, 0xb1,
    0x40, 0x6b, 0xda, 0x2a, 0xd9, 0xa3, 0x83, 0x94, 0xd5, 0xa5, 0xc0, 0x81, 0xcd, 0xf7, 0x47, 0xa0,
    0xbc, 0x2e, 0x4c, 0xad, 0xb0, 0x25, 0x55, 0xe2, 0x1c,
];

const PRIVATE_KEY_DER: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x4d, 0x7d, 0xdc, 0x3d, 0xac, 0xde, 0x4d, 0xe5, 0xc3, 0xf0, 0xd0, 0x69,
    0x42, 0xfd, 0x28, 0x2e, 0x3c, 0x69, 0xb5, 0xbc, 0x50, 0x88, 0xa5, 0xb6, 0x43, 0x52, 0x22, 0x6d,
    0xbe, 0x0d, 0x0a, 0xb9, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x99, 0xad, 0x2f, 0xb9, 0xeb, 0x80,
    0x45, 0xa2, 0x9f, 0xb3, 0xf9, 0x5b, 0x66, 0x23, 0x78, 0x5c, 0xbf, 0xa1, 0xe8, 0x43, 0x99, 0x97,
    0xe4, 0xff, 0xb2, 0x75, 0xc3, 0x4e, 0x4e, 0xbf, 0x5c, 0xab, 0x1d, 0x38, 0x00, 0x20, 0xf7, 0xb3,
    0x2c, 0x68, 0xf4, 0x74, 0x33, 0xd1, 0x08, 0x8a, 0x37, 0x76, 0x44, 0x45, 0x3c, 0xd3, 0xf7, 0x68,
    0x5c, 0xc1, 0x26, 0x7e, 0x94, 0x6f, 0x56, 0xc1, 0xe9, 0x81,
];

fn certificate() -> CertificateDer<'static> {
    CertificateDer::from(CERTIFICATE_DER.to_vec())
}

fn private_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(PRIVATE_KEY_DER.to_vec()))
}

fn client_config(name: &str) -> TlsClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(certificate()).unwrap();
    TlsClientConfig::new(roots, name.to_owned()).unwrap()
}

fn server_config() -> TlsServerConfig {
    TlsServerConfig::new(vec![certificate()], private_key()).unwrap()
}

#[derive(Debug)]
struct RawPublicKeyPinVerifier {
    expected_spki: Vec<u8>,
}

impl ServerCertVerifier for RawPublicKeyPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if intermediates.is_empty() && end_entity.as_ref() == self.expected_spki {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "raw public key does not match the configured SPKI pin".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "the DNS-over-TLS profile is TLS 1.3-only".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn raw_public_key_resolver_and_pin() -> (Arc<dyn ResolvesServerCert>, Vec<u8>) {
    let provider = rustls::crypto::ring::default_provider();
    let key = provider
        .key_provider
        .load_private_key(private_key())
        .unwrap();
    let spki = key.public_key().unwrap().as_ref().to_vec();
    let certified_key = CertifiedKey::new(vec![CertificateDer::from(spki.clone())], key);
    (
        Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(
            Arc::new(certified_key),
        )),
        spki,
    )
}

fn question(query_type: QueryType) -> Question {
    Question {
        qname: dns::DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
        qtype: query_type,
        qclass: QClassType::Class(ClassType::IN),
    }
}

fn query(id: u16) -> Message {
    Message::builder()
        .headers(Headers {
            id,
            ..Headers::default()
        })
        .questions([question(QueryType::A)])
        .additionals([dns::Edns::new(1232).into_record()])
        .build()
        .unwrap()
}

async fn one_connection_server<H>(handler: H) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    one_connection_server_with_config(server_config(), handler).await
}

async fn one_connection_server_with_config<H>(
    config: TlsServerConfig,
    handler: H,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    H: DnsRequestHandler + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(config.0);
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let (_, connection) = stream.get_ref();
        assert_eq!(
            connection.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(connection.alpn_protocol(), Some(DOT_ALPN));
        tcp::serve_tls_connection(stream, peer, Arc::new(handler), true).await;
    });
    (address, task)
}

struct PaddedHandler {
    calls: Arc<AtomicUsize>,
}

struct ConcurrentHandler {
    started: Arc<AtomicUsize>,
    both_started: Arc<Notify>,
}

struct ConcurrentAxfrHandler {
    started: Arc<AtomicUsize>,
    both_started: Arc<Notify>,
}

struct FixedTlsResponses(Vec<Message>);

impl DnsRequestHandler for FixedTlsResponses {
    fn handle<'future>(&'future self, request: crate::DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert_eq!(request.protocol(), TransportProtocol::Tls);
            let _ = request.respond_all(self.0.clone());
        })
    }
}

impl DnsRequestHandler for PaddedHandler {
    fn handle<'future>(&'future self, request: crate::DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.protocol(), TransportProtocol::Tls);
            assert!(
                request
                    .message()
                    .edns()
                    .unwrap()
                    .unwrap()
                    .padding()
                    .is_some()
            );
            let response = Message::builder()
                .headers(Headers {
                    qr: true,
                    ..Headers::default()
                })
                .additionals([dns::Edns::new(1232).into_record()])
                .build()
                .unwrap();
            assert!(request.respond(response));
        })
    }
}

impl DnsRequestHandler for ConcurrentHandler {
    fn handle<'future>(&'future self, request: crate::DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let started = self.started.fetch_add(1, Ordering::SeqCst) + 1;
            if started == 2 {
                self.both_started.notify_waiters();
            }
            while self.started.load(Ordering::SeqCst) < 2 {
                self.both_started.notified().await;
            }
            let response = Message::builder()
                .headers(Headers {
                    qr: true,
                    ..Headers::default()
                })
                .build()
                .unwrap();
            assert!(request.respond(response));
        })
    }
}

impl DnsRequestHandler for ConcurrentAxfrHandler {
    fn handle<'future>(&'future self, request: crate::DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert!(matches!(
                request.message().questions.as_slice(),
                [question] if question.qtype == QueryType::AXFR
            ));
            let started = self.started.fetch_add(1, Ordering::SeqCst) + 1;
            if started == 2 {
                self.both_started.notify_waiters();
            }
            while self.started.load(Ordering::SeqCst) < 2 {
                self.both_started.notified().await;
            }
            let response = Message::builder()
                .headers(Headers {
                    qr: true,
                    aa: true,
                    ..Headers::default()
                })
                .answers([soa(), soa()])
                .build_unchecked();
            assert!(request.respond(response));
        })
    }
}

fn soa() -> ResourceRecord {
    ResourceRecord {
        name: question(QueryType::AXFR).qname,
        rtype: RecordType::SOA,
        class: ClassType::IN,
        ttl: 60,
        rdata: RData::SOA {
            mname: dns::DomainName::root(),
            rname: dns::DomainName::root(),
            serial: 1,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        },
    }
}

mod authentication;
mod axfr;
mod sessions;
mod validation;

mod signed_responses;

mod edns_errors;
