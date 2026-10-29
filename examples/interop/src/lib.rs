use std::{error::Error, fs, path::Path};

use dns::{ClassType, DomainName, Headers, Message, QClassType, QueryType, Question};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

pub type Failure = Box<dyn Error + Send + Sync>;

pub fn certificate(directory: &Path) -> Result<CertificateDer<'static>, Failure> {
    Ok(CertificateDer::from(fs::read(directory.join("cert.der"))?))
}

pub fn private_key(directory: &Path) -> Result<PrivateKeyDer<'static>, Failure> {
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(
        directory.join("key.der"),
    )?)))
}

pub fn roots(directory: &Path) -> Result<RootCertStore, Failure> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(directory)?)?;
    Ok(roots)
}

pub fn query(name: &str) -> Result<Message, Failure> {
    Ok(Message::builder()
        .headers(Headers {
            id: 1234,
            rd: true,
            ..Headers::default()
        })
        .questions([Question {
            qname: DomainName::from_dotted(name)?,
            qtype: QueryType::A,
            qclass: QClassType::Class(ClassType::IN),
        }])
        .build()?)
}

// These fixed keys are public fixtures for this isolated laboratory only.
pub const PROVIDER_SECRET: [u8; 32] = [31; 32];
pub const RESOLVER_SECRET: [u8; 32] = [41; 32];
