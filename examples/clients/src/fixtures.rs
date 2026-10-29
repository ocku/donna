use super::Failure;
use dns::{ClassType, DomainName, Headers, Message, QClassType, QueryType, Question};
use rustls::{RootCertStore, pki_types::CertificateDer};
use std::{fs, path::Path};

pub fn roots(directory: &Path) -> Result<RootCertStore, Failure> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fs::read(directory.join("cert.der"))?))?;
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

pub const PROVIDER_SECRET: [u8; 32] = [31; 32];
