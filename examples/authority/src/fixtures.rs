use super::Failure;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path};

pub fn certificate(directory: &Path) -> Result<CertificateDer<'static>, Failure> {
    Ok(CertificateDer::from(fs::read(directory.join("cert.der"))?))
}

pub fn private_key(directory: &Path) -> Result<PrivateKeyDer<'static>, Failure> {
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(
        directory.join("key.der"),
    )?)))
}

// These fixed keys are public fixtures for this isolated laboratory only.
pub const PROVIDER_SECRET: [u8; 32] = [31; 32];
pub const RESOLVER_SECRET: [u8; 32] = [41; 32];
