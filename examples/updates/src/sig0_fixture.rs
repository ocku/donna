//! Fixed Ed25519 fixture shared with the independent Python SIG(0) client.

use crate::Failure;
use dns::{DomainName, Sig0SigningKey};

pub fn key() -> Result<Sig0SigningKey, Failure> {
    let seed = [51; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    // PKCS#8 OneAsymmetricKey, Ed25519, version 2 with public key.
    let mut der = vec![
        0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&seed);
    der.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
    der.extend_from_slice(&public);
    Ok(Sig0SigningKey::from_ed25519_pkcs8(
        DomainName::from_dotted("sig0-key.example.test.")?,
        0,
        3,
        &der,
    )?)
}
