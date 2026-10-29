use super::*;

/// Authenticated classical DNSCrypt v2 resolver certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnscryptCertificate {
    pub(super) wire: Vec<u8>,
    pub(super) resolver_public_key: [u8; 32],
    pub(super) client_magic: [u8; 8],
    pub(super) serial: u32,
    pub(super) valid_from: u32,
    pub(super) valid_until: u32,
}

impl DnscryptCertificate {
    /// Signs a classical Box-XChaChaPoly certificate with an Ed25519 provider key.
    pub fn sign(
        provider_key: &[u8; 32],
        resolver_public_key: [u8; 32],
        client_magic: [u8; 8],
        serial: u32,
        valid_from: u32,
        valid_until: u32,
    ) -> Result<Self, DnscryptConfigError> {
        if valid_from >= valid_until {
            return Err(DnscryptConfigError::InvalidCertificate(
                "validity interval is empty or inverted",
            ));
        }
        validate_client_magic(&client_magic)?;
        validate_resolver_key(resolver_public_key)?;
        let signing_key = SigningKey::from_bytes(provider_key);
        let mut signed = Vec::with_capacity(CERTIFICATE_MIN_LENGTH - 72);
        signed.extend_from_slice(&resolver_public_key);
        signed.extend_from_slice(&client_magic);
        signed.extend_from_slice(&serial.to_be_bytes());
        signed.extend_from_slice(&valid_from.to_be_bytes());
        signed.extend_from_slice(&valid_until.to_be_bytes());
        let signature = signing_key.sign(&signed).to_bytes();
        let mut wire = Vec::with_capacity(CERTIFICATE_MIN_LENGTH);
        wire.extend_from_slice(CERT_MAGIC);
        wire.extend_from_slice(&ES_VERSION);
        wire.extend_from_slice(&MINOR_VERSION);
        wire.extend_from_slice(&signature);
        wire.extend_from_slice(&signed);
        Ok(Self {
            wire,
            resolver_public_key,
            client_magic,
            serial,
            valid_from,
            valid_until,
        })
    }

    /// Parses and verifies one certificate blob with a provisioned provider key.
    pub fn verify(
        wire: &[u8],
        provider_public_key: &[u8; 32],
        now: u32,
    ) -> Result<Self, DnscryptConfigError> {
        if wire.len() < CERTIFICATE_MIN_LENGTH {
            return Err(DnscryptConfigError::InvalidCertificate(
                "certificate is shorter than 124 bytes",
            ));
        }
        if &wire[..4] != CERT_MAGIC {
            return Err(DnscryptConfigError::InvalidCertificate(
                "certificate magic does not match",
            ));
        }
        if wire[4..6] != ES_VERSION || wire[6..8] != MINOR_VERSION {
            return Err(DnscryptConfigError::InvalidCertificate(
                "unsupported encryption system or minor version",
            ));
        }
        let provider = VerifyingKey::from_bytes(provider_public_key)
            .map_err(|_| DnscryptConfigError::InvalidProviderKey)?;
        let signature_bytes: [u8; 64] = wire[8..72]
            .try_into()
            .map_err(|_| DnscryptConfigError::InvalidCertificate("invalid signature length"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        provider
            .verify_strict(&wire[72..], &signature)
            .map_err(|_| {
                DnscryptConfigError::InvalidCertificate("signature verification failed")
            })?;
        let resolver_public_key = wire[72..104]
            .try_into()
            .map_err(|_| DnscryptConfigError::InvalidCertificate("resolver key is incomplete"))?;
        validate_resolver_key(resolver_public_key)?;
        let client_magic = wire[104..112]
            .try_into()
            .map_err(|_| DnscryptConfigError::InvalidCertificate("client magic is incomplete"))?;
        validate_client_magic(&client_magic)?;
        let serial = read_u32(&wire[112..116]);
        let valid_from = read_u32(&wire[116..120]);
        let valid_until = read_u32(&wire[120..124]);
        if valid_from >= valid_until {
            return Err(DnscryptConfigError::InvalidCertificate(
                "validity interval is empty or inverted",
            ));
        }
        if now < valid_from || now > valid_until {
            return Err(DnscryptConfigError::InvalidCertificate(
                "certificate is not currently valid",
            ));
        }
        Ok(Self {
            wire: wire.to_vec(),
            resolver_public_key,
            client_magic,
            serial,
            valid_from,
            valid_until,
        })
    }

    /// Returns the complete signed certificate blob carried in TXT RDATA.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the resolver short-term X25519 public key.
    pub const fn resolver_public_key(&self) -> [u8; 32] {
        self.resolver_public_key
    }

    /// Returns the opaque query magic identifying this certificate.
    pub const fn client_magic(&self) -> [u8; 8] {
        self.client_magic
    }

    /// Returns the certificate serial number.
    pub const fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns the inclusive certificate expiration time as a Unix timestamp.
    pub const fn valid_until(&self) -> u32 {
        self.valid_until
    }

    pub(super) fn is_valid_at(&self, now: u32) -> bool {
        self.valid_from <= now && now <= self.valid_until
    }
}

fn validate_resolver_key(public_key: [u8; 32]) -> Result<(), DnscryptConfigError> {
    if !valid_public_key(public_key) {
        return Err(DnscryptConfigError::InvalidCertificate(
            "resolver public key has low order",
        ));
    }
    Ok(())
}

fn validate_client_magic(client_magic: &[u8; 8]) -> Result<(), DnscryptConfigError> {
    if client_magic[..7] == [0; 7]
        || client_magic == &RESOLVER_MAGIC
        || client_magic == &RESUME_MAGIC
    {
        return Err(DnscryptConfigError::InvalidCertificate(
            "client magic uses a reserved prefix",
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("caller supplies four bytes"))
}

/// Client provisioning data: provider name and long-term Ed25519 public key.
#[derive(Debug, Clone)]
pub struct DnscryptClientConfig {
    pub(super) provider_name: dns::DomainName,
    pub(super) provider_public_key: [u8; 32],
}

impl DnscryptClientConfig {
    /// Builds client provisioning for a standard
    /// `2.dnscrypt-cert.<zone>` provider name.
    pub fn new(
        zone: dns::DomainName,
        provider_public_key: [u8; 32],
    ) -> Result<Self, DnscryptConfigError> {
        VerifyingKey::from_bytes(&provider_public_key)
            .map_err(|_| DnscryptConfigError::InvalidProviderKey)?;
        let mut labels = vec![b"2".to_vec(), b"dnscrypt-cert".to_vec()];
        labels.extend(zone.as_ref().iter().cloned());
        let provider_name = dns::DomainName::from_labels(labels)
            .map_err(|_| DnscryptConfigError::InvalidProviderName)?;
        Ok(Self {
            provider_name,
            provider_public_key,
        })
    }

    /// Builds provisioning for an explicitly configured provider name.
    pub fn with_provider_name(
        provider_name: dns::DomainName,
        provider_public_key: [u8; 32],
    ) -> Result<Self, DnscryptConfigError> {
        VerifyingKey::from_bytes(&provider_public_key)
            .map_err(|_| DnscryptConfigError::InvalidProviderKey)?;
        Ok(Self {
            provider_name,
            provider_public_key,
        })
    }
}
