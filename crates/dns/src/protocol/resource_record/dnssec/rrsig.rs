use super::*;

/// RRSIG RDATA authenticating one RRSet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rrsig {
    /// RR TYPE covered by the signature.
    pub type_covered: u16,
    /// DNSSEC signature algorithm.
    pub algorithm: u8,
    /// Number of labels in the original owner name.
    pub labels: u8,
    /// Original TTL of the covered RRSet.
    pub original_ttl: u32,
    /// Latest valid signature time modulo 2^32 Unix seconds.
    pub signature_expiration: u32,
    /// Earliest valid signature time modulo 2^32 Unix seconds.
    pub signature_inception: u32,
    /// Key tag of the signing DNSKEY.
    pub key_tag: u16,
    /// Owner name of the signing DNSKEY.
    pub signer_name: DomainName,
    /// Algorithm-specific signature octets.
    pub signature: Vec<u8>,
}

impl Rrsig {
    /// Builds the exact RFC 4034 data covered by this signature.
    ///
    /// The signature field itself is omitted. Domain names are lowercased and
    /// uncompressed, cached TTLs are replaced with [`Self::original_ttl`], a
    /// wildcard owner is reconstructed from [`Self::labels`], and records are
    /// sorted by canonical RDATA.
    ///
    /// # Errors
    ///
    /// Returns an error if `records` is empty, is not one RRset covered by
    /// this RRSIG, contains a duplicate, or cannot be represented on the DNS
    /// wire.
    pub fn signed_data(&self, records: &[ResourceRecord]) -> Result<Vec<u8>, RrsigDataError> {
        let first = records.first().ok_or(RrsigDataError::EmptyRrset)?;
        if u16::from(first.rtype) != self.type_covered {
            return Err(RrsigDataError::TypeCoveredMismatch);
        }
        if first.rtype.is_meta_type() {
            return Err(RrsigDataError::TransientType);
        }
        let owner = signed_owner(&first.name, self.labels)?;
        let mut canonical_rdatas = Vec::with_capacity(records.len());
        for record in records {
            record.validate().map_err(RrsigDataError::InvalidRecord)?;
            if !record.name.eq_dns(&first.name)
                || record.rtype != first.rtype
                || record.class != first.class
                || u16::from(record.rtype) != self.type_covered
            {
                return Err(RrsigDataError::MixedRrset);
            }
            canonical_rdatas.push(canonical_rdata(&record.rdata)?);
        }
        canonical_rdatas.sort_unstable();
        if canonical_rdatas.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RrsigDataError::DuplicateRecord);
        }

        let mut output = Vec::new();
        output.extend_from_slice(&self.type_covered.to_be_bytes());
        output.push(self.algorithm);
        output.push(self.labels);
        output.extend_from_slice(&self.original_ttl.to_be_bytes());
        output.extend_from_slice(&self.signature_expiration.to_be_bytes());
        output.extend_from_slice(&self.signature_inception.to_be_bytes());
        output.extend_from_slice(&self.key_tag.to_be_bytes());
        write_canonical_name(&self.signer_name, &mut output);

        for rdata in canonical_rdatas {
            write_canonical_name(&owner, &mut output);
            output.extend_from_slice(&self.type_covered.to_be_bytes());
            output.extend_from_slice(&first.class.value().to_be_bytes());
            output.extend_from_slice(&self.original_ttl.to_be_bytes());
            let length = u16::try_from(rdata.len()).map_err(|_| RrsigDataError::RDataTooLong {
                length: rdata.len(),
            })?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&rdata);
        }
        Ok(output)
    }

    /// Verifies this RRSIG with a supported RSA or ECDSA DNSKEY.
    ///
    /// `now` is a 32-bit Unix timestamp and is compared using RFC 1982 serial
    /// arithmetic, as required for RRSIG inception and expiration fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable key, unsupported algorithm, invalid
    /// validity interval, malformed canonical data, or signature mismatch.
    pub fn verify(
        &self,
        records: &[ResourceRecord],
        key_name: &DomainName,
        dnskey: &Dnskey,
        now: u32,
    ) -> Result<(), RrsigVerificationError> {
        self.verify_with_cache(records, key_name, dnskey, now, None)
    }

    pub(crate) fn verify_with_cache(
        &self,
        records: &[ResourceRecord],
        key_name: &DomainName,
        dnskey: &Dnskey,
        now: u32,
        cache: Option<&crate::protocol::SuccessfulSignatureCache>,
    ) -> Result<(), RrsigVerificationError> {
        if dnskey.protocol != 3 || dnskey.flags & Dnskey::ZONE_KEY_FLAG == 0 {
            return Err(RrsigVerificationError::UnusableKey);
        }
        if !self.signer_name.eq_dns(key_name)
            || self.key_tag != dnskey.key_tag()
            || self.algorithm != dnskey.algorithm
        {
            return Err(RrsigVerificationError::WrongKey);
        }
        let lifetime = self
            .signature_expiration
            .wrapping_sub(self.signature_inception);
        if lifetime >= (1_u32 << 31) || now.wrapping_sub(self.signature_inception) > lifetime {
            return Err(RrsigVerificationError::BadTime);
        }
        let data = self
            .signed_data(records)
            .map_err(RrsigVerificationError::CanonicalData)?;
        let verify = || match self.algorithm {
            5 | 7 | 8 | 10 => {
                verify_rsa(self.algorithm, &dnskey.public_key, &data, &self.signature)
            }
            13 => verify_ecdsa_p256(&dnskey.public_key, &data, &self.signature),
            algorithm => Err(RrsigVerificationError::UnsupportedAlgorithm { algorithm }),
        };
        match cache {
            Some(cache) => cache.verify(
                self.algorithm,
                &dnskey.public_key,
                &data,
                &self.signature,
                verify,
            ),
            None => verify(),
        }
    }
}

/// An RSA/SHA-1 or RSA/SHA-2 DNSSEC signing key.
pub struct RsaDnssecSigningKey {
    private_key: rsa::RsaPrivateKey,
    dnskey: Dnskey,
}

impl fmt::Debug for RsaDnssecSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RsaDnssecSigningKey")
            .field("dnskey", &self.dnskey)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl RsaDnssecSigningKey {
    /// Loads a PKCS#8 RSA private key and constructs its DNSKEY representation.
    ///
    /// `algorithm` must be 5 or 7 (RSA/SHA-1), 8 (RSA/SHA-256), or 10
    /// (RSA/SHA-512). `flags` may contain the Zone Key flag and optional
    /// Secure Entry Point flag.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material, unusable DNSKEY flags, an
    /// unsupported algorithm, or an RSA modulus outside RFC 5702's bounds.
    pub fn from_pkcs8_der(
        flags: u16,
        algorithm: u8,
        pkcs8_der: &[u8],
    ) -> Result<Self, RrsigSigningError> {
        if !matches!(algorithm, 5 | 7 | 8 | 10) {
            return Err(RrsigSigningError::UnsupportedAlgorithm { algorithm });
        }
        if flags & Dnskey::ZONE_KEY_FLAG == 0
            || flags & !(Dnskey::ZONE_KEY_FLAG | Dnskey::SECURE_ENTRY_POINT_FLAG) != 0
        {
            return Err(RrsigSigningError::InvalidFlags { flags });
        }
        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)
            .map_err(|_| RrsigSigningError::MalformedPrivateKey)?;
        let bits = private_key.n().bits();
        let minimum = if matches!(algorithm, 5 | 7 | 8) {
            512
        } else {
            1_024
        };
        let maximum = 4_096;
        if !(minimum..=maximum).contains(&bits) {
            return Err(RrsigSigningError::InvalidKeySize {
                algorithm,
                bits,
                minimum,
                maximum,
            });
        }
        let exponent = private_key.e().to_bytes_be();
        let modulus = private_key.n().to_bytes_be();
        let mut public_key = Vec::with_capacity(3 + exponent.len() + modulus.len());
        if exponent.len() < 256 {
            public_key.push(exponent.len() as u8);
        } else {
            let length = u16::try_from(exponent.len())
                .map_err(|_| RrsigSigningError::MalformedPrivateKey)?;
            public_key.push(0);
            public_key.extend_from_slice(&length.to_be_bytes());
        }
        public_key.extend_from_slice(&exponent);
        public_key.extend_from_slice(&modulus);
        Ok(Self {
            private_key,
            dnskey: Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key,
            },
        })
    }

    /// Returns the public DNSKEY corresponding to this private key.
    pub const fn dnskey(&self) -> &Dnskey {
        &self.dnskey
    }

    /// Signs one ordinary zone RRset and returns its RRSIG RDATA.
    ///
    /// The Original TTL is taken from the RRset. A wildcard owner automatically
    /// omits its asterisk label from the RRSIG Labels field.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed/mixed RRset, an owner outside the
    /// signer zone, inconsistent TTLs, or an invalid serial-time interval.
    pub fn sign_rrset(
        &self,
        records: &[ResourceRecord],
        signer_name: &DomainName,
        signature_inception: u32,
        signature_expiration: u32,
    ) -> Result<Rrsig, RrsigSigningError> {
        let first = records.first().ok_or(RrsigSigningError::InvalidRrset)?;
        if !first.name.is_descendant_of(signer_name)
            || records.iter().any(|record| record.ttl != first.ttl)
        {
            return Err(RrsigSigningError::InvalidRrset);
        }
        let lifetime = signature_expiration.wrapping_sub(signature_inception);
        if lifetime == 0 || lifetime >= (1_u32 << 31) {
            return Err(RrsigSigningError::InvalidValidityPeriod);
        }
        let owner_labels = first.name.as_ref();
        let labels = owner_labels.len()
            - usize::from(
                owner_labels
                    .first()
                    .is_some_and(|label| label.as_slice() == b"*"),
            );
        let labels = u8::try_from(labels).map_err(|_| RrsigSigningError::InvalidRrset)?;
        let mut rrsig = Rrsig {
            type_covered: u16::from(first.rtype),
            algorithm: self.dnskey.algorithm,
            labels,
            original_ttl: first.ttl,
            signature_expiration,
            signature_inception,
            key_tag: self.dnskey.key_tag(),
            signer_name: signer_name.clone(),
            signature: Vec::new(),
        };
        let data = rrsig
            .signed_data(records)
            .map_err(RrsigSigningError::CanonicalData)?;
        rrsig.signature = match self.dnskey.algorithm {
            5 | 7 => rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(self.private_key.clone())
                .sign(&data)
                .to_vec(),
            8 => rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(self.private_key.clone())
                .sign(&data)
                .to_vec(),
            10 => rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(self.private_key.clone())
                .sign(&data)
                .to_vec(),
            _ => unreachable!("constructor restricts the signing algorithm"),
        };
        Ok(rrsig)
    }
}

/// An RFC 6605 ECDSA P-256/SHA-256 DNSSEC signing key.
pub struct EcdsaP256DnssecSigningKey {
    private_key: p256::ecdsa::SigningKey,
    dnskey: Dnskey,
}

impl fmt::Debug for EcdsaP256DnssecSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcdsaP256DnssecSigningKey")
            .field("dnskey", &self.dnskey)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl EcdsaP256DnssecSigningKey {
    /// Loads a PKCS#8 P-256 private key and constructs an algorithm 13 DNSKEY.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material or unusable DNSKEY flags.
    pub fn from_pkcs8_der(flags: u16, pkcs8_der: &[u8]) -> Result<Self, RrsigSigningError> {
        if flags & Dnskey::ZONE_KEY_FLAG == 0
            || flags & !(Dnskey::ZONE_KEY_FLAG | Dnskey::SECURE_ENTRY_POINT_FLAG) != 0
        {
            return Err(RrsigSigningError::InvalidFlags { flags });
        }
        let private_key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|_| RrsigSigningError::MalformedPrivateKey)?;
        let encoded = private_key.verifying_key().to_encoded_point(false);
        let public_key = encoded
            .as_bytes()
            .get(1..)
            .ok_or(RrsigSigningError::MalformedPrivateKey)?
            .to_vec();
        Ok(Self {
            private_key,
            dnskey: Dnskey {
                flags,
                protocol: 3,
                algorithm: 13,
                public_key,
            },
        })
    }

    /// Returns the public DNSKEY corresponding to this private key.
    pub const fn dnskey(&self) -> &Dnskey {
        &self.dnskey
    }

    /// Signs one ordinary zone RRset with deterministic ECDSA P-256/SHA-256.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed/mixed RRset, an owner outside the
    /// signer zone, inconsistent TTLs, or an invalid serial-time interval.
    pub fn sign_rrset(
        &self,
        records: &[ResourceRecord],
        signer_name: &DomainName,
        signature_inception: u32,
        signature_expiration: u32,
    ) -> Result<Rrsig, RrsigSigningError> {
        let mut rrsig = unsigned_rrsig(
            records,
            signer_name,
            self.dnskey.algorithm,
            self.dnskey.key_tag(),
            signature_inception,
            signature_expiration,
        )?;
        let data = rrsig
            .signed_data(records)
            .map_err(RrsigSigningError::CanonicalData)?;
        let signature: p256::ecdsa::Signature = self.private_key.sign(&data);
        rrsig.signature = signature.to_bytes().to_vec();
        Ok(rrsig)
    }
}

fn unsigned_rrsig(
    records: &[ResourceRecord],
    signer_name: &DomainName,
    algorithm: u8,
    key_tag: u16,
    signature_inception: u32,
    signature_expiration: u32,
) -> Result<Rrsig, RrsigSigningError> {
    let first = records.first().ok_or(RrsigSigningError::InvalidRrset)?;
    if !first.name.is_descendant_of(signer_name)
        || records.iter().any(|record| record.ttl != first.ttl)
    {
        return Err(RrsigSigningError::InvalidRrset);
    }
    let lifetime = signature_expiration.wrapping_sub(signature_inception);
    if lifetime == 0 || lifetime >= (1_u32 << 31) {
        return Err(RrsigSigningError::InvalidValidityPeriod);
    }
    let owner_labels = first.name.as_ref();
    let labels = owner_labels.len()
        - usize::from(
            owner_labels
                .first()
                .is_some_and(|label| label.as_slice() == b"*"),
        );
    Ok(Rrsig {
        type_covered: u16::from(first.rtype),
        algorithm,
        labels: u8::try_from(labels).map_err(|_| RrsigSigningError::InvalidRrset)?,
        original_ttl: first.ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name: signer_name.clone(),
        signature: Vec::new(),
    })
}
