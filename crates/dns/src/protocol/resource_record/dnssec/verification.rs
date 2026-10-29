use super::*;

/// A DNSSEC RRset signing failure.
#[derive(Debug)]
pub enum RrsigSigningError {
    /// The requested signing algorithm is not supported by this key type.
    UnsupportedAlgorithm {
        /// Rejected DNSSEC algorithm number.
        algorithm: u8,
    },
    /// DNSKEY flags do not describe an ordinary zone key.
    InvalidFlags {
        /// Rejected DNSKEY flags word.
        flags: u16,
    },
    /// PKCS#8 private-key material is malformed or not RSA.
    MalformedPrivateKey,
    /// The RSA modulus is outside RFC 5702's bounds.
    InvalidKeySize {
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Actual modulus size in bits.
        bits: usize,
        /// Minimum permitted size in bits.
        minimum: usize,
        /// Maximum permitted size in bits.
        maximum: usize,
    },
    /// The supplied records are not a signable RRset.
    InvalidRrset,
    /// The inception-to-expiration serial interval is empty or ambiguous.
    InvalidValidityPeriod,
    /// Canonical signed data could not be constructed.
    CanonicalData(RrsigDataError),
}

impl fmt::Display for RrsigSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(
                    formatter,
                    "unsupported DNSSEC signing algorithm {algorithm}"
                )
            }
            Self::InvalidFlags { flags } => {
                write!(formatter, "invalid DNSKEY signing flags {flags:#06x}")
            }
            Self::MalformedPrivateKey => formatter.write_str("malformed PKCS#8 RSA private key"),
            Self::InvalidKeySize {
                algorithm,
                bits,
                minimum,
                maximum,
            } => write!(
                formatter,
                "DNSSEC algorithm {algorithm} RSA key is {bits} bits; required range is {minimum}..={maximum}"
            ),
            Self::InvalidRrset => formatter.write_str("records do not form a signable RRset"),
            Self::InvalidValidityPeriod => {
                formatter.write_str("RRSIG validity period is empty or serially ambiguous")
            }
            Self::CanonicalData(error) => write!(formatter, "invalid signed RRset: {error}"),
        }
    }
}

impl std::error::Error for RrsigSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalData(error) => Some(error),
            _ => None,
        }
    }
}

/// An RRSIG authentication failure.
#[derive(Debug)]
pub enum RrsigVerificationError {
    /// DNSKEY protocol or Zone Key flags make it unusable for validation.
    UnusableKey,
    /// Signer name, key tag, or algorithm does not identify this DNSKEY.
    WrongKey,
    /// The RRSIG is not valid at the supplied time.
    BadTime,
    /// The algorithm is not implemented by this verifier.
    UnsupportedAlgorithm {
        /// DNSSEC algorithm number.
        algorithm: u8,
    },
    /// RSA DNSKEY exponent/modulus framing is malformed.
    MalformedPublicKey,
    /// RSA modulus is outside RFC 5702's bounds.
    InvalidKeySize {
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Actual modulus size in bits.
        bits: usize,
        /// Minimum permitted size in bits.
        minimum: usize,
        /// Maximum permitted size in bits.
        maximum: usize,
    },
    /// The canonical RRset could not be constructed.
    CanonicalData(RrsigDataError),
    /// The cryptographic signature does not verify.
    BadSignature,
}

impl fmt::Display for RrsigVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusableKey => formatter.write_str("DNSKEY is not usable for zone validation"),
            Self::WrongKey => formatter.write_str("RRSIG does not identify this DNSKEY"),
            Self::BadTime => formatter.write_str("RRSIG is outside its validity interval"),
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(formatter, "unsupported DNSSEC algorithm {algorithm}")
            }
            Self::MalformedPublicKey => formatter.write_str("malformed RSA DNSKEY public key"),
            Self::InvalidKeySize {
                algorithm,
                bits,
                minimum,
                maximum,
            } => write!(
                formatter,
                "DNSSEC algorithm {algorithm} RSA key is {bits} bits; required range is {minimum}..={maximum}"
            ),
            Self::CanonicalData(error) => write!(formatter, "invalid signed RRset: {error}"),
            Self::BadSignature => formatter.write_str("RRSIG cryptographic signature is invalid"),
        }
    }
}

impl std::error::Error for RrsigVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalData(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) fn verify_rsa(
    algorithm: u8,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), RrsigVerificationError> {
    let (exponent, modulus) = split_rsa_dnskey(public_key)?;
    let first_nonzero = modulus
        .iter()
        .position(|octet| *octet != 0)
        .ok_or(RrsigVerificationError::MalformedPublicKey)?;
    let bits = (modulus.len() - first_nonzero - 1) * 8
        + (8 - modulus[first_nonzero].leading_zeros() as usize);
    let minimum = match algorithm {
        5 | 7 | 8 => 512,
        10 => 1_024,
        _ => return Err(RrsigVerificationError::UnsupportedAlgorithm { algorithm }),
    };
    let maximum = 4_096;
    if !(minimum..=maximum).contains(&bits) {
        return Err(RrsigVerificationError::InvalidKeySize {
            algorithm,
            bits,
            minimum,
            maximum,
        });
    }
    let public_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| RrsigVerificationError::MalformedPublicKey)?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| RrsigVerificationError::BadSignature)?;
    let result = match algorithm {
        5 | 7 => {
            rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public_key).verify(data, &signature)
        }
        8 => rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(public_key)
            .verify(data, &signature),
        10 => rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha512>::new(public_key)
            .verify(data, &signature),
        _ => unreachable!("algorithm was selected above"),
    };
    result.map_err(|_| RrsigVerificationError::BadSignature)
}

pub(super) fn verify_ecdsa_p256(
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), RrsigVerificationError> {
    if public_key.len() != 64 {
        return Err(RrsigVerificationError::MalformedPublicKey);
    }
    let mut encoded = [0_u8; 65];
    encoded[0] = 4;
    encoded[1..].copy_from_slice(public_key);
    if ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &encoded)
        .verify(data, signature)
        .is_ok()
    {
        return Ok(());
    }
    // Preserve the checked path's malformed-key precedence, including when
    // both key and signature are invalid. Successful verification already
    // performed ring's strict point/scalar checks and SHA-256 verification.
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| RrsigVerificationError::MalformedPublicKey)?;
    Err(RrsigVerificationError::BadSignature)
}

fn split_rsa_dnskey(public_key: &[u8]) -> Result<(&[u8], &[u8]), RrsigVerificationError> {
    let Some(&first) = public_key.first() else {
        return Err(RrsigVerificationError::MalformedPublicKey);
    };
    let (length, offset) = if first == 0 {
        let bytes = public_key
            .get(1..3)
            .ok_or(RrsigVerificationError::MalformedPublicKey)?;
        (usize::from(u16::from_be_bytes([bytes[0], bytes[1]])), 3)
    } else {
        (usize::from(first), 1)
    };
    if length == 0 || offset + length >= public_key.len() {
        return Err(RrsigVerificationError::MalformedPublicKey);
    }
    Ok((
        &public_key[offset..offset + length],
        &public_key[offset + length..],
    ))
}
