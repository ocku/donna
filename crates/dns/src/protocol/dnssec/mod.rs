use std::{collections::BTreeSet, fmt};

use crate::{
    ClassType, Dnskey, DomainName, Ds, Nsec3ClosestEncloserError, RData, RecordType,
    ResourceRecord, Rrsig, RrsigVerificationError, find_nsec3_closest_encloser,
};

/// DNSSEC validation state defined by RFC 4033.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecSecurityStatus {
    /// The data has a validated chain from a configured trust anchor.
    Secure,
    /// An authenticated proof or unsupported authenticated delegation shows
    /// that no supported chain of trust exists.
    Insecure,
    /// A supported chain was expected but validation failed.
    Bogus,
    /// The validator could not determine a security state.
    Indeterminate,
}

/// RFC 6944 implementation status for a DNSSEC signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithmStatus {
    /// Every conforming implementation was required to implement it.
    MustImplement,
    /// Implementations were prohibited from implementing it.
    MustNotImplement,
    /// Implementations were recommended to implement it.
    Recommended,
    /// Implementations could choose whether to implement it.
    Optional,
}

/// Returns the historical implementation status assigned by RFC 6944.
///
/// RFC 9364 points current implementations to RFC 8624 for modern algorithm
/// policy; this function intentionally exposes RFC 6944's named matrix rather
/// than silently treating it as current operational advice.
pub const fn rfc6944_algorithm_status(algorithm: u8) -> DnssecAlgorithmStatus {
    match algorithm {
        1 => DnssecAlgorithmStatus::MustNotImplement,
        5 => DnssecAlgorithmStatus::MustImplement,
        7 | 8 | 10 | 13 | 14 => DnssecAlgorithmStatus::Recommended,
        _ => DnssecAlgorithmStatus::Optional,
    }
}

/// Returns whether this crate can cryptographically validate `algorithm`.
///
/// Algorithms 5 and 7 are RSA/SHA-1, algorithms 8 and 10 are RSA/SHA-2,
/// and algorithm 13 is ECDSA P-256/SHA-256.
pub const fn supports_dnssec_algorithm(algorithm: u8) -> bool {
    matches!(algorithm, 5 | 7 | 8 | 10 | 13)
}

/// Returns whether this crate can calculate `digest_type` for a DS record.
///
/// Digest 1 is SHA-1, digest 2 is SHA-256, and digest 4 is SHA-384.
pub const fn supports_ds_digest(digest_type: u8) -> bool {
    matches!(digest_type, 1 | 2 | 4)
}

/// A DNSSEC validation outcome carrying authenticated data only when secure.
#[derive(Debug)]
pub enum DnssecValidation<T> {
    /// Validation reached a trust anchor and authenticated the value.
    Secure(T),
    /// The authenticated delegation has no supported chain of trust.
    Insecure,
    /// A supported authentication path existed but failed.
    Bogus(DnssecValidationError),
    /// The validator lacks enough supported information to decide.
    Indeterminate(DnssecValidationError),
}

impl<T> DnssecValidation<T> {
    /// Returns this outcome's RFC 4033 security state.
    pub const fn status(&self) -> DnssecSecurityStatus {
        match self {
            Self::Secure(_) => DnssecSecurityStatus::Secure,
            Self::Insecure => DnssecSecurityStatus::Insecure,
            Self::Bogus(_) => DnssecSecurityStatus::Bogus,
            Self::Indeterminate(_) => DnssecSecurityStatus::Indeterminate,
        }
    }

    /// Returns the authenticated value, if validation was secure.
    pub const fn secure(&self) -> Option<&T> {
        match self {
            Self::Secure(value) => Some(value),
            _ => None,
        }
    }
}

/// A reason DNSSEC validation could not produce secure data.
#[derive(Debug)]
pub enum DnssecValidationError {
    /// The supplied records do not form the expected RRset.
    InvalidRrset,
    /// No DNSKEY matched any supported authenticated DS record.
    NoMatchingDs,
    /// A DNSKEY trust anchor was not present in the apex DNSKEY RRset.
    MissingTrustAnchor,
    /// Every applicable supported signature failed validation.
    NoValidSignature,
    /// Authenticated denial records do not prove the requested fact.
    MissingDenialProof,
    /// A denial record is malformed or unsafe to use for this proof.
    InvalidDenialProof,
    /// An NSEC3 closest-encloser proof failed validation.
    Nsec3Proof(Nsec3ClosestEncloserError),
    /// A cryptographic signature failed for the reported reason.
    Signature(RrsigVerificationError),
}

impl fmt::Display for DnssecValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRrset => formatter.write_str("records do not form the expected RRset"),
            Self::NoMatchingDs => {
                formatter.write_str("no DNSKEY matches a supported authenticated DS record")
            }
            Self::MissingTrustAnchor => {
                formatter.write_str("DNSKEY trust anchor is absent from the apex DNSKEY RRset")
            }
            Self::NoValidSignature => {
                formatter.write_str("no applicable RRSIG validated the RRset")
            }
            Self::MissingDenialProof => {
                formatter.write_str("authenticated denial proof is incomplete")
            }
            Self::InvalidDenialProof => {
                formatter.write_str("authenticated denial proof is malformed or unsafe")
            }
            Self::Nsec3Proof(error) => write!(formatter, "NSEC3 denial proof failed: {error}"),
            Self::Signature(error) => write!(formatter, "RRSIG validation failed: {error}"),
        }
    }
}

impl std::error::Error for DnssecValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signature(error) => Some(error),
            Self::Nsec3Proof(error) => Some(error),
            _ => None,
        }
    }
}

mod authenticated_dnskey;
mod authentication;
mod nodata;
mod nsec;

pub use authenticated_dnskey::AuthenticatedDnskeySet;
pub use authentication::{authenticate_dnskey_with_anchor, authenticate_dnskey_with_ds};

/// Metadata produced by successful RRset signature validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRrset {
    authenticated_ttl: u32,
    signature_expiration: u32,
    signing_key_tag: u16,
    wildcard_closest_encloser: Option<DomainName>,
}

/// Kind of fact established by an authenticated denial proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecDenialKind {
    /// The queried name exists but the requested type does not.
    NoData,
    /// The queried name and an applicable wildcard do not exist.
    NameError,
    /// An authenticated denial proves that a delegation is unsigned.
    UnsignedDelegation,
    /// An authenticated denial proves that a positive wildcard answer had no
    /// closer exact match.
    WildcardExpansion,
}

/// Authenticated NSEC or NSEC3 denial metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedDenial {
    authenticated_ttl: u32,
    signature_expiration: u32,
    kind: DnssecDenialKind,
    proof_record_indices: Vec<usize>,
    opt_out: bool,
}

impl AuthenticatedDenial {
    /// Returns the earliest DNSSEC serial expiration among the proof signatures
    /// that actually authenticated the selected records.
    pub const fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Whether the next-closer denial uses an NSEC3 Opt-Out interval.
    ///
    /// The proof RRsets are authenticated, but RFC 5155 section 9.2 requires
    /// clearing AD because an unsigned delegation could exist in this span.
    pub const fn opt_out(&self) -> bool {
        self.opt_out
    }

    /// Returns the RFC 4035 upper bound on the proof's cache lifetime.
    pub const fn authenticated_ttl(&self) -> u32 {
        self.authenticated_ttl
    }

    /// Returns the fact established by the proof.
    pub const fn kind(&self) -> DnssecDenialKind {
        self.kind
    }

    /// Returns indices of the NSEC or NSEC3 records used from the supplied
    /// proof-record slice.
    pub fn proof_record_indices(&self) -> &[usize] {
        &self.proof_record_indices
    }
}

impl AuthenticatedRrset {
    /// Returns the expiration of the signature that authenticated this RRset.
    /// This is a DNSSEC serial timestamp, distinct from received record TTLs.
    pub const fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Returns the RFC 4035 upper bound on the authenticated cache lifetime.
    pub const fn authenticated_ttl(&self) -> u32 {
        self.authenticated_ttl
    }

    /// Returns the key tag of the DNSKEY that authenticated the RRset.
    pub const fn signing_key_tag(&self) -> u16 {
        self.signing_key_tag
    }

    /// Returns the closest encloser implied by a wildcard-expanded signature.
    ///
    /// A caller must authenticate denial of a closer match before treating a
    /// wildcard-expanded RRset as fully secure.
    pub const fn wildcard_closest_encloser(&self) -> Option<&DomainName> {
        self.wildcard_closest_encloser.as_ref()
    }
}

#[cfg(test)]
mod tests;

mod denial_signature_cache;
