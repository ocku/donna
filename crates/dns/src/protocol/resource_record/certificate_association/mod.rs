use std::fmt;

use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

use crate::{DnssecSecurityStatus, DomainName, DomainNameError};

/// TLSA/SMIMEA certificate-association RDATA.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateAssociation {
    /// Certificate usage registry value.
    pub certificate_usage: u8,
    /// Selector registry value.
    pub selector: u8,
    /// Matching-type registry value.
    pub matching_type: u8,
    /// Exact certificate material or its registered digest.
    pub association_data: Vec<u8>,
}

impl CertificateAssociation {
    /// Matches authenticated association data against a DER certificate and
    /// its DER SubjectPublicKeyInfo value.
    ///
    /// # Errors
    ///
    /// Returns an error unless DNSSEC authenticated the lookup, or when a
    /// registry value is not defined by RFC 6698.
    pub fn matches(
        &self,
        security: DnssecSecurityStatus,
        certificate_der: &[u8],
        subject_public_key_info_der: &[u8],
    ) -> Result<bool, CertificateAssociationError> {
        if security != DnssecSecurityStatus::Secure {
            return Err(CertificateAssociationError::Unauthenticated(security));
        }
        if self.certificate_usage > 3 {
            return Err(CertificateAssociationError::UnsupportedCertificateUsage(
                self.certificate_usage,
            ));
        }
        let selected = match self.selector {
            0 => certificate_der,
            1 => subject_public_key_info_der,
            selector => return Err(CertificateAssociationError::UnsupportedSelector(selector)),
        };
        let matches = match self.matching_type {
            0 => selected == self.association_data,
            1 => {
                ring::digest::digest(&ring::digest::SHA256, selected).as_ref()
                    == self.association_data
            }
            2 => Sha512::digest(selected)[..] == self.association_data,
            matching_type => {
                return Err(CertificateAssociationError::UnsupportedMatchingType(
                    matching_type,
                ));
            }
        };
        Ok(matches)
    }

    /// Applies certificate usages 0 through 3 to a caller-validated path.
    ///
    /// The DNS layer deliberately does not implement X.509 path validation.
    /// `pkix_valid` reports ordinary PKIX validation, while
    /// `dane_ta_path_valid` reports validation using the matching usage-2
    /// certificate as the trust anchor.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::matches`].
    pub fn evaluate_path(
        &self,
        security: DnssecSecurityStatus,
        end_entity: CertificateMaterial<'_>,
        chain: &[CertificateMaterial<'_>],
        pkix_valid: bool,
        dane_ta_path_valid: bool,
    ) -> Result<bool, CertificateAssociationError> {
        if security != DnssecSecurityStatus::Secure {
            return Err(CertificateAssociationError::Unauthenticated(security));
        }
        if self.selector > 1 {
            return Err(CertificateAssociationError::UnsupportedSelector(
                self.selector,
            ));
        }
        if self.matching_type > 2 {
            return Err(CertificateAssociationError::UnsupportedMatchingType(
                self.matching_type,
            ));
        }
        let end_entity_matches = || self.matches_material(end_entity);
        match self.certificate_usage {
            0 => Ok(pkix_valid
                && chain
                    .iter()
                    .copied()
                    .any(|certificate| self.matches_material(certificate).unwrap_or(false))),
            1 => Ok(pkix_valid && end_entity_matches()?),
            2 => Ok(dane_ta_path_valid
                && chain
                    .iter()
                    .copied()
                    .chain(std::iter::once(end_entity))
                    .any(|certificate| self.matches_material(certificate).unwrap_or(false))),
            3 => end_entity_matches(),
            value => Err(CertificateAssociationError::UnsupportedCertificateUsage(
                value,
            )),
        }
    }

    fn matches_material(
        &self,
        certificate: CertificateMaterial<'_>,
    ) -> Result<bool, CertificateAssociationError> {
        let selected = match self.selector {
            0 => certificate.certificate_der,
            1 => certificate.subject_public_key_info_der,
            selector => return Err(CertificateAssociationError::UnsupportedSelector(selector)),
        };
        match self.matching_type {
            0 => Ok(selected == self.association_data),
            1 => Ok(
                ring::digest::digest(&ring::digest::SHA256, selected).as_ref()
                    == self.association_data,
            ),
            2 => Ok(Sha512::digest(selected)[..] == self.association_data),
            value => Err(CertificateAssociationError::UnsupportedMatchingType(value)),
        }
    }

    pub(crate) fn expected_data_length(&self) -> Option<usize> {
        match self.matching_type {
            1 => Some(32),
            2 => Some(64),
            _ => None,
        }
    }
}

/// DER certificate material supplied by a TLS or S/MIME application.
#[derive(Debug, Clone, Copy)]
pub struct CertificateMaterial<'a> {
    /// Complete DER Certificate value.
    pub certificate_der: &'a [u8],
    /// DER SubjectPublicKeyInfo value from that certificate.
    pub subject_public_key_info_der: &'a [u8],
}

/// TLSA transport-protocol label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsaTransport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Stream Control Transmission Protocol.
    Sctp,
}

impl TlsaTransport {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Tcp => b"_tcp",
            Self::Udp => b"_udp",
            Self::Sctp => b"_sctp",
        }
    }
}

/// Constructs an RFC 6698 TLSA owner name.
///
/// # Errors
///
/// Returns an error when the base name is not an RFC 952 host name as updated
/// by RFC 1123, or the resulting DNS name exceeds protocol limits.
pub fn tlsa_owner_name(
    host: &DomainName,
    port: u16,
    transport: TlsaTransport,
) -> Result<DomainName, CertificateAssociationError> {
    if host.as_ref().is_empty() || !host.as_ref().iter().all(|label| valid_host_label(label)) {
        return Err(CertificateAssociationError::InvalidHostName);
    }
    let mut labels = Vec::with_capacity(host.as_ref().len() + 2);
    labels.push(format!("_{port}").into_bytes());
    labels.push(transport.label().to_vec());
    labels.extend_from_slice(host.as_ref());
    DomainName::from_labels(labels).map_err(CertificateAssociationError::InvalidOwnerName)
}

/// Constructs an RFC 8162 SMIMEA owner from an already canonicalized local
/// part and a mail domain. Non-ASCII input is normalized to NFC before hashing.
///
/// # Errors
///
/// Returns an error when the domain is the root or the resulting DNS name
/// exceeds protocol limits.
pub fn smimea_owner_name(
    canonical_local_part: &str,
    domain: &DomainName,
) -> Result<DomainName, CertificateAssociationError> {
    if domain.as_ref().is_empty() {
        return Err(CertificateAssociationError::InvalidMailDomain);
    }
    let normalized = canonical_local_part.nfc().collect::<String>();
    let digest = Sha256::digest(normalized.as_bytes());
    let mut hash_label = Vec::with_capacity(56);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &octet in &digest[..28] {
        hash_label.extend_from_slice(&[HEX[(octet >> 4) as usize], HEX[(octet & 15) as usize]]);
    }
    let mut labels = Vec::with_capacity(domain.as_ref().len() + 2);
    labels.push(hash_label);
    labels.push(b"_smimecert".to_vec());
    labels.extend_from_slice(domain.as_ref());
    DomainName::from_labels(labels).map_err(CertificateAssociationError::InvalidOwnerName)
}

fn valid_host_label(label: &[u8]) -> bool {
    label.first().is_some_and(u8::is_ascii_alphanumeric)
        && label.last().is_some_and(u8::is_ascii_alphanumeric)
        && label
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'-')
}

/// Failure to construct or securely evaluate a certificate association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateAssociationError {
    /// DNSSEC did not authenticate the lookup.
    Unauthenticated(DnssecSecurityStatus),
    /// The certificate-usage registry value is not understood.
    UnsupportedCertificateUsage(u8),
    /// The selector registry value is not understood.
    UnsupportedSelector(u8),
    /// The matching-type registry value is not understood.
    UnsupportedMatchingType(u8),
    /// The TLSA base name is not an RFC 952 host name as updated by RFC 1123.
    InvalidHostName,
    /// The SMIMEA mail domain is the root name.
    InvalidMailDomain,
    /// The constructed owner is not a valid DNS name.
    InvalidOwnerName(DomainNameError),
}

impl fmt::Display for CertificateAssociationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated(status) => {
                write!(
                    formatter,
                    "certificate association is not DNSSEC secure: {status:?}"
                )
            }
            Self::UnsupportedCertificateUsage(value) => {
                write!(formatter, "unsupported certificate usage {value}")
            }
            Self::UnsupportedSelector(value) => write!(formatter, "unsupported selector {value}"),
            Self::UnsupportedMatchingType(value) => {
                write!(formatter, "unsupported matching type {value}")
            }
            Self::InvalidHostName => formatter.write_str("invalid TLSA base host name"),
            Self::InvalidMailDomain => formatter.write_str("invalid SMIMEA mail domain"),
            Self::InvalidOwnerName(error) => {
                write!(formatter, "invalid association owner: {error}")
            }
        }
    }
}

impl std::error::Error for CertificateAssociationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidOwnerName(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
