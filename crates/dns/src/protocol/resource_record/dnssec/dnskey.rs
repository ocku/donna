use super::*;

/// DS RDATA identifying a child-zone DNSKEY.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ds {
    /// Key tag of the referenced DNSKEY.
    pub key_tag: u16,
    /// DNSSEC algorithm of the referenced DNSKEY.
    pub algorithm: u8,
    /// Digest algorithm identifier.
    pub digest_type: u8,
    /// Digest of the canonical owner name and DNSKEY RDATA.
    pub digest: Vec<u8>,
}

/// DNSKEY RDATA containing a zone or secure-entry-point public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dnskey {
    /// DNSKEY flags, including Zone Key and Secure Entry Point.
    pub flags: u16,
    /// Protocol value, which must be 3 for DNSSEC.
    pub protocol: u8,
    /// DNSSEC public-key algorithm.
    pub algorithm: u8,
    /// Algorithm-specific public-key octets.
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /// Zone Key flag.
    pub const ZONE_KEY_FLAG: u16 = 0x0100;
    /// Secure Entry Point flag.
    pub const SECURE_ENTRY_POINT_FLAG: u16 = 0x0001;

    /// Computes the RFC 4034 Appendix B key tag.
    pub fn key_tag(&self) -> u16 {
        if self.algorithm == 1 && self.public_key.len() >= 3 {
            let length = self.public_key.len();
            return (u16::from(self.public_key[length - 3]) << 8)
                | u16::from(self.public_key[length - 2]);
        }
        let mut accumulator = 0_u32;
        for (index, octet) in self.rdata_octets().into_iter().enumerate() {
            accumulator += if index & 1 == 0 {
                u32::from(octet) << 8
            } else {
                u32::from(octet)
            };
        }
        accumulator += (accumulator >> 16) & 0xffff;
        accumulator as u16
    }

    /// Constructs a DS record digest for this DNSKEY and owner name.
    ///
    /// Digest type 1 is SHA-1 as defined by RFC 4034, digest type 2 is
    /// SHA-256 as defined by RFC 4509, and digest type 4 is SHA-384 as
    /// defined by RFC 6605.
    /// Type 1 is retained for DNSSEC validation of existing delegations;
    /// it must not be used when publishing a delegation (RFC 9905).
    ///
    /// # Errors
    ///
    /// Returns an error when `digest_type` is unsupported.
    pub fn to_ds(&self, owner: &DomainName, digest_type: u8) -> Result<Ds, DsDigestError> {
        if self.protocol != 3 {
            return Err(DsDigestError::InvalidProtocol {
                protocol: self.protocol,
            });
        }
        if self.flags & Self::ZONE_KEY_FLAG == 0 {
            return Err(DsDigestError::NotZoneKey);
        }
        let mut input = Vec::with_capacity(owner.wire_len() + 4 + self.public_key.len());
        write_canonical_name(owner, &mut input);
        input.extend_from_slice(&self.rdata_octets());
        let digest = match digest_type {
            1 => <sha1::Sha1 as sha1::Digest>::digest(&input).to_vec(),
            2 => ring::digest::digest(&ring::digest::SHA256, &input)
                .as_ref()
                .to_vec(),
            4 => ring::digest::digest(&ring::digest::SHA384, &input)
                .as_ref()
                .to_vec(),
            _ => return Err(DsDigestError::UnsupportedDigest { digest_type }),
        };
        Ok(Ds {
            key_tag: self.key_tag(),
            algorithm: self.algorithm,
            digest_type,
            digest,
        })
    }

    pub(crate) fn rdata_octets(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.public_key.len());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.push(self.protocol);
        bytes.push(self.algorithm);
        bytes.extend_from_slice(&self.public_key);
        bytes
    }
}

impl Ds {
    /// Tests whether this DS identifies `dnskey` at `owner`.
    ///
    /// # Errors
    ///
    /// Returns an error when the DS digest type is unsupported.
    pub fn matches_dnskey(
        &self,
        owner: &DomainName,
        dnskey: &Dnskey,
    ) -> Result<bool, DsDigestError> {
        let expected = dnskey.to_ds(owner, self.digest_type)?;
        Ok(self.key_tag == expected.key_tag
            && self.algorithm == expected.algorithm
            && self.digest == expected.digest)
    }
}

/// An unsupported DS digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsDigestError {
    /// No digest implementation is available for this code.
    UnsupportedDigest {
        /// DS Digest Type code.
        digest_type: u8,
    },
    /// The DNSKEY protocol field is not the required value 3.
    InvalidProtocol {
        /// Rejected protocol value.
        protocol: u8,
    },
    /// The DNSKEY does not set the Zone Key flag.
    NotZoneKey,
}

impl fmt::Display for DsDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDigest { digest_type } => {
                write!(formatter, "unsupported DS digest type {digest_type}")
            }
            Self::InvalidProtocol { protocol } => {
                write!(
                    formatter,
                    "DNSKEY protocol is {protocol}; required value is 3"
                )
            }
            Self::NotZoneKey => formatter.write_str("DNSKEY does not set the Zone Key flag"),
        }
    }
}

impl std::error::Error for DsDigestError {}
