mod caa;
mod certificate_association;
mod class;
mod csync;
mod dnssec;
mod key;
mod rdata;
mod record_type;
mod rrset;
mod sig;
mod tsig;

pub use caa::Caa;
pub(crate) use caa::is_valid_caa_property_tag;
pub use certificate_association::{
    CertificateAssociation, CertificateAssociationError, CertificateMaterial, TlsaTransport,
    smimea_owner_name, tlsa_owner_name,
};
pub use class::{ClassType, QClassParseError, QClassType};
pub use csync::{Csync, TypeBitmap, TypeBitmapError};
pub(crate) use dnssec::canonical_name_cmp;
pub use dnssec::{
    Dnskey, Ds, DsDigestError, EcdsaP256DnssecSigningKey, Nsec, Nsec3, Nsec3Chain, Nsec3ChainError,
    Nsec3ClosestEncloserError, Nsec3ClosestEncloserProof, Nsec3HashError, Nsec3ProofError,
    Nsec3param, Rrsig, RrsigDataError, RrsigSigningError, RrsigVerificationError,
    RsaDnssecSigningKey, find_nsec3_closest_encloser,
};
pub use key::Key;
pub use rdata::RData;
pub use record_type::RecordType;
pub use rrset::RecordValidationError;
pub(crate) use rrset::{
    same_record, same_rrset_key, validate_rdata_forwarded, validate_received_edns_options,
    validate_zone_records,
};
pub use sig::Sig;
pub use tsig::{Tsig, TsigAlgorithm, TsigErrorCode};

use crate::protocol::DomainName;

/// A DNS resource record.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    /// Identifies the node that owns this resource record.
    pub name: DomainName,
    /// Identifies the resource-record TYPE.
    pub rtype: RecordType,
    /// Identifies the resource-record CLASS.
    pub class: ClassType,
    /// Specifies how many seconds the record can be cached.
    ///
    /// A zero TTL permits use only for the current transaction.
    pub ttl: u32,
    /// Describes the resource according to its TYPE and CLASS.
    ///
    /// Encoding derives the RFC 1035 `RDLENGTH` field from this value.
    pub rdata: RData,
}

impl ResourceRecord {
    /// Compares DNS identity, including case-insensitive names in RDATA.
    pub fn eq_dns(&self, other: &Self) -> bool {
        self.name.eq_dns(&other.name)
            && self.rtype == other.rtype
            && self.class == other.class
            && rrset::same_rdata(&self.rdata, &other.rdata)
    }
}
