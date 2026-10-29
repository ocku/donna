use std::fmt;

use crate::constants::{MAX_TTL, character_string::MAX_OCTETS as MAX_CHARACTER_STRING_OCTETS};

/// A semantic problem in resource-record data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordValidationError {
    /// The RRSet contains no records.
    EmptyRrSet,
    /// RRSet members do not share one owner, type, and class.
    MixedRrSet,
    /// RRSet members do not share one TTL.
    InconsistentTtl {
        /// Contains the first TTL in the RRSet.
        expected: u32,
        /// Contains the conflicting TTL.
        actual: u32,
    },
    /// The TTL exceeds the RFC 2181 limit.
    TtlTooLarge {
        /// Contains the rejected TTL.
        value: u32,
    },
    /// The RRSet contains an identical DNS record.
    DuplicateRecord,
    /// The same RRSet occurs in more than one message section.
    DuplicateRrSetAcrossSections,
    /// A known or reserved TYPE uses the generic variant.
    NonCanonicalRecordType {
        /// Contains the rejected TYPE value.
        value: u16,
    },
    /// A known or reserved CLASS uses the generic variant.
    NonCanonicalClass {
        /// Contains the rejected CLASS value.
        value: u16,
    },
    /// RDATA does not match the record TYPE and CLASS.
    InvalidRDataType,
    /// TXT RDATA contains no character strings.
    EmptyTxt,
    /// TLSA or SMIMEA certificate association data contains no octets.
    EmptyCertificateAssociationData,
    /// A registered hash matching type has the wrong digest length.
    InvalidCertificateAssociationLength {
        /// Matching-type registry value.
        matching_type: u8,
        /// Actual association-data length.
        length: usize,
        /// Required digest length.
        expected: usize,
    },
    /// A CAA property tag contains no octets.
    EmptyCaaTag,
    /// A CAA property tag cannot fit in its one-octet length field.
    CaaTagTooLong {
        /// Reports the tag length in octets.
        length: usize,
    },
    /// A CAA property tag contains an octet other than an ASCII letter or digit.
    InvalidCaaTag,
    /// A CAA record selected for zone publication has reserved flag bits set.
    ReservedCaaFlags {
        /// Contains the rejected flags byte.
        value: u8,
    },
    /// A CSYNC record selected for publication has undefined flag bits set.
    ReservedCsyncFlags {
        /// Contains the rejected flags word.
        value: u16,
    },
    /// A CSYNC publisher asks the parent to synchronize a prohibited type.
    ForbiddenCsyncType {
        /// Contains the rejected RR TYPE code.
        value: u16,
    },
    /// RRSIG Labels exceeds its owner name's label count.
    RrsigLabelsTooLarge {
        /// Labels field value.
        labels: u8,
        /// Number of labels in the record owner name.
        owner_labels: usize,
    },
    /// RRSIG Type Covered is not an ordinary signable RR TYPE.
    InvalidRrsigTypeCovered {
        /// Rejected TYPE code.
        value: u16,
    },
    /// RRSIG Original TTL exceeds the RFC 2181 maximum.
    RrsigOriginalTtlTooLarge {
        /// Rejected Original TTL.
        value: u32,
    },
    /// A known DS digest has the wrong wire length.
    InvalidDsDigestLength {
        /// DS Digest Type code.
        digest_type: u8,
        /// Actual digest length.
        length: usize,
        /// Required digest length.
        expected: usize,
    },
    /// A locally published DNSKEY does not use protocol 3.
    InvalidDnskeyProtocol {
        /// Rejected protocol value.
        value: u8,
    },
    /// A locally published DNSKEY sets reserved flag bits.
    ReservedDnskeyFlags {
        /// Complete rejected flags word.
        value: u16,
    },
    /// A locally published DNSKEY sets SEP without the Zone Key flag.
    DnskeySepWithoutZoneKey,
    /// An NSEC3 or NSEC3PARAM salt exceeds its one-octet length field.
    Nsec3SaltTooLong {
        /// Salt length in octets.
        length: usize,
    },
    /// An NSEC3 next-owner hash is empty or exceeds its one-octet length field.
    InvalidNsec3HashLength {
        /// Hash length in octets.
        length: usize,
    },
    /// NSEC3 SHA-1 uses a fixed 160-bit next-owner hash.
    InvalidNsec3Sha1HashLength {
        /// Hash length in octets.
        length: usize,
    },
    /// A locally published NSEC3 record sets undefined flag bits.
    ReservedNsec3Flags {
        /// Complete rejected flags byte.
        value: u8,
    },
    /// A locally published NSEC3PARAM record has nonzero flags.
    NonzeroNsec3paramFlags {
        /// Complete rejected flags byte.
        value: u8,
    },
    /// A TSIG Time Signed value exceeds its 48-bit wire field.
    TsigTimeTooLarge {
        /// Contains the rejected timestamp.
        value: u64,
    },
    /// A TSIG MAC exceeds its two-octet length field.
    TsigMacTooLong {
        /// Reports the MAC length in octets.
        length: usize,
    },
    /// TSIG Other Data exceeds its two-octet length field.
    TsigOtherDataTooLong {
        /// Reports the Other Data length in octets.
        length: usize,
    },
    /// An EDNS option exceeds its two-octet OPTION-LENGTH field.
    EdnsOptionTooLong {
        /// Reports the option data length in octets.
        length: usize,
    },
    /// An OPT record contains more than one RFC 7830 Padding option.
    DuplicateEdnsPadding,
    /// A DAU, DHU, or N3U option occurs more than once.
    DuplicateDnssecAlgorithmSignal {
        /// Duplicated EDNS option code.
        code: u16,
    },
    /// A locally authored DAU, DHU, or N3U list contains a reserved code.
    ReservedDnssecAlgorithmCode {
        /// DAU, DHU, or N3U option code.
        option_code: u16,
        /// Rejected registry value.
        algorithm: u8,
    },
    /// An RFC 7830 Padding option is not the final EDNS option.
    EdnsPaddingNotLast,
    /// An EDE option omits its required two-octet INFO-CODE.
    ExtendedDnsErrorMissingInfoCode {
        /// Reports the EDE payload length in octets.
        length: usize,
    },
    /// An EDE option's EXTRA-TEXT is not valid UTF-8.
    ExtendedDnsErrorTextNotUtf8,
    /// A locally authored EDE option's EXTRA-TEXT is not Unicode Normalization
    /// Form C (NFC).
    ExtendedDnsErrorTextNotNfc,
    /// A locally authored EDE option's EXTRA-TEXT violates RFC 5198.
    ExtendedDnsErrorTextNotNetUnicode,
    /// Reserved EDNS Z flag bits are set on an outbound OPT record.
    NonzeroEdnsZ {
        /// Contains the rejected fifteen-bit flag field.
        value: u16,
    },
    /// A character string exceeds its one-octet length field.
    CharacterStringTooLong {
        /// Reports the string length in octets.
        length: usize,
    },
    /// RDATA exceeds its two-octet length field.
    RDataTooLong {
        /// Reports the RDATA length in octets.
        length: usize,
    },
    /// A WKS bitmap exceeds the available port-number space.
    WksBitmapTooLong {
        /// Reports the bitmap length in octets.
        length: usize,
    },
    /// A CNAME RRSet contains more than one record.
    MultipleCnameRecords,
    /// A CNAME owner also has incompatible data.
    CnameWithOtherData,
    /// Zone data contains a transient Meta-TYPE.
    MetaTypeInZone {
        /// Contains the rejected TYPE value.
        value: u16,
    },
    /// Zone records use more than one CLASS.
    MixedZoneClass,
}

impl fmt::Display for RecordValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRrSet => f.write_str("an RRSet must contain at least one resource record"),

            Self::MixedRrSet => f.write_str("RRSet records must share owner, class, and type"),
            Self::InconsistentTtl { expected, actual } => {
                write!(f, "RRSet TTLs differ: expected {expected}, found {actual}")
            }
            Self::TtlTooLarge { value } => {
                write!(f, "TTL {value} exceeds the RFC 2181 maximum of {MAX_TTL}")
            }
            Self::DuplicateRecord => f.write_str("RRSet contains a duplicate resource record"),
            Self::DuplicateRrSetAcrossSections => {
                f.write_str("an RRSet cannot be repeated across message sections")
            }
            Self::NonCanonicalRecordType { value } => {
                write!(f, "TYPE {value} uses the wrong public enum variant")
            }
            Self::NonCanonicalClass { value } => {
                write!(f, "CLASS {value} uses the wrong public enum variant")
            }
            Self::InvalidRDataType => f.write_str("record TYPE does not match its RDATA"),
            Self::EmptyTxt => f.write_str("TXT RDATA requires at least one character-string"),
            Self::EmptyCertificateAssociationData => {
                f.write_str("TLSA/SMIMEA association data must not be empty")
            }
            Self::InvalidCertificateAssociationLength {
                matching_type,
                length,
                expected,
            } => write!(
                f,
                "TLSA/SMIMEA matching type {matching_type} has {length} octets; expected {expected}"
            ),
            Self::EmptyCaaTag => f.write_str("CAA property tag must not be empty"),
            Self::CaaTagTooLong { length } => {
                write!(f, "CAA property tag length {length} exceeds {}", u8::MAX)
            }
            Self::InvalidCaaTag => {
                f.write_str("CAA property tag must contain only ASCII letters and digits")
            }
            Self::ReservedCaaFlags { value } => {
                write!(f, "reserved CAA flags are nonzero: {value:#04x}")
            }
            Self::ReservedCsyncFlags { value } => {
                write!(f, "reserved CSYNC flags are nonzero: {value:#06x}")
            }
            Self::ForbiddenCsyncType { value } => {
                write!(f, "CSYNC must not request synchronization of TYPE {value}")
            }
            Self::RrsigLabelsTooLarge {
                labels,
                owner_labels,
            } => write!(
                f,
                "RRSIG Labels value {labels} exceeds owner label count {owner_labels}"
            ),
            Self::InvalidRrsigTypeCovered { value } => {
                write!(f, "RRSIG cannot cover TYPE {value}")
            }
            Self::RrsigOriginalTtlTooLarge { value } => write!(
                f,
                "RRSIG Original TTL {value} exceeds the RFC 2181 maximum of {MAX_TTL}"
            ),
            Self::InvalidDsDigestLength {
                digest_type,
                length,
                expected,
            } => write!(
                f,
                "DS digest type {digest_type} has {length} octets; expected {expected}"
            ),
            Self::InvalidDnskeyProtocol { value } => {
                write!(f, "DNSKEY protocol is {value}; required value is 3")
            }
            Self::ReservedDnskeyFlags { value } => {
                write!(f, "reserved DNSKEY flags are nonzero: {value:#06x}")
            }
            Self::DnskeySepWithoutZoneKey => {
                f.write_str("DNSKEY SEP flag requires the Zone Key flag")
            }
            Self::Nsec3SaltTooLong { length } => {
                write!(f, "NSEC3 salt length {length} exceeds {}", u8::MAX)
            }
            Self::InvalidNsec3HashLength { length } => write!(
                f,
                "NSEC3 next-owner hash length {length} must be between 1 and {}",
                u8::MAX
            ),
            Self::InvalidNsec3Sha1HashLength { length } => write!(
                f,
                "NSEC3 SHA-1 next-owner hash length {length} must be 20 octets"
            ),
            Self::ReservedNsec3Flags { value } => {
                write!(f, "reserved NSEC3 flags are nonzero: {value:#04x}")
            }
            Self::NonzeroNsec3paramFlags { value } => {
                write!(f, "NSEC3PARAM flags are nonzero: {value:#04x}")
            }
            Self::TsigTimeTooLarge { value } => {
                write!(f, "TSIG signing time {value} exceeds its 48-bit field")
            }
            Self::TsigMacTooLong { length } => {
                write!(f, "TSIG MAC length {length} exceeds {}", u16::MAX)
            }
            Self::TsigOtherDataTooLong { length } => {
                write!(f, "TSIG Other Data length {length} exceeds {}", u16::MAX)
            }
            Self::EdnsOptionTooLong { length } => {
                write!(f, "EDNS option data length {length} exceeds {}", u16::MAX)
            }
            Self::DuplicateEdnsPadding => {
                f.write_str("an OPT record may contain only one EDNS Padding option")
            }
            Self::DuplicateDnssecAlgorithmSignal { code } => {
                write!(f, "EDNS algorithm signal option {code} is duplicated")
            }
            Self::ReservedDnssecAlgorithmCode {
                option_code,
                algorithm,
            } => write!(
                f,
                "EDNS option {option_code} contains reserved algorithm code {algorithm}"
            ),
            Self::EdnsPaddingNotLast => {
                f.write_str("the EDNS Padding option must be the final option")
            }
            Self::ExtendedDnsErrorMissingInfoCode { length } => write!(
                f,
                "EDE payload length {length} omits its two-octet INFO-CODE"
            ),
            Self::ExtendedDnsErrorTextNotUtf8 => f.write_str("EDE EXTRA-TEXT is not valid UTF-8"),
            Self::ExtendedDnsErrorTextNotNfc => f.write_str("EDE EXTRA-TEXT is not NFC-normalized"),
            Self::ExtendedDnsErrorTextNotNetUnicode => {
                f.write_str("EDE EXTRA-TEXT violates the Net-Unicode sender profile")
            }
            Self::NonzeroEdnsZ { value } => {
                write!(f, "reserved EDNS Z flags are nonzero: {value:#06x}")
            }
            Self::CharacterStringTooLong { length } => write!(
                f,
                "character-string length {length} exceeds {MAX_CHARACTER_STRING_OCTETS}"
            ),
            Self::RDataTooLong { length } => {
                write!(f, "RDATA length {length} exceeds {}", u16::MAX)
            }
            Self::WksBitmapTooLong { length } => write!(
                f,
                "WKS bitmap length {length} exceeds the 8192-octet port-number space"
            ),
            Self::MultipleCnameRecords => {
                f.write_str("a CNAME RRSet can contain only one resource record")
            }
            Self::CnameWithOtherData => {
                f.write_str("a CNAME owner cannot have resource records of another type")
            }
            Self::MetaTypeInZone { value } => {
                write!(f, "Meta-TYPE {value} cannot be stored as zone data")
            }
            Self::MixedZoneClass => {
                f.write_str("all resource records in a zone must share one class")
            }
        }
    }
}

impl std::error::Error for RecordValidationError {}
