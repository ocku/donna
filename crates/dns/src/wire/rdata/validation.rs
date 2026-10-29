use crate::RecordValidationError;
use crate::wire::WireError;

pub(crate) fn validation_error_to_wire(error: RecordValidationError) -> WireError {
    match error {
        RecordValidationError::NonCanonicalRecordType { value } => WireError::InvalidValue {
            field: "TYPE",
            value: u64::from(value),
        },
        RecordValidationError::NonCanonicalClass { value } => WireError::InvalidValue {
            field: "CLASS",
            value: u64::from(value),
        },
        RecordValidationError::TtlTooLarge { value } => WireError::InvalidValue {
            field: "TTL",
            value: u64::from(value),
        },
        RecordValidationError::CharacterStringTooLong { length } => WireError::LengthOverflow {
            field: "character-string",
            length,
            maximum: u8::MAX as usize,
        },
        RecordValidationError::RDataTooLong { length } => WireError::LengthOverflow {
            field: "RDATA",
            length,
            maximum: u16::MAX as usize,
        },
        RecordValidationError::WksBitmapTooLong { .. } => WireError::InvalidRData {
            record_type: "WKS",
            detail: "service bitmap exceeds the 16-bit port-number space",
        },
        RecordValidationError::EmptyTxt => WireError::InvalidRData {
            record_type: "TXT",
            detail: "requires at least one character-string",
        },
        RecordValidationError::EmptyCertificateAssociationData => WireError::InvalidRData {
            record_type: "TLSA/SMIMEA",
            detail: "certificate association data must not be empty",
        },
        RecordValidationError::InvalidCertificateAssociationLength { .. } => {
            WireError::InvalidRData {
                record_type: "TLSA/SMIMEA",
                detail: "association length does not match the matching type",
            }
        }
        RecordValidationError::EdnsOptionTooLong { length } => WireError::LengthOverflow {
            field: "EDNS option data",
            length,
            maximum: u16::MAX as usize,
        },
        RecordValidationError::DuplicateEdnsPadding => WireError::InvalidRData {
            record_type: "OPT",
            detail: "contains more than one EDNS Padding option",
        },
        RecordValidationError::DuplicateDnssecAlgorithmSignal { .. } => WireError::InvalidRData {
            record_type: "OPT",
            detail: "contains a duplicate DNSSEC algorithm signal",
        },
        RecordValidationError::ReservedDnssecAlgorithmCode { .. } => WireError::InvalidRData {
            record_type: "OPT",
            detail: "DNSSEC algorithm signal contains a reserved code",
        },
        RecordValidationError::EdnsPaddingNotLast => WireError::InvalidRData {
            record_type: "OPT",
            detail: "EDNS Padding is not the final option",
        },
        RecordValidationError::ExtendedDnsErrorMissingInfoCode { .. } => WireError::InvalidRData {
            record_type: "OPT",
            detail: "EDE option omits its two-octet INFO-CODE",
        },
        RecordValidationError::ExtendedDnsErrorTextNotUtf8 => WireError::InvalidRData {
            record_type: "OPT",
            detail: "EDE EXTRA-TEXT is not valid UTF-8",
        },
        RecordValidationError::ExtendedDnsErrorTextNotNfc => WireError::InvalidRData {
            record_type: "OPT",
            detail: "EDE EXTRA-TEXT is not NFC-normalized",
        },
        RecordValidationError::ExtendedDnsErrorTextNotNetUnicode => WireError::InvalidRData {
            record_type: "OPT",
            detail: "EDE EXTRA-TEXT violates the Net-Unicode sender profile",
        },
        RecordValidationError::NonzeroEdnsZ { value } => WireError::InvalidValue {
            field: "EDNS Z",
            value: u64::from(value),
        },
        RecordValidationError::EmptyCaaTag => WireError::InvalidRData {
            record_type: "CAA",
            detail: "property tag must not be empty",
        },
        RecordValidationError::CaaTagTooLong { length } => WireError::LengthOverflow {
            field: "CAA property tag",
            length,
            maximum: u8::MAX as usize,
        },
        RecordValidationError::InvalidCaaTag => WireError::InvalidRData {
            record_type: "CAA",
            detail: "property tag must contain only ASCII letters and digits",
        },
        RecordValidationError::ReservedCaaFlags { value } => WireError::InvalidValue {
            field: "CAA flags",
            value: u64::from(value),
        },
        RecordValidationError::ReservedCsyncFlags { value } => WireError::InvalidValue {
            field: "CSYNC flags",
            value: u64::from(value),
        },
        RecordValidationError::ForbiddenCsyncType { .. } => WireError::InvalidRData {
            record_type: "CSYNC",
            detail: "requests synchronization of a prohibited DNSSEC or CSYNC type",
        },
        RecordValidationError::RrsigLabelsTooLarge { labels, .. } => WireError::InvalidValue {
            field: "RRSIG Labels",
            value: u64::from(labels),
        },
        RecordValidationError::InvalidRrsigTypeCovered { value } => WireError::InvalidValue {
            field: "RRSIG Type Covered",
            value: u64::from(value),
        },
        RecordValidationError::RrsigOriginalTtlTooLarge { value } => WireError::InvalidValue {
            field: "RRSIG Original TTL",
            value: u64::from(value),
        },
        RecordValidationError::InvalidDsDigestLength { .. } => WireError::InvalidRData {
            record_type: "DS",
            detail: "digest length does not match the digest type",
        },
        RecordValidationError::InvalidDnskeyProtocol { value } => WireError::InvalidValue {
            field: "DNSKEY protocol",
            value: u64::from(value),
        },
        RecordValidationError::ReservedDnskeyFlags { value } => WireError::InvalidValue {
            field: "DNSKEY flags",
            value: u64::from(value),
        },
        RecordValidationError::DnskeySepWithoutZoneKey => WireError::InvalidRData {
            record_type: "DNSKEY",
            detail: "SEP flag is set without the Zone Key flag",
        },
        RecordValidationError::Nsec3SaltTooLong { length } => WireError::LengthOverflow {
            field: "NSEC3 salt",
            length,
            maximum: usize::from(u8::MAX),
        },
        RecordValidationError::InvalidNsec3HashLength { .. } => WireError::InvalidRData {
            record_type: "NSEC3",
            detail: "next hashed owner name must contain 1 through 255 octets",
        },
        RecordValidationError::InvalidNsec3Sha1HashLength { .. } => WireError::InvalidRData {
            record_type: "NSEC3",
            detail: "SHA-1 next hashed owner name must contain exactly 20 octets",
        },
        RecordValidationError::ReservedNsec3Flags { value } => WireError::InvalidValue {
            field: "NSEC3 flags",
            value: u64::from(value),
        },
        RecordValidationError::NonzeroNsec3paramFlags { value } => WireError::InvalidValue {
            field: "NSEC3PARAM flags",
            value: u64::from(value),
        },
        RecordValidationError::TsigTimeTooLarge { value } => WireError::InvalidValue {
            field: "TSIG Time Signed",
            value,
        },
        RecordValidationError::TsigMacTooLong { length } => WireError::LengthOverflow {
            field: "TSIG MAC",
            length,
            maximum: usize::from(u16::MAX),
        },
        RecordValidationError::TsigOtherDataTooLong { length } => WireError::LengthOverflow {
            field: "TSIG Other Data",
            length,
            maximum: usize::from(u16::MAX),
        },
        RecordValidationError::InvalidRDataType => WireError::InvalidRData {
            record_type: "resource record",
            detail: "TYPE does not match RDATA",
        },
        RecordValidationError::EmptyRrSet
        | RecordValidationError::MixedRrSet
        | RecordValidationError::MetaTypeInZone { .. }
        | RecordValidationError::MixedZoneClass
        | RecordValidationError::InconsistentTtl { .. }
        | RecordValidationError::DuplicateRecord
        | RecordValidationError::DuplicateRrSetAcrossSections
        | RecordValidationError::MultipleCnameRecords
        | RecordValidationError::CnameWithOtherData => WireError::InvalidRData {
            record_type: "resource record",
            detail: "record failed semantic validation",
        },
    }
}
