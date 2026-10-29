use std::fmt;

use super::HeaderFieldValueError;
use crate::RecordValidationError;

/// A message section cannot fit in its RFC 1035 unsigned 16-bit count field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionTooLongError {
    /// Identifies the oversized section.
    pub section: &'static str,
    /// Reports the number of entries in the section.
    pub length: usize,
}

impl fmt::Display for SectionTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} section has {} entries; RFC 1035 permits at most {}",
            self.section,
            self.length,
            u16::MAX
        )
    }
}

impl std::error::Error for SectionTooLongError {}

/// A semantic problem in an outbound DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageValidationError {
    /// A section count exceeds the header field width.
    SectionTooLong(SectionTooLongError),
    /// A header field cannot be emitted.
    InvalidHeader(HeaderFieldValueError),
    /// A question uses a noncanonical type or class representation.
    InvalidQuestion {
        /// Identifies the zero-based question.
        index: usize,
        /// Identifies the invalid field.
        field: &'static str,
        /// Contains the rejected value.
        value: u16,
    },
    /// A resource record violates an outbound invariant.
    InvalidRecord {
        /// Identifies the containing message section.
        section: &'static str,
        /// Identifies the zero-based record within the section.
        index: usize,
        /// Describes the record violation.
        error: RecordValidationError,
    },
    /// A query sets fields that have meaning only in a response.
    ResponseOnlyQueryFields,
    /// A standard query request contains invalid answer or authority data.
    InvalidQueryRequestSections,
    /// An inverse query request contains invalid sections.
    InvalidIqueryRequestSections,
    /// An RFC 2136 UPDATE message has invalid flags or section data.
    InvalidUpdateMessage,
    /// An RFC 1996 NOTIFY message has invalid flags or section data.
    InvalidNotifyMessage,
    /// A successful AXFR response contains invalid header or section data.
    InvalidAxfrResponseFields,
    /// An authoritative response answers a QCLASS ANY question.
    AuthoritativeAnyClass,
    /// An authoritative negative response has invalid answer data or omits a
    /// suitable SOA.
    InvalidAuthoritativeNegativeResponse,
    /// An OPT pseudo-record appears outside the additional section.
    OptOutsideAdditional,
    /// More than one OPT pseudo-record appears in the message.
    MultipleOpt,
    /// A TSIG meta-record appears outside the additional section.
    TsigOutsideAdditional,
    /// More than one TSIG meta-record appears in the message.
    MultipleTsig,
    /// TSIG is not the final additional record.
    TsigNotLast,
    /// TSIG request/response fields are inconsistent with the message.
    InvalidTsigMessage,
    /// A SIG(0) record appears outside the additional section.
    Sig0OutsideAdditional,
    /// More than one SIG(0) record appears in the message.
    MultipleSig0,
    /// SIG(0) is not the final additional record.
    Sig0NotLast,
    /// SIG(0) fixed fields are inconsistent with RFC 2931.
    InvalidSig0Message,
    /// A message contains both TSIG and SIG(0).
    MultipleAuthenticationSchemes,
    /// A request uses nonzero extended RCODE bits.
    ExtendedRcodeInRequest,
}

impl fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionTooLong(error) => error.fmt(f),
            Self::InvalidHeader(error) => write!(f, "invalid DNS header: {error}"),
            Self::InvalidQuestion {
                index,
                field,
                value,
            } => write!(f, "invalid question {index}: {field} value {value}"),
            Self::InvalidRecord {
                section,
                index,
                error,
            } => write!(f, "invalid {section} record {index}: {error}"),
            Self::ResponseOnlyQueryFields => {
                f.write_str("a query sets AA, TC, RA, or a nonzero response code")
            }
            Self::InvalidQueryRequestSections => f.write_str(concat!(
                "a standard QUERY request must have an empty answer section and no authority data ",
                "except the client SOA in an IXFR request",
            )),
            Self::InvalidIqueryRequestSections => f.write_str(concat!(
                "an IQUERY request must have no questions, exactly one answer, ",
                "and empty authority and additional sections",
            )),
            Self::InvalidUpdateMessage => {
                f.write_str("an UPDATE message violates RFC 2136 section or metavalue rules")
            }
            Self::InvalidNotifyMessage => {
                f.write_str("a NOTIFY message violates RFC 1996 section or flag rules")
            }
            Self::InvalidAxfrResponseFields => f.write_str(concat!(
                "a successful AXFR response must use QUERY, set AA, clear TC/AD/CD, and have an ",
                "empty authority section",
            )),
            Self::AuthoritativeAnyClass => {
                f.write_str("a QCLASS ANY response cannot be authoritative")
            }
            Self::InvalidAuthoritativeNegativeResponse => f.write_str(concat!(
                "an authoritative negative response has invalid answer data or lacks an authority ",
                "SOA whose TTL does not exceed SOA.MINIMUM",
            )),
            Self::OptOutsideAdditional => {
                f.write_str("an OPT record may appear only in the additional section")
            }
            Self::MultipleOpt => f.write_str("a message may contain only one OPT record"),
            Self::TsigOutsideAdditional => {
                f.write_str("a TSIG record may appear only in the additional section")
            }
            Self::MultipleTsig => f.write_str("a message may contain only one TSIG record"),
            Self::TsigNotLast => f.write_str("TSIG must be the final additional record"),
            Self::InvalidTsigMessage => {
                f.write_str("TSIG fields are inconsistent with the DNS message")
            }
            Self::Sig0OutsideAdditional => {
                f.write_str("SIG(0) may appear only in the additional section")
            }
            Self::MultipleSig0 => f.write_str("a message may contain only one SIG(0) record"),
            Self::Sig0NotLast => f.write_str("SIG(0) must be the final additional record"),
            Self::InvalidSig0Message => f.write_str("SIG(0) fields are inconsistent with RFC 2931"),
            Self::MultipleAuthenticationSchemes => {
                f.write_str("a message cannot contain both TSIG and SIG(0)")
            }
            Self::ExtendedRcodeInRequest => {
                f.write_str("an EDNS request must have a zero extended response code")
            }
        }
    }
}

impl std::error::Error for MessageValidationError {}
