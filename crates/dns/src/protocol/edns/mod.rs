/// Extended DNS Error option construction and inspection (RFC 8914).
pub(crate) mod extended_error;
/// EDNS Padding option construction and block-length policies (RFC 7830/8467).
mod padding;

pub use extended_error::{
    EDNS_EXTENDED_DNS_ERROR_OPTION_CODE, ExtendedDnsError, ExtendedDnsErrorCode,
    ExtendedDnsErrorError,
};
pub use padding::{
    EDNS_PADDING_OPTION_CODE, PaddingOutcome, PaddingPolicyError,
    RECOMMENDED_QUERY_PADDING_BLOCK_SIZE, RECOMMENDED_RESPONSE_PADDING_BLOCK_SIZE,
};

use std::fmt;

use crate::protocol::resource_record::validate_received_edns_options;
use crate::{
    ClassType, DomainName, Message, RData, RecordType, RecordValidationError, ResourceRecord,
};

/// An opaque EDNS option tuple.
///
/// Unknown option codes are deliberately preserved and ignored by generic
/// EDNS processing, as required by RFC 6891 section 6.1.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdnsOption {
    /// Identifies the option's registered meaning.
    pub code: u16,
    /// Contains the option data exactly as it appears after OPTION-LENGTH.
    pub data: Vec<u8>,
}

/// DNSSEC algorithm-understanding signal defined by RFC 6975.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithmSignal {
    /// DNSSEC Algorithm Understood (DAU), option code 5.
    Dau,
    /// DS Hash Understood (DHU), option code 6.
    Dhu,
    /// NSEC3 Hash Understood (N3U), option code 7.
    N3u,
}

impl DnssecAlgorithmSignal {
    /// Returns the assigned EDNS option code.
    pub const fn option_code(self) -> u16 {
        match self {
            Self::Dau => 5,
            Self::Dhu => 6,
            Self::N3u => 7,
        }
    }
}

/// The control information carried by an RFC 6891 OPT pseudo-record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    /// Largest UDP payload the sender can receive.
    pub udp_payload_size: u16,
    /// Upper eight bits of the twelve-bit extended response code.
    pub extended_rcode: u8,
    /// EDNS protocol version advertised by the sender.
    pub version: u8,
    /// DNSSEC OK (DO) flag.
    pub dnssec_ok: bool,
    /// Remaining fifteen EDNS flag bits.
    ///
    /// Senders using only RFC 6891 must leave these bits zero. Receivers retain
    /// them so future assigned flags can be ignored without losing wire data.
    pub z: u16,
    /// Ordered EDNS option tuples.
    pub options: Vec<EdnsOption>,
}

impl Edns {
    /// EDNS version implemented by this crate.
    pub const VERSION: u8 = 0;
    /// RFC 6891's suggested initial UDP payload size.
    pub const RECOMMENDED_UDP_PAYLOAD_SIZE: u16 = 4096;
    /// The minimum effective DNS UDP payload size.
    pub const MIN_UDP_PAYLOAD_SIZE: u16 = 512;

    /// Returns a DNSSEC algorithm signal, preserving its advertised order.
    ///
    /// # Errors
    ///
    /// Returns an error when the option occurs more than once.
    pub fn algorithm_signal(
        &self,
        signal: DnssecAlgorithmSignal,
    ) -> Result<Option<&[u8]>, DnssecAlgorithmSignalError> {
        let code = signal.option_code();
        let mut matching = self.options.iter().filter(|option| option.code == code);
        let value = matching.next().map(|option| option.data.as_slice());
        if matching.next().is_some() {
            return Err(DnssecAlgorithmSignalError::DuplicateOption { code });
        }
        Ok(value)
    }

    /// Replaces one DNSSEC algorithm signal and enables the DO bit.
    ///
    /// Duplicate algorithm values are collapsed in first-seen order. Reserved
    /// code 0 and code 255 are rejected for all three registries.
    ///
    /// # Errors
    ///
    /// Returns an error if a reserved algorithm code is supplied.
    pub fn set_algorithm_signal(
        &mut self,
        signal: DnssecAlgorithmSignal,
        algorithms: impl IntoIterator<Item = u8>,
    ) -> Result<(), DnssecAlgorithmSignalError> {
        let code = signal.option_code();
        let mut data = Vec::new();
        for algorithm in algorithms {
            if matches!(algorithm, 0 | u8::MAX) {
                return Err(DnssecAlgorithmSignalError::ReservedAlgorithm {
                    option_code: code,
                    algorithm,
                });
            }
            if !data.contains(&algorithm) {
                data.push(algorithm);
            }
        }
        self.options.retain(|option| option.code != code);
        self.options.push(EdnsOption { code, data });
        self.dnssec_ok = true;
        Ok(())
    }

    /// Unions advertised algorithms into an existing signal.
    ///
    /// Existing order is preserved and newly seen values are appended.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate existing option or a reserved code.
    pub fn union_algorithm_signal(
        &mut self,
        signal: DnssecAlgorithmSignal,
        algorithms: impl IntoIterator<Item = u8>,
    ) -> Result<(), DnssecAlgorithmSignalError> {
        let mut union = self.algorithm_signal(signal)?.unwrap_or_default().to_vec();
        union.extend(algorithms);
        self.set_algorithm_signal(signal, union)
    }

    /// Removes all DAU, DHU, and N3U options before producing a response.
    pub fn remove_algorithm_signals(&mut self) {
        self.options.retain(|option| !matches!(option.code, 5..=7));
    }

    /// Creates an EDNS(0) value without flags or options.
    #[must_use]
    pub const fn new(udp_payload_size: u16) -> Self {
        Self {
            udp_payload_size,
            extended_rcode: 0,
            version: Self::VERSION,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        }
    }

    /// Returns the advertised payload size after applying RFC 6891's 512-byte
    /// lower bound.
    #[must_use]
    pub const fn effective_udp_payload_size(&self) -> u16 {
        if self.udp_payload_size < Self::MIN_UDP_PAYLOAD_SIZE {
            Self::MIN_UDP_PAYLOAD_SIZE
        } else {
            self.udp_payload_size
        }
    }

    /// Validates the option tuples whose formats this crate implements.
    ///
    /// Unknown options remain opaque. Known options must satisfy their own
    /// wire-format rules. Padding must be unique, but receivers accept it in
    /// any option position because RFC 6891 assigns no meaning to option order.
    ///
    /// # Errors
    ///
    /// Returns the first malformed known option or option-order violation.
    pub fn validate_options(&self) -> Result<(), RecordValidationError> {
        validate_received_edns_options(&self.options)
    }

    /// Builds the OPT pseudo-record used in a message's additional section.
    #[must_use]
    pub fn into_record(self) -> ResourceRecord {
        let ttl = (u32::from(self.extended_rcode) << 24)
            | (u32::from(self.version) << 16)
            | (u32::from(self.dnssec_ok) << 15)
            | u32::from(self.z & 0x7fff);
        ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::OPT,
            class: ClassType::Unknown(self.udp_payload_size),
            ttl,
            rdata: RData::OPT(self.options),
        }
    }

    /// Reads the control fields from a valid OPT pseudo-record.
    ///
    /// # Errors
    ///
    /// Returns an error if the record is not an OPT record or violates the
    /// fixed-format requirements in RFC 6891 section 6.1.2.
    pub fn try_from_record(record: &ResourceRecord) -> Result<Self, EdnsRecordError> {
        if record.rtype != RecordType::OPT {
            return Err(EdnsRecordError::NotOpt);
        }
        if record.name != DomainName::root() {
            return Err(EdnsRecordError::NonRootName);
        }
        let RData::OPT(options) = &record.rdata else {
            return Err(EdnsRecordError::InvalidRData);
        };
        let ClassType::Unknown(udp_payload_size) = record.class else {
            return Err(EdnsRecordError::InvalidPayloadClass);
        };
        Ok(Self {
            udp_payload_size,
            extended_rcode: (record.ttl >> 24) as u8,
            version: (record.ttl >> 16) as u8,
            dnssec_ok: record.ttl & 0x8000 != 0,
            z: (record.ttl & 0x7fff) as u16,
            options: options.clone(),
        })
    }
}

/// A malformed or unrepresentable RFC 6975 algorithm signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithmSignalError {
    /// One signal option occurs more than once.
    DuplicateOption {
        /// Duplicated EDNS option code.
        code: u16,
    },
    /// A sender attempted to advertise a reserved algorithm code.
    ReservedAlgorithm {
        /// DAU, DHU, or N3U option code.
        option_code: u16,
        /// Rejected registry value.
        algorithm: u8,
    },
}

impl fmt::Display for DnssecAlgorithmSignalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateOption { code } => {
                write!(
                    formatter,
                    "EDNS algorithm signal option {code} is duplicated"
                )
            }
            Self::ReservedAlgorithm {
                option_code,
                algorithm,
            } => write!(
                formatter,
                "EDNS option {option_code} contains reserved algorithm code {algorithm}"
            ),
        }
    }
}

impl std::error::Error for DnssecAlgorithmSignalError {}

impl Default for Edns {
    fn default() -> Self {
        Self::new(Self::RECOMMENDED_UDP_PAYLOAD_SIZE)
    }
}

/// A resource record cannot be interpreted as an RFC 6891 OPT pseudo-record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsRecordError {
    /// The record TYPE is not OPT (41).
    NotOpt,
    /// The OPT owner NAME is not the root domain.
    NonRootName,
    /// The OPT CLASS is not represented as its unsigned payload-size value.
    InvalidPayloadClass,
    /// The OPT RDATA does not contain EDNS option tuples.
    InvalidRData,
}

impl fmt::Display for EdnsRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotOpt => "record TYPE is not OPT",
            Self::NonRootName => "OPT NAME is not the root domain",
            Self::InvalidPayloadClass => "OPT CLASS is not a UDP payload size",
            Self::InvalidRData => "OPT RDATA does not contain EDNS options",
        })
    }
}

impl std::error::Error for EdnsRecordError {}

/// An RFC 6891 placement or cardinality error in a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsMessageError {
    /// An OPT pseudo-record appears outside the additional section.
    OutsideAdditional,
    /// A message contains more than one OPT pseudo-record.
    MultipleOpt,
    /// The sole additional OPT record has an invalid fixed format.
    InvalidRecord(EdnsRecordError),
}

impl fmt::Display for EdnsMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideAdditional => f.write_str("OPT record is outside the additional section"),
            Self::MultipleOpt => f.write_str("message contains more than one OPT record"),
            Self::InvalidRecord(error) => write!(f, "invalid OPT record: {error}"),
        }
    }
}

impl std::error::Error for EdnsMessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRecord(error) => Some(error),
            Self::OutsideAdditional | Self::MultipleOpt => None,
        }
    }
}

impl Message {
    /// Returns this message's EDNS control information, if present.
    ///
    /// # Errors
    ///
    /// Returns an error for an OPT record outside the additional section, for
    /// multiple OPT records, or for an invalid OPT fixed part.
    pub fn edns(&self) -> Result<Option<Edns>, EdnsMessageError> {
        if self
            .answers
            .iter()
            .chain(&self.authorities)
            .any(|record| record.rtype == RecordType::OPT)
        {
            return Err(EdnsMessageError::OutsideAdditional);
        }
        let mut records = self
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT);
        let Some(record) = records.next() else {
            return Ok(None);
        };
        if records.next().is_some() {
            return Err(EdnsMessageError::MultipleOpt);
        }
        Edns::try_from_record(record)
            .map(Some)
            .map_err(EdnsMessageError::InvalidRecord)
    }

    /// Returns the complete twelve-bit response code formed from the DNS
    /// header and this message's valid OPT record.
    ///
    /// For malformed messages, or messages without EDNS, only the four header
    /// bits are returned.
    #[must_use]
    pub fn extended_rcode(&self) -> u16 {
        let upper = self
            .edns()
            .ok()
            .flatten()
            .map_or(0, |edns| u16::from(edns.extended_rcode));
        (upper << 4) | u16::from(self.headers.rcode.value())
    }
}

#[cfg(test)]
mod tests;
