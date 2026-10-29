//! RFC 1035 DNS message wire codec.
//!
//! The decoder retains the complete packet so compressed domain names can
//! safely refer to any earlier location in that packet.

mod compression;
mod decoder;
mod encoder;
mod header;
mod message;
mod name;
mod prepared;
mod question;

pub use prepared::{
    EncodedReply, PreparedAuthoritativeNodataReply, PreparedNegativeReply, PreparedPositiveReply,
};
mod rdata;
mod record;

use std::fmt;

// Codec building blocks stay internal. Public entry points are checked wire
// traits, errors, and immutable prepared replies with bounded mutations.
pub(crate) use decoder::Decoder;
pub(crate) use encoder::Encoder;
pub(crate) use header::{decode_header, decode_mdns_header, encode_header};
pub(crate) use name::{decode_name, decode_uncompressed_name};
pub(crate) use question::{
    class, decode_question, encode_question, qclass, query_type, record_type,
};
pub(crate) use rdata::{decode_rdata, encode_rdata};
pub(crate) use record::{
    decode_record, decode_update_record, encode_record, encode_update_record,
    encode_validated_record,
};

/// Encodes a self-contained DNS protocol value into RFC 1035 wire format.
// This trait borrows the value; `to_wire` would be less consistent with
// `FromWire`.
#[allow(clippy::wrong_self_convention)]
pub trait IntoWire {
    /// Encodes this value as a complete DNS wire-format byte sequence.
    ///
    /// # Errors
    ///
    /// Returns an error if the value violates wire-format or semantic limits.
    fn into_wire(&self) -> Result<Vec<u8>>;
}

/// Decodes a self-contained DNS protocol value from RFC 1035 wire format.
pub trait FromWire: Sized {
    /// Decodes one complete DNS wire-format value.
    ///
    /// # Errors
    ///
    /// Returns an error if input is truncated, malformed, unsupported, or has
    /// trailing octets.
    fn from_wire(bytes: &[u8]) -> Result<Self>;
}

pub(crate) fn decode_complete<T>(
    bytes: &[u8],
    decode: impl FnOnce(&mut Decoder<'_>) -> Result<T>,
) -> Result<T> {
    let mut decoder = Decoder::new(bytes);
    let value = decode(&mut decoder)?;
    if decoder.remaining() != 0 {
        return Err(WireError::InvalidValue {
            field: "trailing octets",
            value: decoder.remaining() as u64,
        });
    }
    Ok(value)
}

/// An invalid or unsupported DNS wire-format value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The input ends before the requested value is complete.
    Truncated {
        /// Identifies the byte offset at which decoding stopped.
        position: usize,
        /// Reports the number of required octets.
        needed: usize,
        /// Reports the number of available octets.
        remaining: usize,
    },
    /// A label length octet uses a reserved label type.
    InvalidLabelType {
        /// Identifies the label's byte offset.
        position: usize,
        /// Contains the invalid label length octet.
        value: u8,
    },
    /// A compression pointer refers beyond the message.
    CompressionPointerOutOfBounds {
        /// Identifies the pointer's byte offset.
        position: usize,
        /// Contains the referenced byte offset.
        offset: usize,
    },
    /// A compression pointer does not point backward.
    CompressionPointerForward {
        /// Identifies the pointer's byte offset.
        position: usize,
        /// Contains the referenced byte offset.
        offset: usize,
    },
    /// A compression pointer creates a reference cycle.
    CompressionPointerCycle {
        /// Identifies the pointer's byte offset.
        position: usize,
        /// Contains the referenced byte offset.
        offset: usize,
    },
    /// A compression pointer does not target a known name label.
    CompressionPointerInvalidTarget {
        /// Identifies the pointer's byte offset.
        position: usize,
        /// Contains the referenced byte offset.
        offset: usize,
    },
    /// A field contains an invalid numeric value.
    InvalidValue {
        /// Identifies the invalid field.
        field: &'static str,
        /// Contains the rejected value.
        value: u64,
    },
    /// Structured RDATA violates its record-type format.
    InvalidRData {
        /// Identifies the resource-record type.
        record_type: &'static str,
        /// Describes the format violation.
        detail: &'static str,
    },
    /// A value exceeds the width of its wire length field.
    LengthOverflow {
        /// Identifies the oversized field.
        field: &'static str,
        /// Reports the actual length in octets.
        length: usize,
        /// Reports the maximum length in octets.
        maximum: usize,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                position,
                needed,
                remaining,
            } => write!(
                f,
                "truncated DNS message at byte {position}: need {needed} bytes, have {remaining}"
            ),
            Self::InvalidLabelType { position, value } => {
                write!(f, "invalid DNS label type {value:#04x} at byte {position}")
            }
            Self::CompressionPointerOutOfBounds { position, offset } => write!(
                f,
                "compression pointer at byte {position} refers outside the message to byte {offset}"
            ),

            Self::CompressionPointerForward { position, offset } => write!(
                f,
                "compression pointer at byte {position} refers forward to byte {offset}"
            ),
            Self::CompressionPointerCycle { position, offset } => write!(
                f,
                "compression pointer at byte {position} creates a cycle through byte {offset}"
            ),
            Self::CompressionPointerInvalidTarget { position, offset } => write!(
                f,
                concat!(
                    "compression pointer at byte {} does not refer to a prior domain-name ",
                    "label at byte {}",
                ),
                position, offset,
            ),
            Self::InvalidValue { field, value } => write!(f, "invalid {field} value {value}"),
            Self::InvalidRData {
                record_type,
                detail,
            } => write!(f, "invalid {record_type} RDATA: {detail}"),
            Self::LengthOverflow {
                field,
                length,
                maximum,
            } => write!(f, "{field} length {length} exceeds {maximum}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Result returned by DNS wire encoding and decoding operations.
pub type Result<T> = std::result::Result<T, WireError>;
