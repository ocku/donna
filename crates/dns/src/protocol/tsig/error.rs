use std::fmt;

use crate::{TsigErrorCode, wire::WireError};

/// A TSIG construction or verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsigAuthenticationError {
    /// The configured shared secret is empty.
    EmptySecret,
    /// The message direction does not match the requested operation.
    WrongDirection,
    /// A TSIG record is missing.
    MissingTsig,
    /// TSIG placement or cardinality violates RFC 8945.
    InvalidPlacement,
    /// A message already has a TSIG and cannot be signed again.
    AlreadySigned,
    /// The key name is not the configured key.
    BadKey,
    /// The algorithm name is not the one associated with the key.
    BadAlgorithm,
    /// The keyed hash does not match.
    BadSignature,
    /// The signing time is outside the permitted interval.
    BadTime,
    /// The MAC violates the protocol length bounds.
    InvalidMacLength {
        /// Actual MAC length.
        length: usize,
        /// Smallest permitted length.
        minimum: usize,
        /// Full hash output length.
        maximum: usize,
    },
    /// The MAC is valid but shorter than local policy permits.
    BadTruncation {
        /// Actual MAC length.
        length: usize,
        /// Local policy minimum.
        minimum: usize,
    },
    /// Time Signed cannot fit its 48-bit field.
    TimeTooLarge {
        /// Rejected timestamp.
        value: u64,
    },
    /// Other Data does not match the TSIG error form.
    InvalidOtherData,
    /// BADSIG and BADKEY responses must carry an empty MAC.
    ErrorMustBeUnsigned {
        /// Error that requires the unsigned form.
        error: TsigErrorCode,
    },
    /// An unauthenticated TSIG error response was received.
    UnsignedError {
        /// Reported error value.
        error: TsigErrorCode,
    },
    /// More than 99 consecutive intermediary messages omitted TSIG.
    TooManyUnsignedMessages,
    /// A stream TSIG timestamp moved backwards.
    TimeRegression {
        /// Previously authenticated timestamp.
        previous: u64,
        /// Rejected timestamp.
        current: u64,
    },
    /// DNS wire encoding or decoding failed.
    Wire(WireError),
}

impl fmt::Display for TsigAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => formatter.write_str("TSIG shared secret must not be empty"),
            Self::WrongDirection => formatter.write_str("TSIG operation has the wrong direction"),
            Self::MissingTsig => formatter.write_str("expected a final TSIG record"),
            Self::InvalidPlacement => formatter.write_str("TSIG is duplicated or misplaced"),
            Self::AlreadySigned => formatter.write_str("message already contains TSIG"),
            Self::BadKey => formatter.write_str("TSIG key name is not recognized"),
            Self::BadAlgorithm => formatter.write_str("TSIG algorithm does not match the key"),
            Self::BadSignature => formatter.write_str("TSIG MAC verification failed"),
            Self::BadTime => formatter.write_str("TSIG signing time is outside its validity range"),
            Self::InvalidMacLength {
                length,
                minimum,
                maximum,
            } => write!(
                formatter,
                "TSIG MAC length {length} is outside {minimum}..={maximum}"
            ),
            Self::BadTruncation { length, minimum } => write!(
                formatter,
                "TSIG MAC length {length} is below local minimum {minimum}"
            ),
            Self::TimeTooLarge { value } => {
                write!(formatter, "TSIG signing time {value} exceeds 48 bits")
            }
            Self::InvalidOtherData => formatter.write_str("invalid TSIG Other Data"),
            Self::ErrorMustBeUnsigned { error } => {
                write!(formatter, "TSIG error {error:?} must be unsigned")
            }
            Self::UnsignedError { error } => {
                write!(formatter, "received unauthenticated TSIG error {error:?}")
            }
            Self::TooManyUnsignedMessages => {
                formatter.write_str("more than 99 stream messages omitted TSIG")
            }
            Self::TimeRegression { previous, current } => write!(
                formatter,
                "TSIG stream time moved backwards from {previous} to {current}"
            ),
            Self::Wire(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TsigAuthenticationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wire(error) => Some(error),
            _ => None,
        }
    }
}
