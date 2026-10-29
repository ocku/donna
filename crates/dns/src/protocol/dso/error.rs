use super::*;

/// Invalid DSO or DNS Push state/wire data.
#[derive(Debug)]
pub enum DsoError {
    /// Ordinary DNS wire error.
    Wire(WireError),
    /// DSO header is invalid.
    InvalidHeader,
    /// Message ID violates request/unidirectional rules.
    InvalidMessageId,
    /// TLV exceeds its 16-bit length.
    TlvTooLong {
        /// DSO-TYPE whose payload was oversized.
        code: u16,
        /// Actual payload length in octets.
        length: usize,
    },
    /// TLV payload does not match its type.
    MalformedTlv(u16),
    /// PUSH contains no changes.
    EmptyPushUpdate,
    /// PUSH exceeds RFC 8765's 16,382-byte limit.
    PushMessageTooLong(usize),
    /// PUSH change encoding is invalid.
    MalformedPushChange,
    /// Record selected for PUSH is invalid.
    InvalidRecord(crate::RecordValidationError),
    /// Client/server message direction is invalid.
    WrongDirection,
    /// Subscription duplicates an active ID or question.
    DuplicateSubscription,
    /// Subscription capacity was exhausted.
    SubscriptionLimit,
    /// Caller authorization refused the subscription.
    NotAuthorized,
    /// Server advertised a keepalive interval below ten seconds.
    InvalidKeepaliveInterval(u32),
}

impl fmt::Display for DsoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::InvalidHeader => formatter.write_str("invalid DSO header"),
            Self::InvalidMessageId => formatter.write_str("invalid DSO message ID"),
            Self::TlvTooLong { code, length } => {
                write!(formatter, "DSO TLV {code} length {length} exceeds 65535")
            }
            Self::MalformedTlv(code) => write!(formatter, "malformed DSO TLV {code}"),
            Self::EmptyPushUpdate => formatter.write_str("DNS Push update contains no changes"),
            Self::PushMessageTooLong(length) => {
                write!(formatter, "DNS Push message length {length} exceeds 16382")
            }
            Self::MalformedPushChange => formatter.write_str("malformed DNS Push change"),
            Self::InvalidRecord(error) => write!(formatter, "invalid DNS Push record: {error}"),
            Self::WrongDirection => formatter.write_str("invalid DNS Push message direction"),
            Self::DuplicateSubscription => formatter.write_str("duplicate DNS Push subscription"),
            Self::SubscriptionLimit => formatter.write_str("DNS Push subscription limit reached"),
            Self::NotAuthorized => formatter.write_str("DNS Push subscription is not authorized"),
            Self::InvalidKeepaliveInterval(value) => {
                write!(
                    formatter,
                    "DSO keepalive interval {value} ms is below 10000 ms"
                )
            }
        }
    }
}

impl std::error::Error for DsoError {}

impl From<WireError> for DsoError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
