use super::*;

/// Fields echoed in an acknowledgment to a gratuitous LLQ event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlqEventAck {
    /// DNS message ID copied from the event response.
    pub message_id: u16,
    /// EVENT option copied from the event response.
    pub option: LlqOption,
}

/// Invalid LLQ option or client-state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlqError {
    /// Ordinary DNS wire-format failure.
    Wire(WireError),
    /// EDNS option code or fixed payload size is invalid.
    MalformedOption,
    /// LLQ opcode is not assigned.
    UnknownOpcode(u16),
    /// LLQ response code is not assigned.
    UnknownResponseCode(u16),
    /// LLQ question is noncanonical or uses ANY, NONE, or reserved class zero.
    InvalidQuestion,
    /// Initial or granted lease is zero where a live lease is required.
    InvalidLease,
    /// Operation is invalid in the current handshake phase.
    InvalidState,
    /// Refresh or event arrived after lease expiration.
    LeaseExpired,
    /// SERV-FULL retry delay has not elapsed.
    RetryTooEarly,
    /// LLQ EVENT message structure is inconsistent.
    MalformedEvent,
    /// LLQ EVENT contains an invalid resource record.
    InvalidEventRecord,
    /// A DNS section has more than 65535 entries.
    SectionTooLong,
}

impl fmt::Display for LlqError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::MalformedOption => formatter.write_str("malformed LLQ option"),
            Self::UnknownOpcode(value) => write!(formatter, "unknown LLQ opcode {value}"),
            Self::UnknownResponseCode(value) => {
                write!(formatter, "unknown LLQ response code {value}")
            }
            Self::InvalidQuestion => formatter.write_str("invalid LLQ question"),
            Self::InvalidLease => formatter.write_str("invalid LLQ lease"),
            Self::InvalidState => formatter.write_str("invalid LLQ client state transition"),
            Self::LeaseExpired => formatter.write_str("LLQ lease has expired"),
            Self::RetryTooEarly => formatter.write_str("LLQ retry delay has not elapsed"),
            Self::MalformedEvent => formatter.write_str("malformed LLQ event message"),
            Self::InvalidEventRecord => formatter.write_str("invalid LLQ event record"),
            Self::SectionTooLong => formatter.write_str("LLQ event section is too long"),
        }
    }
}

impl std::error::Error for LlqError {}

impl From<WireError> for LlqError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
