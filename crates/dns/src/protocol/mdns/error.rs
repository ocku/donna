use super::*;

/// An invalid mDNS packet or receive context.
#[derive(Debug)]
pub enum MdnsError {
    /// Ordinary DNS wire-format failure.
    Wire(WireError),
    /// Header fields violate mDNS message rules.
    InvalidHeaders,
    /// QU/cache-flush encoding was applied to an invalid class value.
    InvalidClass(u16),
    /// A record failed ordinary DNS semantic validation.
    InvalidRecord(crate::RecordValidationError),
    /// Cache-flush appeared in a query or Authority section.
    InvalidCacheFlush,
    /// Received IP TTL or IPv6 hop limit was not 255.
    InvalidHopLimit(u8),
    /// Datagram source is not valid for mDNS.
    InvalidSource(SocketAddr),
    /// Multicast datagram used the wrong destination port.
    InvalidDestination(SocketAddr),
}

impl fmt::Display for MdnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::InvalidHeaders => formatter.write_str("invalid mDNS header fields"),
            Self::InvalidClass(value) => write!(formatter, "invalid mDNS class {value}"),
            Self::InvalidRecord(error) => write!(formatter, "invalid mDNS record: {error}"),
            Self::InvalidCacheFlush => formatter.write_str("invalid mDNS cache-flush placement"),
            Self::InvalidHopLimit(value) => write!(formatter, "mDNS hop limit is {value}, not 255"),
            Self::InvalidSource(source) => write!(formatter, "invalid mDNS source {source}"),
            Self::InvalidDestination(destination) => {
                write!(formatter, "invalid mDNS destination {destination}")
            }
        }
    }
}

impl std::error::Error for MdnsError {}

impl From<WireError> for MdnsError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
