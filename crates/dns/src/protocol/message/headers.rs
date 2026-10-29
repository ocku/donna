use std::fmt;

/// An unassigned or out-of-range DNS header field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFieldValueError {
    /// The value does not fit in its wire field.
    TooWide {
        /// Identifies the invalid field.
        field: &'static str,
        /// Contains the rejected value.
        value: u8,
        /// Reports the field width.
        bits: u8,
        /// Reports the largest accepted value.
        maximum: u8,
    },
    /// The value fits in its field but is reserved.
    Reserved {
        /// Identifies the invalid field.
        field: &'static str,
        /// Contains the rejected value.
        value: u8,
    },
}

impl fmt::Display for HeaderFieldValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooWide {
                field,
                value,
                bits,
                maximum,
            } => write!(
                f,
                "{field} value {value} exceeds its {bits}-bit maximum of {maximum}"
            ),
            Self::Reserved { field, value } => {
                write!(f, "{field} value {value} is unassigned")
            }
        }
    }
}

impl std::error::Error for HeaderFieldValueError {}

/// Assigned four-bit DNS OPCODE values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// Requests a standard query (OPCODE 0).
    Query,
    /// Requests an inverse query (OPCODE 1, obsolete).
    IQuery,
    /// Requests server status (OPCODE 2).
    Status,
    /// Notifies a secondary server of a zone change (OPCODE 4).
    Notify,
    /// Requests a dynamic update (OPCODE 5).
    Update,
    /// An unassigned opcode retained from the wire.
    Unknown(u8),
}

impl OpCode {
    /// Returns the four-bit DNS OPCODE value.
    pub(crate) const fn value(self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Unknown(value) => value,
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = HeaderFieldValueError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 0x0f {
            return Err(HeaderFieldValueError::TooWide {
                field: "OPCODE",
                value,
                bits: 4,
                maximum: 0x0f,
            });
        }
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::IQuery),
            2 => Ok(Self::Status),
            4 => Ok(Self::Notify),
            5 => Ok(Self::Update),
            value => Ok(Self::Unknown(value)),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(value: OpCode) -> Self {
        value.value()
    }
}

/// Assigned four-bit DNS header RCODE values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    /// Indicates that no error occurred (RCODE 0).
    Ok,
    /// Indicates a malformed request (RCODE 1).
    FormatError,
    /// Indicates an internal server failure (RCODE 2).
    ServerFailure,
    /// Indicates that the queried domain does not exist (RCODE 3).
    NameError,
    /// Indicates that the requested operation is unsupported (RCODE 4).
    NotImplemented,
    /// Indicates that policy refused the request (RCODE 5).
    Refused,
    /// Indicates that a prerequisite name already exists (RCODE 6).
    YXDomain,
    /// Indicates that a prerequisite RRSet already exists (RCODE 7).
    YXRRSet,
    /// Indicates that a prerequisite RRSet does not exist (RCODE 8).
    NXRRSet,
    /// The server is not authoritative for the requested zone.
    ///
    /// Assigned as RCODE 9 after RFC 1035; RFC 5936 §2.2.1 recommends it
    /// for AXFR requests for a zone the server does not serve.
    NotAuthoritative,
    /// Indicates that a name is outside the update zone (RCODE 10).
    NotZone,
    /// An unassigned response code retained from the wire.
    Unknown(u8),
}

impl RCode {
    /// Returns the four-bit DNS RCODE value.
    pub(crate) const fn value(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::YXDomain => 6,
            Self::YXRRSet => 7,
            Self::NXRRSet => 8,
            Self::NotAuthoritative => 9,
            Self::NotZone => 10,
            Self::Unknown(value) => value,
        }
    }
}

impl TryFrom<u8> for RCode {
    type Error = HeaderFieldValueError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 0x0f {
            return Err(HeaderFieldValueError::TooWide {
                field: "RCODE",
                value,
                bits: 4,
                maximum: 0x0f,
            });
        }
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::FormatError),
            2 => Ok(Self::ServerFailure),
            3 => Ok(Self::NameError),
            4 => Ok(Self::NotImplemented),
            5 => Ok(Self::Refused),
            6 => Ok(Self::YXDomain),
            7 => Ok(Self::YXRRSet),
            8 => Ok(Self::NXRRSet),
            9 => Ok(Self::NotAuthoritative),
            10 => Ok(Self::NotZone),
            value => Ok(Self::Unknown(value)),
        }
    }
}

impl From<RCode> for u8 {
    fn from(value: RCode) -> Self {
        value.value()
    }
}

/// Semantic DNS message header fields.
///
/// Section counts are derived from the message sections when a wire header is
/// encoded. The one bit that remains reserved from RFC 1035's original
/// three-bit `Z` field is absent and therefore always encoded as zero.
///
/// RFC 1035 §4.1.1; RFC 4035 §2.
#[derive(Debug, Clone)]
pub struct Headers {
    /// Identifier chosen by the query originator and copied into a response.
    pub id: u16,
    /// `false` for a query and `true` for a response.
    pub qr: bool,
    /// The kind of query.
    pub opcode: OpCode,
    /// Authoritative Answer. Meaningful only in responses.
    pub aa: bool,
    /// Whether the message was truncated for its transport.
    pub tc: bool,
    /// Whether recursion was requested.
    pub rd: bool,
    /// Whether the server offers recursion. Meaningful only in responses.
    pub ra: bool,
    /// Whether the response data is authenticated, or a query requests this
    /// signal. RFC 4035 and RFC 6840 §5.7.
    pub ad: bool,
    /// Whether DNSSEC validation is disabled. RFC 4035 §3.2.2.
    pub cd: bool,
    /// Response code. Meaningful only in responses.
    pub rcode: RCode,
}

impl Headers {
    /// Validates values permitted in an outbound DNS header.
    ///
    /// The decoder preserves unassigned values so it can report what it
    /// received. A response may echo an unassigned OPCODE so the client can
    /// match it to its query and receive a NOTIMP response.
    ///
    /// # Errors
    ///
    /// Returns an error if a field is too wide or uses a reserved outbound
    /// representation.
    pub(crate) fn validate_wire(&self) -> Result<(), HeaderFieldValueError> {
        let opcode = self.opcode.value();
        OpCode::try_from(opcode)?;
        if matches!(self.opcode, OpCode::Unknown(_)) && !self.qr {
            return Err(HeaderFieldValueError::Reserved {
                field: "OPCODE",
                value: opcode,
            });
        }

        let rcode = self.rcode.value();
        RCode::try_from(rcode)?;
        if matches!(self.rcode, RCode::Unknown(_)) {
            return Err(HeaderFieldValueError::Reserved {
                field: "RCODE",
                value: rcode,
            });
        }
        Ok(())
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self {
            id: 0,
            qr: false,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            ad: false,
            cd: false,
            rcode: RCode::Ok,
        }
    }
}
