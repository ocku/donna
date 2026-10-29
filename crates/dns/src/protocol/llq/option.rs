use super::*;

/// Operation carried by an LLQ EDNS option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LlqOpcode {
    /// Four-message setup handshake.
    Setup = 1,
    /// Lease refresh or termination.
    Refresh = 2,
    /// Gratuitous add/remove notification.
    Event = 3,
}

impl TryFrom<u16> for LlqOpcode {
    type Error = LlqError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Setup),
            2 => Ok(Self::Refresh),
            3 => Ok(Self::Event),
            value => Err(LlqError::UnknownOpcode(value)),
        }
    }
}

/// Error value carried inside an LLQ option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LlqResponseCode {
    /// Operation succeeded.
    NoError = 0,
    /// Server resource or rate limit was reached.
    ServerFull = 1,
    /// Data is considered static and must not be polled.
    Static = 2,
    /// LLQ option was malformed.
    FormatError = 3,
    /// Refresh named an expired or unknown LLQ.
    NoSuchLlq = 4,
    /// Requested LLQ version is unsupported.
    BadVersion = 5,
    /// Unclassified server error.
    UnknownError = 6,
}

impl TryFrom<u16> for LlqResponseCode {
    type Error = LlqError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoError),
            1 => Ok(Self::ServerFull),
            2 => Ok(Self::Static),
            3 => Ok(Self::FormatError),
            4 => Ok(Self::NoSuchLlq),
            5 => Ok(Self::BadVersion),
            6 => Ok(Self::UnknownError),
            value => Err(LlqError::UnknownResponseCode(value)),
        }
    }
}

/// The fixed 18-octet payload of an LLQ EDNS option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LlqOption {
    /// Protocol version; RFC 8764 documents version 1.
    pub version: u16,
    /// LLQ operation.
    pub opcode: LlqOpcode,
    /// Operation-specific result.
    pub response_code: LlqResponseCode,
    /// Server-generated subscription identifier.
    pub id: u64,
    /// Requested, granted, remaining, or retry lifetime in seconds.
    pub lease: u32,
}

impl LlqOption {
    /// Encodes this value as EDNS option code 1.
    #[must_use]
    pub fn into_edns_option(self) -> EdnsOption {
        let mut data = Vec::with_capacity(18);
        data.extend_from_slice(&self.version.to_be_bytes());
        data.extend_from_slice(&(self.opcode as u16).to_be_bytes());
        data.extend_from_slice(&(self.response_code as u16).to_be_bytes());
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.lease.to_be_bytes());
        EdnsOption {
            code: LLQ_OPTION_CODE,
            data,
        }
    }

    /// Decodes an LLQ EDNS option.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong option code, a non-18-byte payload, or
    /// unknown opcode/error values.
    pub fn from_edns_option(option: &EdnsOption) -> Result<Self, LlqError> {
        if option.code != LLQ_OPTION_CODE || option.data.len() != 18 {
            return Err(LlqError::MalformedOption);
        }
        Ok(Self {
            version: u16::from_be_bytes(option.data[0..2].try_into().expect("checked length")),
            opcode: LlqOpcode::try_from(u16::from_be_bytes(
                option.data[2..4].try_into().expect("checked length"),
            ))?,
            response_code: LlqResponseCode::try_from(u16::from_be_bytes(
                option.data[4..6].try_into().expect("checked length"),
            ))?,
            id: u64::from_be_bytes(option.data[6..14].try_into().expect("checked length")),
            lease: u32::from_be_bytes(option.data[14..18].try_into().expect("checked length")),
        })
    }
}

/// Constructs `_dns-llq._udp.<zone>` for LLQ server discovery.
///
/// # Errors
///
/// Returns an error if the resulting name exceeds DNS limits.
pub fn llq_service_name(zone: &DomainName) -> Result<DomainName, DomainNameError> {
    let mut labels = vec![b"_dns-llq".to_vec(), b"_udp".to_vec()];
    labels.extend(zone.as_ref().iter().cloned());
    DomainName::from_labels(labels)
}
