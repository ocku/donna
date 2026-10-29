use crate::DomainName;

/// A TSIG extended error value carried in TSIG RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsigErrorCode {
    /// No TSIG processing error.
    NoError,
    /// The message authentication code did not verify (16).
    BadSignature,
    /// The key name or algorithm is unknown (17).
    BadKey,
    /// The signing time is outside the permitted interval (18).
    BadTime,
    /// The MAC is shorter than local policy permits (22).
    BadTruncation,
    /// A future or private TSIG error value.
    Unknown(u16),
}

impl TsigErrorCode {
    /// Returns the numeric TSIG error value.
    pub const fn value(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::BadSignature => 16,
            Self::BadKey => 17,
            Self::BadTime => 18,
            Self::BadTruncation => 22,
            Self::Unknown(value) => value,
        }
    }
}

impl From<u16> for TsigErrorCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NoError,
            16 => Self::BadSignature,
            17 => Self::BadKey,
            18 => Self::BadTime,
            22 => Self::BadTruncation,
            value => Self::Unknown(value),
        }
    }
}

impl From<TsigErrorCode> for u16 {
    fn from(value: TsigErrorCode) -> Self {
        value.value()
    }
}

/// Transaction Signature RDATA.
///
/// TSIG is transaction metadata rather than ordinary zone data. The owner of
/// its [`crate::ResourceRecord`] is the shared key name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tsig {
    /// Identifies the keyed hash algorithm as a DNS name.
    pub algorithm: DomainName,
    /// Seconds since the Unix epoch, limited to the TSIG 48-bit field.
    pub time_signed: u64,
    /// Permitted clock skew in seconds.
    pub fudge: u16,
    /// Full or permitted leading truncation of the keyed hash output.
    pub mac: Vec<u8>,
    /// Message ID of the original request.
    pub original_id: u16,
    /// Extended TSIG processing status.
    pub error: TsigErrorCode,
    /// Error-specific data; BADTIME carries the server time as six octets.
    pub other_data: Vec<u8>,
}

impl Tsig {
    /// Largest value representable by the 48-bit Time Signed field.
    pub const MAX_TIME_SIGNED: u64 = (1_u64 << 48) - 1;

    /// Returns the BADTIME server clock when Other Data has its required form.
    pub fn bad_time_server_time(&self) -> Option<u64> {
        if self.error != TsigErrorCode::BadTime || self.other_data.len() != 6 {
            return None;
        }
        Some(
            self.other_data
                .iter()
                .fold(0_u64, |value, octet| (value << 8) | u64::from(*octet)),
        )
    }
}

/// Keyed hash algorithms required by RFC 8945.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    /// HMAC-SHA-1; retained for protocol compatibility.
    HmacSha1,
    /// HMAC-SHA-256; the recommended mandatory algorithm.
    HmacSha256,
}

impl TsigAlgorithm {
    /// Returns the registered case-insensitive TSIG algorithm name.
    pub fn name(self) -> DomainName {
        let label = match self {
            Self::HmacSha1 => b"hmac-sha1".as_slice(),
            Self::HmacSha256 => b"hmac-sha256".as_slice(),
        };
        DomainName::from_labels(vec![label.to_vec()]).expect("registered TSIG name is valid")
    }

    /// Resolves a registered mandatory algorithm name case-insensitively.
    pub fn from_name(name: &DomainName) -> Option<Self> {
        [Self::HmacSha1, Self::HmacSha256]
            .into_iter()
            .find(|algorithm| name.eq_dns(&algorithm.name()))
    }

    /// Returns the full keyed hash output length in octets.
    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
        }
    }

    /// Returns the protocol minimum permitted MAC length.
    pub const fn protocol_minimum_mac_len(self) -> usize {
        let half = self.output_len() / 2;
        if half > 10 { half } else { 10 }
    }
}
