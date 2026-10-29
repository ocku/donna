use std::fmt;

use unicode_normalization::{UnicodeNormalization, char::is_public_assigned, is_nfc};

use super::{Edns, EdnsOption};

/// EDNS option code assigned to Extended DNS Error by RFC 8914.
pub const EDNS_EXTENDED_DNS_ERROR_OPTION_CODE: u16 = 15;

/// An Extended DNS Error INFO-CODE.
///
/// Values not assigned by RFC 8914 are retained so later assignments and
/// private-use values can be represented without losing wire information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendedDnsErrorCode {
    /// The error does not match another known category (0).
    Other,
    /// The DNSKEY RRset contains only unsupported algorithms (1).
    UnsupportedDnskeyAlgorithm,
    /// The DS RRset contains only unsupported digest types (2).
    UnsupportedDsDigestType,
    /// A previously cached answer was served stale (3).
    StaleAnswer,
    /// Policy caused an answer to be forged (4).
    ForgedAnswer,
    /// DNSSEC validation ended in the indeterminate state (5).
    DnssecIndeterminate,
    /// DNSSEC validation ended in the bogus state (6).
    DnssecBogus,
    /// No signature is currently valid and at least one is expired (7).
    SignatureExpired,
    /// No signature is currently valid and at least one is not yet valid (8).
    SignatureNotYetValid,
    /// A matching DNSKEY could not be found for a parent DS record (9).
    DnskeyMissing,
    /// An expected RRSIG could not be found (10).
    RrsigsMissing,
    /// No DNSKEY has the Zone Key flag set (11).
    NoZoneKeyBitSet,
    /// A covering NSEC or NSEC3 record is missing (12).
    NsecMissing,
    /// A cached SERVFAIL is being returned (13).
    CachedError,
    /// The server is not yet ready to answer (14).
    NotReady,
    /// Internal operator security policy blocked the query (15).
    Blocked,
    /// An external requirement caused the query to be censored (16).
    Censored,
    /// Client-requested policy filtered the query (17).
    Filtered,
    /// The client is not permitted to perform the operation (18).
    Prohibited,
    /// A previously cached NXDOMAIN answer was served stale (19).
    StaleNxdomainAnswer,
    /// The server is not authoritative for the requested name (20).
    NotAuthoritative,
    /// The requested operation is unsupported (21).
    NotSupported,
    /// No authoritative server could be reached (22).
    NoReachableAuthority,
    /// An unrecoverable network error occurred (23).
    NetworkError,
    /// An authoritative server's configured zone data is unusable (24).
    InvalidData,
    /// An unassigned, later-assigned, or private-use INFO-CODE.
    Unknown(u16),
}

impl ExtendedDnsErrorCode {
    /// Returns the unsigned INFO-CODE carried on the wire.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::Other => 0,
            Self::UnsupportedDnskeyAlgorithm => 1,
            Self::UnsupportedDsDigestType => 2,
            Self::StaleAnswer => 3,
            Self::ForgedAnswer => 4,
            Self::DnssecIndeterminate => 5,
            Self::DnssecBogus => 6,
            Self::SignatureExpired => 7,
            Self::SignatureNotYetValid => 8,
            Self::DnskeyMissing => 9,
            Self::RrsigsMissing => 10,
            Self::NoZoneKeyBitSet => 11,
            Self::NsecMissing => 12,
            Self::CachedError => 13,
            Self::NotReady => 14,
            Self::Blocked => 15,
            Self::Censored => 16,
            Self::Filtered => 17,
            Self::Prohibited => 18,
            Self::StaleNxdomainAnswer => 19,
            Self::NotAuthoritative => 20,
            Self::NotSupported => 21,
            Self::NoReachableAuthority => 22,
            Self::NetworkError => 23,
            Self::InvalidData => 24,
            Self::Unknown(value) => value,
        }
    }

    /// Returns whether this code is in RFC 8914's private-use range.
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        self.value() >= 49_152
    }
}

impl From<u16> for ExtendedDnsErrorCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Other,
            1 => Self::UnsupportedDnskeyAlgorithm,
            2 => Self::UnsupportedDsDigestType,
            3 => Self::StaleAnswer,
            4 => Self::ForgedAnswer,
            5 => Self::DnssecIndeterminate,
            6 => Self::DnssecBogus,
            7 => Self::SignatureExpired,
            8 => Self::SignatureNotYetValid,
            9 => Self::DnskeyMissing,
            10 => Self::RrsigsMissing,
            11 => Self::NoZoneKeyBitSet,
            12 => Self::NsecMissing,
            13 => Self::CachedError,
            14 => Self::NotReady,
            15 => Self::Blocked,
            16 => Self::Censored,
            17 => Self::Filtered,
            18 => Self::Prohibited,
            19 => Self::StaleNxdomainAnswer,
            20 => Self::NotAuthoritative,
            21 => Self::NotSupported,
            22 => Self::NoReachableAuthority,
            23 => Self::NetworkError,
            24 => Self::InvalidData,
            value => Self::Unknown(value),
        }
    }
}

impl From<ExtendedDnsErrorCode> for u16 {
    fn from(value: ExtendedDnsErrorCode) -> Self {
        value.value()
    }
}

/// The structured payload of an RFC 8914 Extended DNS Error option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedDnsError {
    /// Machine-readable diagnostic category.
    pub info_code: ExtendedDnsErrorCode,
    /// Optional UTF-8 diagnostic text intended only for human consumption.
    pub extra_text: String,
}

impl ExtendedDnsError {
    /// Largest UTF-8 EXTRA-TEXT payload representable after the INFO-CODE.
    pub const MAX_EXTRA_TEXT_OCTETS: usize = u16::MAX as usize - 2;

    /// Creates an EDE with no EXTRA-TEXT.
    #[must_use]
    pub const fn without_text(info_code: ExtendedDnsErrorCode) -> Self {
        Self {
            info_code,
            extra_text: String::new(),
        }
    }

    /// Creates an EDE with human-readable Net-Unicode EXTRA-TEXT.
    ///
    /// The text is normalized to Unicode Normalization Form C (NFC), as
    /// required by RFC 5198, before its encoded length is checked.
    ///
    /// # Errors
    ///
    /// Returns an error if the text violates RFC 5198's sender profile or if
    /// its encoding cannot fit in OPTION-LENGTH after the two-octet INFO-CODE.
    pub fn new(
        info_code: ExtendedDnsErrorCode,
        extra_text: impl Into<String>,
    ) -> Result<Self, ExtendedDnsErrorError> {
        let extra_text = extra_text.into().nfc().collect::<String>();
        validate_outbound_extra_text(&extra_text)?;
        if extra_text.len() > Self::MAX_EXTRA_TEXT_OCTETS {
            return Err(ExtendedDnsErrorError::ExtraTextTooLong {
                length: extra_text.len(),
            });
        }
        Ok(Self {
            info_code,
            extra_text,
        })
    }

    /// Encodes this structured value as an EDNS option tuple.
    ///
    /// # Errors
    ///
    /// Returns an error when a known INFO-CODE uses the noncanonical
    /// [`ExtendedDnsErrorCode::Unknown`] representation, or when public-field
    /// construction supplied text that violates RFC 5198 or is too long for
    /// an EDNS option after NFC normalization.
    pub fn into_option(mut self) -> Result<EdnsOption, ExtendedDnsErrorError> {
        if let ExtendedDnsErrorCode::Unknown(value @ 0..=24) = self.info_code {
            return Err(ExtendedDnsErrorError::NonCanonicalInfoCode { value });
        }
        if !is_nfc(&self.extra_text) {
            self.extra_text = self.extra_text.nfc().collect();
        }
        validate_outbound_extra_text(&self.extra_text)?;
        if self.extra_text.len() > Self::MAX_EXTRA_TEXT_OCTETS {
            return Err(ExtendedDnsErrorError::ExtraTextTooLong {
                length: self.extra_text.len(),
            });
        }
        let mut data = Vec::with_capacity(2 + self.extra_text.len());
        data.extend_from_slice(&self.info_code.value().to_be_bytes());
        data.extend_from_slice(self.extra_text.as_bytes());
        Ok(EdnsOption {
            code: EDNS_EXTENDED_DNS_ERROR_OPTION_CODE,
            data,
        })
    }

    /// Decodes the structured payload of an EDE option tuple.
    ///
    /// # Errors
    ///
    /// Returns an error for another option code, a missing INFO-CODE, or
    /// EXTRA-TEXT that is not UTF-8. Valid received text is normalized to NFC
    /// for the structured representation.
    pub fn try_from_option(option: &EdnsOption) -> Result<Self, ExtendedDnsErrorError> {
        if option.code != EDNS_EXTENDED_DNS_ERROR_OPTION_CODE {
            return Err(ExtendedDnsErrorError::WrongOptionCode { code: option.code });
        }
        let [high, low, extra_text @ ..] = option.data.as_slice() else {
            return Err(ExtendedDnsErrorError::MissingInfoCode {
                length: option.data.len(),
            });
        };
        let extra_text = std::str::from_utf8(extra_text)
            .map_err(|_| ExtendedDnsErrorError::ExtraTextNotUtf8)?
            .nfc()
            .collect();
        Ok(Self {
            info_code: u16::from_be_bytes([*high, *low]).into(),
            extra_text,
        })
    }
}

/// A malformed or unrepresentable Extended DNS Error option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsErrorError {
    /// A known INFO-CODE was represented by the opaque `Unknown` variant.
    NonCanonicalInfoCode {
        /// Contains the known INFO-CODE that must use its named variant.
        value: u16,
    },
    /// The EDNS tuple does not use EDE option code 15.
    WrongOptionCode {
        /// Contains the actual option code.
        code: u16,
    },
    /// The option payload is shorter than the two-octet INFO-CODE.
    MissingInfoCode {
        /// Contains the actual payload length.
        length: usize,
    },
    /// EXTRA-TEXT is not valid UTF-8.
    ExtraTextNotUtf8,
    /// EXTRA-TEXT begins with the forbidden Net-Unicode BOM signature.
    ExtraTextStartsWithBom,
    /// EXTRA-TEXT contains an RFC 5198 C1 control character.
    ExtraTextContainsC1Control {
        /// Contains the prohibited Unicode code point.
        code_point: u32,
    },
    /// EXTRA-TEXT contains a code point unassigned in the supported Unicode
    /// version.
    ExtraTextContainsUnassignedCodePoint {
        /// Contains the prohibited Unicode code point.
        code_point: u32,
    },
    /// EXTRA-TEXT contains a carriage return not followed by LF or NUL.
    ExtraTextContainsInvalidCarriageReturn {
        /// Contains the UTF-8 byte index of the invalid carriage return.
        byte_index: usize,
    },
    /// EXTRA-TEXT uses a Unicode line or paragraph separator forbidden by
    /// Net-Unicode.
    ExtraTextContainsUnicodeLineSeparator {
        /// Contains U+2028 or U+2029.
        code_point: u32,
    },
    /// EXTRA-TEXT leaves no room for the two-octet INFO-CODE.
    ExtraTextTooLong {
        /// Contains the UTF-8 text length in octets.
        length: usize,
    },
}

impl fmt::Display for ExtendedDnsErrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalInfoCode { value } => write!(
                f,
                "known EDE INFO-CODE {value} must use its named representation"
            ),
            Self::WrongOptionCode { code } => write!(f, "EDNS option code {code} is not EDE"),
            Self::MissingInfoCode { length } => {
                write!(
                    f,
                    "EDE payload length {length} omits its two-octet INFO-CODE"
                )
            }
            Self::ExtraTextNotUtf8 => f.write_str("EDE EXTRA-TEXT is not valid UTF-8"),
            Self::ExtraTextStartsWithBom => {
                f.write_str("EDE EXTRA-TEXT must not begin with a Unicode BOM")
            }
            Self::ExtraTextContainsC1Control { code_point } => write!(
                f,
                "EDE EXTRA-TEXT contains prohibited C1 control U+{code_point:04X}"
            ),
            Self::ExtraTextContainsUnassignedCodePoint { code_point } => write!(
                f,
                "EDE EXTRA-TEXT contains unassigned code point U+{code_point:04X}"
            ),
            Self::ExtraTextContainsInvalidCarriageReturn { byte_index } => write!(
                f,
                "EDE EXTRA-TEXT contains invalid carriage return at byte {byte_index}"
            ),
            Self::ExtraTextContainsUnicodeLineSeparator { code_point } => write!(
                f,
                "EDE EXTRA-TEXT contains forbidden line separator U+{code_point:04X}"
            ),
            Self::ExtraTextTooLong { length } => write!(
                f,
                "EDE EXTRA-TEXT length {length} exceeds {}",
                ExtendedDnsError::MAX_EXTRA_TEXT_OCTETS
            ),
        }
    }
}

impl std::error::Error for ExtendedDnsErrorError {}

pub(crate) fn validate_outbound_extra_text(extra_text: &str) -> Result<(), ExtendedDnsErrorError> {
    if extra_text.starts_with('\u{feff}') {
        return Err(ExtendedDnsErrorError::ExtraTextStartsWithBom);
    }

    let mut characters = extra_text.char_indices().peekable();
    while let Some((byte_index, character)) = characters.next() {
        let code_point = u32::from(character);
        if ('\u{80}'..='\u{9f}').contains(&character) {
            return Err(ExtendedDnsErrorError::ExtraTextContainsC1Control { code_point });
        }
        if matches!(character, '\u{2028}' | '\u{2029}') {
            return Err(
                ExtendedDnsErrorError::ExtraTextContainsUnicodeLineSeparator { code_point },
            );
        }
        if character == '\r'
            && !characters
                .peek()
                .is_some_and(|(_, next)| matches!(next, '\n' | '\0'))
        {
            return Err(
                ExtendedDnsErrorError::ExtraTextContainsInvalidCarriageReturn { byte_index },
            );
        }
        if !is_public_assigned(character) && !is_private_use(character) {
            return Err(ExtendedDnsErrorError::ExtraTextContainsUnassignedCodePoint { code_point });
        }
    }
    Ok(())
}

const fn is_private_use(character: char) -> bool {
    matches!(
        character,
        '\u{e000}'..='\u{f8ff}'
            | '\u{f0000}'..='\u{ffffd}'
            | '\u{100000}'..='\u{10fffd}'
    )
}

impl EdnsOption {
    /// Returns whether this tuple is an Extended DNS Error option.
    #[must_use]
    pub const fn is_extended_dns_error(&self) -> bool {
        self.code == EDNS_EXTENDED_DNS_ERROR_OPTION_CODE
    }

    /// Parses this tuple as an Extended DNS Error when it uses option code 15.
    ///
    /// # Errors
    ///
    /// Returns an error when an EDE payload is malformed. Another option code
    /// returns `Ok(None)`.
    pub fn as_extended_dns_error(&self) -> Result<Option<ExtendedDnsError>, ExtendedDnsErrorError> {
        self.is_extended_dns_error()
            .then(|| ExtendedDnsError::try_from_option(self))
            .transpose()
    }
}

impl Edns {
    /// Iterates over every EDE option in wire order.
    ///
    /// Multiple EDE options are deliberately retained and exposed. Individual
    /// malformed payloads are reported without hiding later options.
    pub fn extended_dns_errors(
        &self,
    ) -> impl Iterator<Item = Result<ExtendedDnsError, ExtendedDnsErrorError>> + '_ {
        self.options
            .iter()
            .filter(|option| option.is_extended_dns_error())
            .map(ExtendedDnsError::try_from_option)
    }

    /// Appends an EDE option without replacing any existing EDE options.
    ///
    /// # Errors
    ///
    /// Returns an error when `error` cannot be represented canonically.
    pub fn push_extended_dns_error(
        &mut self,
        error: ExtendedDnsError,
    ) -> Result<(), ExtendedDnsErrorError> {
        self.options.push(error.into_option()?);
        Ok(())
    }

    /// Removes every EDE option and reports whether one was present.
    pub fn remove_extended_dns_errors(&mut self) -> bool {
        let old_length = self.options.len();
        self.options
            .retain(|option| !option.is_extended_dns_error());
        self.options.len() != old_length
    }
}

#[cfg(test)]
mod tests;
