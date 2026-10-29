use std::fmt;

use crate::{ClassType, DomainName, QClassType, QueryType};

/// A DNS question.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2>
#[derive(Debug, Clone)]
pub struct Question {
    /// The domain name being queried.
    pub qname: DomainName,
    /// The type of the resource record being queried.
    pub qtype: QueryType,
    /// The class of the resource record being queried.
    pub qclass: QClassType,
}

/// A question value that has a noncanonical public representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuestionValidationError {
    NonCanonicalQueryType { value: u16 },
    NonCanonicalQueryClass { value: u16 },
}

impl fmt::Display for QuestionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalQueryType { value } => {
                write!(f, "QTYPE {value} uses the wrong public enum variant")
            }
            Self::NonCanonicalQueryClass { value } => {
                write!(f, "QCLASS {value} uses the wrong public enum variant")
            }
        }
    }
}

impl std::error::Error for QuestionValidationError {}

impl Question {
    /// Returns whether QTYPE and QCLASS use their canonical public variants.
    pub fn is_wire_canonical(&self) -> bool {
        self.validate_wire().is_ok()
    }

    /// Validates the public QTYPE and QCLASS representations before encoding.
    pub(crate) fn validate_wire(&self) -> Result<(), QuestionValidationError> {
        if let QueryType::Unknown(value) = self.qtype
            && matches!(
                value,
                0 | 1..=16 | 24 | 25 | 28 | 33 | 39 | 43 | 46..=48 | 50..=53 | 62 | 251..=255 | 257 | u16::MAX
            )
        {
            return Err(QuestionValidationError::NonCanonicalQueryType { value });
        }

        let noncanonical_qclass = match self.qclass {
            QClassType::Unknown(value) if matches!(value, 0 | 1 | 3 | 4 | 255 | u16::MAX) => {
                Some(value)
            }
            QClassType::Class(ClassType::Unknown(value)) => Some(value),
            _ => None,
        };
        if let Some(value) = noncanonical_qclass {
            return Err(QuestionValidationError::NonCanonicalQueryClass { value });
        }

        Ok(())
    }
}
