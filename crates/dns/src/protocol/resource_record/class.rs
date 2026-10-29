/// Assigned DNS resource-record CLASS codes.
///
/// RFC 6895: <https://www.rfc-editor.org/rfc/rfc6895#section-3.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassType {
    /// Internet (CLASS 1).
    IN,

    /// CHAOS (CLASS 3).
    CH,
    /// Hesiod (CLASS 4).
    HS,
    /// An otherwise unassigned CLASS value retained from the wire.
    Unknown(u16),
}

impl ClassType {
    /// Returns the RFC 1035 CLASS code.
    pub const fn value(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CH => 3,
            Self::HS => 4,
            Self::Unknown(value) => value,
        }
    }

    /// Returns whether `code` is available for ordinary data CLASS use.
    ///
    /// RFC 6895 §3.2 reserves 128–255 and 57344–65279 for QCLASSes or
    /// Meta-CLASSes (with 254 and 255 already assigned), while zero and 65535
    /// are reserved. Private-use values remain valid data CLASS values.
    pub(crate) const fn is_data_code(code: u16) -> bool {
        matches!(code, 1..=127 | 256..=57_343 | 65_280..=65_534)
    }
}

impl From<ClassType> for u16 {
    fn from(value: ClassType) -> Self {
        value.value()
    }
}

#[cfg(test)]
mod tests {
    use super::{ClassType, QClassType};

    #[test]
    fn uses_rfc6895_class_codes() {
        assert_eq!(u16::from(ClassType::IN), 1);
        assert_eq!(u16::from(ClassType::Unknown(2)), 2);
        assert_eq!(u16::from(ClassType::CH), 3);
        assert_eq!(u16::from(ClassType::HS), 4);
        assert_eq!(u16::from(ClassType::Unknown(42)), 42);
    }

    #[test]
    fn uses_rfc1035_qclass_codes() {
        assert_eq!(u16::from(QClassType::Class(ClassType::IN)), 1);
        assert_eq!(u16::from(QClassType::Class(ClassType::HS)), 4);
        assert_eq!(u16::from(QClassType::ANY), 255);
        assert_eq!(u16::from(QClassType::Unknown(42)), 42);
    }
}

/// DNS question-section QCLASS codes.
///
/// QCLASS values are a superset of CLASS values.
///
/// RFC 6895: <https://www.rfc-editor.org/rfc/rfc6895#section-3.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QClassType {
    /// Queries records in a specific resource-record class.
    Class(ClassType),
    /// Queries records in any class (QCLASS 255).
    ANY,
    /// An otherwise unassigned QCLASS value retained from the wire.
    Unknown(u16),
}

impl QClassType {
    /// Returns the RFC 1035 QCLASS code.
    pub const fn value(self) -> u16 {
        match self {
            Self::Class(class) => class.value(),
            Self::ANY => 255,
            Self::Unknown(value) => value,
        }
    }
}

impl From<QClassType> for u16 {
    fn from(value: QClassType) -> Self {
        value.value()
    }
}

/// An invalid DNS query-class mnemonic or numeric code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QClassParseError(String);
impl std::fmt::Display for QClassParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown DNS query class {:?}; use IN, CH, HS, ANY, or CLASS<number>",
            self.0
        )
    }
}
impl std::error::Error for QClassParseError {}

impl std::str::FromStr for QClassType {
    type Err = QClassParseError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text_upper = text.to_ascii_uppercase();
        match text_upper.as_str() {
            "IN" => Ok(Self::Class(ClassType::IN)),
            "CH" => Ok(Self::Class(ClassType::CH)),
            "HS" => Ok(Self::Class(ClassType::HS)),
            "ANY" => Ok(Self::ANY),
            _ => {
                let code = text_upper
                    .strip_prefix("CLASS")
                    .unwrap_or(&text_upper)
                    .parse::<u16>()
                    .map_err(|_| QClassParseError(text.to_owned()))?;
                if code == Self::ANY.value() {
                    return Ok(Self::ANY);
                }
                if !ClassType::is_data_code(code) {
                    return Err(QClassParseError(text.to_owned()));
                }
                Ok([ClassType::IN, ClassType::CH, ClassType::HS]
                    .into_iter()
                    .find(|class| class.value() == code)
                    .map(Self::Class)
                    .unwrap_or(Self::Unknown(code)))
            }
        }
    }
}
impl std::fmt::Display for QClassType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Class(ClassType::Unknown(code)) | Self::Unknown(code) => write!(f, "CLASS{code}"),
            Self::Class(class) => write!(f, "{class:?}"),
            Self::ANY => f.write_str("ANY"),
        }
    }
}

#[cfg(test)]
mod presentation_tests {
    use super::*;

    #[test]
    fn numeric_query_classes_preserve_canonical_and_reserved_values() {
        assert_eq!(
            "class1".parse::<QClassType>().unwrap(),
            QClassType::Class(ClassType::IN)
        );
        assert_eq!(
            "CLASS2".parse::<QClassType>().unwrap(),
            QClassType::Unknown(2)
        );
        assert_eq!("CLASS255".parse::<QClassType>().unwrap(), QClassType::ANY);
        assert_eq!(
            "CLASS65280".parse::<QClassType>().unwrap(),
            QClassType::Unknown(65280)
        );
        for reserved in [
            "CLASS0",
            "CLASS128",
            "CLASS254",
            "CLASS65535",
            "CLASS65536",
            "TYPO",
        ] {
            assert!(reserved.parse::<QClassType>().is_err(), "{reserved}");
        }
    }
}
