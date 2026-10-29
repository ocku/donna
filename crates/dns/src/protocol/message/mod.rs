/// Fluent construction of validated DNS messages.
mod builder;
mod cache;
/// DNS domain-name value definitions.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.1>
mod domain_name;
/// DNS message header definitions.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035/#section-4.1.1>
mod headers;
/// DNS query type definitions.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.3>
mod qtype;
/// DNS question format.
///
/// RFC 1035: <https://www.rfc-editor.org/info/rfc1035/#section-4.1.2>
mod question;
/// Shared error reply construction and EDNS error handling.
mod response;

mod error;
mod notify;
mod update;
mod validation;

use crate::ResourceRecord;

#[cfg(test)]
use crate::{RecordType, RecordValidationError};

pub use builder::MessageBuilder;
pub use domain_name::{DomainName, DomainNameError};
pub use error::{MessageValidationError, SectionTooLongError};
pub use headers::{HeaderFieldValueError, Headers, OpCode, RCode};
pub(crate) use notify::validate_notify_message;
pub use qtype::{QueryType, QueryTypeParseError};
pub use question::Question;
pub(crate) use question::QuestionValidationError;
pub(crate) use update::validate_update_message;

/// The four section counts that occupy an RFC 1035 wire header.
///
/// They are derived from [`Message`] rather than independently stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionCounts {
    /// Counts entries in the question section.
    pub questions: u16,
    /// Counts entries in the answer section.
    pub answers: u16,
    /// Counts entries in the authority section.
    pub authorities: u16,
    /// Counts entries in the additional section.
    pub additionals: u16,
}

/// A DNS message.
///
/// This is an in-memory semantic model. Compression, section counts, and
/// RDLENGTH are wire-level derived values and are not stored redundantly.
///
/// RFC 1035 §4.
#[derive(Debug, Clone)]
pub struct Message {
    /// Contains semantic header fields.
    pub headers: Headers,
    /// Contains questions in wire order.
    pub questions: Vec<Question>,
    /// Contains answer records in wire order.
    pub answers: Vec<ResourceRecord>,
    /// Contains authority records in wire order.
    pub authorities: Vec<ResourceRecord>,
    /// Contains additional records in wire order.
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Starts building a message that will be strictly validated before use.
    #[must_use]
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    /// Derives the four RFC 1035 section counts for this message.
    ///
    /// # Errors
    ///
    /// Returns an error if any section contains more than [`u16::MAX`] entries.
    pub fn section_counts(&self) -> Result<SectionCounts, SectionTooLongError> {
        Ok(SectionCounts {
            questions: section_count("question", self.questions.len())?,
            answers: section_count("answer", self.answers.len())?,
            authorities: section_count("authority", self.authorities.len())?,
            additionals: section_count("additional", self.additionals.len())?,
        })
    }

    /// Verifies that every section can be represented by an RFC 1035 header.
    ///
    /// # Errors
    ///
    /// Returns an error if any section contains more than [`u16::MAX`] entries.
    pub fn validate(&self) -> Result<(), SectionTooLongError> {
        self.section_counts().map(|_| ())
    }
}

fn section_count(section: &'static str, length: usize) -> Result<u16, SectionTooLongError> {
    u16::try_from(length).map_err(|_| SectionTooLongError { section, length })
}

#[cfg(test)]
mod tests;
