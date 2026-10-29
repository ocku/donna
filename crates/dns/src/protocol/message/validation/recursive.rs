//! Ordinary RRset checks for the restricted borrowed recursive reply writer.
use super::records::RecordChecks;
use crate::{Message, MessageValidationError, ResourceRecord};

impl Message {
    // The checked writer fixes QUERY/QR/RA, NOERROR, !AA/!TC, one already
    // validated concrete question, ordinary records and at most one empty OPT. There
    // are no transaction signatures, transfers or authoritative-negative rules.
    pub(crate) fn validate_borrowed_recursive(
        answers: &[(&ResourceRecord, u32)],
        authorities: &[(&ResourceRecord, u32)],
        opt: Option<&ResourceRecord>,
    ) -> Result<(), MessageValidationError> {
        let mut checks = RecordChecks::default();
        for (section, records) in [("answer", answers), ("authority", authorities)] {
            for (index, &(record, ttl)) in records.iter().enumerate() {
                record.validate_for_forwarding().map_err(|error| {
                    MessageValidationError::InvalidRecord {
                        section,
                        index,
                        error,
                    }
                })?;
                checks.validate_with_ttl(section, index, record, ttl)?;
                checks.push_with_ttl(section, index, record, ttl);
            }
        }
        if let Some(opt) = opt {
            opt.validate_for_forwarding().map_err(|error| {
                MessageValidationError::InvalidRecord {
                    section: "additional",
                    index: 0,
                    error,
                }
            })?;
        }
        Ok(())
    }
}
