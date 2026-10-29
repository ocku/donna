//! RRset validation for a checked uniform-owner authoritative projection.
use super::records::RecordChecks;
use crate::{DomainName, Message, MessageValidationError, ResourceRecord};

impl Message {
    // The writer admits a uniform DNS source owner, a uniform effective answer
    // owner, and authorities disjoint from both. Renaming is therefore a
    // bijection of RRset identities: the ordinary source-record checks remain
    // exact, including their promoted indexes. Owner-dependent record checks
    // use the effective owner. Unsupported projections retain ordinary Message.
    pub(crate) fn validate_borrowed_authoritative_positive(
        answers: &[(&ResourceRecord, &DomainName)],
        authorities: &[&ResourceRecord],
        opt: Option<&ResourceRecord>,
    ) -> Result<(), MessageValidationError> {
        let mut checks = RecordChecks::default();
        for (index, &(record, owner)) in answers.iter().enumerate() {
            record.validate_with_owner(owner).map_err(|error| {
                MessageValidationError::InvalidRecord {
                    section: "answer",
                    index,
                    error,
                }
            })?;
            checks.validate_nontransfer("answer", index, record)?;
            checks.push("answer", index, record);
        }
        for (index, &record) in authorities.iter().enumerate() {
            record.validate_for_forwarding().map_err(|error| {
                MessageValidationError::InvalidRecord {
                    section: "authority",
                    index,
                    error,
                }
            })?;
            checks.validate_nontransfer("authority", index, record)?;
            checks.push("authority", index, record);
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
