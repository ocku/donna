//! Complete validation for the restricted borrowed authoritative-negative writer.
use crate::{
    Headers, Message, MessageValidationError, Question, RData, RecordType, ResourceRecord,
};

use super::records::RecordChecks;

impl Message {
    // The wire constructor fixes QUERY/QR/AA, one concrete-class question,
    // empty Answer, no transaction signatures and at most one empty OPT.
    // These are the remaining ordinary Message checks. Reuse the same RRset
    // validator so duplicate, TTL and CNAME consistency cannot diverge.
    pub(crate) fn validate_borrowed_negative(
        headers: &Headers,
        question: &Question,
        authorities: &[&ResourceRecord],
        opt: Option<&ResourceRecord>,
    ) -> Result<(), MessageValidationError> {
        headers
            .validate_wire()
            .map_err(MessageValidationError::InvalidHeader)?;
        question.validate_wire().map_err(|error| {
            let (field, value) = match error {
                crate::protocol::message::QuestionValidationError::NonCanonicalQueryType {
                    value,
                } => ("QTYPE", value),
                crate::protocol::message::QuestionValidationError::NonCanonicalQueryClass {
                    value,
                } => ("QCLASS", value),
            };
            MessageValidationError::InvalidQuestion {
                index: 0,
                field,
                value,
            }
        })?;
        if !authorities.iter().any(|record| {
            record.rtype == RecordType::SOA
                && record.class.value() == question.qclass.value()
                && question.qname.is_descendant_of(&record.name)
                && matches!(record.rdata, RData::SOA { minimum, .. } if record.ttl <= minimum)
        }) {
            return Err(MessageValidationError::InvalidAuthoritativeNegativeResponse);
        }
        let mut checks = RecordChecks::default();
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

impl Message {
    /// Additional scope checks after ordinary effective-TTL RRset validation.
    pub(crate) fn validate_borrowed_recursive_negative(
        question: &Question,
        answers: &[(&ResourceRecord, u32)],
        authorities: &[(&ResourceRecord, u32)],
    ) -> Result<(), MessageValidationError> {
        let invalid = || MessageValidationError::InvalidAuthoritativeNegativeResponse;
        let mut terminal = &question.qname;
        let mut hops = 0;
        while let Some(target) = answers.iter().find_map(|&(record, _)| {
            if record.rtype == RecordType::CNAME
                && record.name.eq_dns(terminal)
                && let RData::CNAME(target) = &record.rdata
            {
                return Some(target);
            }
            None
        }) {
            hops += 1;
            if hops > answers.len() {
                return Err(invalid());
            }
            terminal = target;
        }
        // Reject disconnected CNAMEs as well as bounded cycles. Signatures do
        // not count as hops; the wire constructor checks their covered owner.
        if hops
            != answers
                .iter()
                .filter(|(record, _)| record.rtype == RecordType::CNAME)
                .count()
            || !authorities.iter().any(|&(record, ttl)| {
                record.rtype == RecordType::SOA
                    && record.class.value() == question.qclass.value()
                    && terminal.is_descendant_of(&record.name)
                    && matches!(record.rdata, RData::SOA { minimum, .. } if ttl <= minimum)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}
