use crate::{DomainName, QueryType, RecordType, RecordValidationError, ResourceRecord};

use super::super::{MessageValidationError, Question};

pub(super) fn is_rrsig_type(rtype: RecordType) -> bool {
    matches!(u16::from(rtype), 24 | 46)
}

pub(super) fn is_allowed_nxdomain_answer(rtype: RecordType) -> bool {
    matches!(rtype, RecordType::CNAME | RecordType::DNAME) || matches!(u16::from(rtype), 24 | 46)
}

pub(super) fn answer_matches_question(
    record: &ResourceRecord,
    question: &Question,
    name: &DomainName,
) -> bool {
    if record.class.value() != question.qclass.value() || !record.name.eq_dns(name) {
        return false;
    }
    match question.qtype {
        QueryType::ANY => true,
        QueryType::MAILA => matches!(record.rtype, RecordType::MD | RecordType::MF),
        QueryType::MAILB => matches!(
            record.rtype,
            RecordType::MB | RecordType::MG | RecordType::MR
        ),
        qtype => u16::from(qtype) == u16::from(record.rtype),
    }
}

pub(super) fn invalid_record(
    section: &'static str,
    index: usize,
    error: RecordValidationError,
) -> MessageValidationError {
    MessageValidationError::InvalidRecord {
        section,
        index,
        error,
    }
}
