use super::*;

impl Message {
    /// Validates an IXFR response using its outstanding transfer question.
    ///
    /// This permits questionless continuation frames and validates RRsets per
    /// ordered delete/add operation. The caller must validate the serial chain
    /// across frames separately.
    pub fn validate_ixfr(
        &self,
        question: &super::super::Question,
    ) -> Result<(), MessageValidationError> {
        self.validate_with_record_origin(false, Some(question))
    }

    pub(super) fn ixfr_validation_question<'a>(
        &'a self,
        explicit: Option<&'a super::super::Question>,
    ) -> Result<Option<&'a super::super::Question>, MessageValidationError> {
        let implicit = match self.questions.as_slice() {
            [question] if question.qtype == QueryType::IXFR => Some(question),
            _ => None,
        };
        let Some(question) = explicit.or(implicit) else {
            return Ok(None);
        };
        if explicit.is_some()
            && (question.qtype != QueryType::IXFR
                || !self.headers.qr
                || self.headers.opcode != OpCode::Query
                || (!self.questions.is_empty()
                    && !matches!(self.questions.as_slice(), [q] if q.qtype == question.qtype && q.qclass == question.qclass && q.qname.eq_dns(&question.qname))))
        {
            return Err(MessageValidationError::InvalidQueryRequestSections);
        }
        Ok(
            (self.headers.qr && self.headers.opcode == OpCode::Query && self.extended_rcode() == 0)
                .then_some(question),
        )
    }
}

#[cfg(test)]
mod tests;
