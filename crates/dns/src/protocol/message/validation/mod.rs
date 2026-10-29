mod authoritative_positive;
mod helpers;
mod ixfr;
mod negative;
mod records;
mod recursive;

use crate::{QClassType, RData, RecordType, ResourceRecord};
use helpers::{answer_matches_question, is_allowed_nxdomain_answer};
use records::RecordChecks;

use super::{
    Message, MessageValidationError, OpCode, QueryType, QuestionValidationError, RCode,
    validate_notify_message, validate_update_message,
};

const NOERROR_RCODE: u16 = 0;
const NXDOMAIN_RCODE: u16 = 3;

impl Message {
    /// Strictly validates outgoing message data.
    ///
    /// Decoding remains deliberately permissive, but messages intended for
    /// transmission must use representable header and question values, valid
    /// records, and RFC 2181-consistent RRSets across all message sections.
    ///
    /// # Errors
    ///
    /// Returns an error that identifies the first invalid message property.
    pub fn validate_strict(&self) -> Result<(), MessageValidationError> {
        self.validate_with_record_origin(true, None)
    }

    /// Validates a message for forwarding received records.
    ///
    /// Unlike local construction, forwarding permits opaque reserved CAA flag
    /// bits and advisory DNSSEC algorithm codes, preserving received values.
    /// EDNS Z bits remain invalid because OPT records are hop-by-hop metadata.
    pub fn validate_for_forwarding(&self) -> Result<(), MessageValidationError> {
        self.validate_with_record_origin(false, None)
    }

    fn validate_with_record_origin(
        &self,
        locally_authored: bool,
        ixfr_question: Option<&super::Question>,
    ) -> Result<(), MessageValidationError> {
        let ixfr_question = self.ixfr_validation_question(ixfr_question)?;
        self.validate()
            .map_err(MessageValidationError::SectionTooLong)?;
        self.headers
            .validate_wire()
            .map_err(MessageValidationError::InvalidHeader)?;
        self.validate_tsig_structure()?;
        self.validate_sig0_structure()?;
        if self.headers.opcode == OpCode::Update {
            return validate_update_message(self, locally_authored);
        }
        if self.headers.opcode == OpCode::Notify {
            return validate_notify_message(self, locally_authored);
        }
        if !self.headers.qr
            && (self.headers.aa
                || self.headers.tc
                || self.headers.ra
                || self.headers.rcode != RCode::Ok)
        {
            return Err(MessageValidationError::ResponseOnlyQueryFields);
        }
        if !self.headers.qr && self.headers.opcode == OpCode::Query {
            let ixfr = self
                .questions
                .iter()
                .any(|question| question.qtype == QueryType::IXFR);
            if !self.answers.is_empty()
                || (ixfr && !self.is_valid_ixfr_request())
                || (!ixfr && !self.authorities.is_empty())
            {
                return Err(MessageValidationError::InvalidQueryRequestSections);
            }
        }
        if !self.headers.qr
            && self.headers.opcode == OpCode::IQuery
            && (!self.questions.is_empty()
                || self.answers.len() != 1
                || !self.authorities.is_empty()
                || !self.additionals.is_empty())
        {
            return Err(MessageValidationError::InvalidIqueryRequestSections);
        }
        for (index, question) in self.questions.iter().enumerate() {
            question.validate_wire().map_err(|error| {
                let (field, value) = match error {
                    QuestionValidationError::NonCanonicalQueryType { value } => ("QTYPE", value),
                    QuestionValidationError::NonCanonicalQueryClass { value } => ("QCLASS", value),
                };
                MessageValidationError::InvalidQuestion {
                    index,
                    field,
                    value,
                }
            })?;
        }
        if self.headers.qr
            && self.headers.aa
            && self
                .questions
                .iter()
                .any(|question| question.qclass == QClassType::ANY)
        {
            return Err(MessageValidationError::AuthoritativeAnyClass);
        }
        if self
            .answers
            .iter()
            .chain(&self.authorities)
            .any(|record| record.rtype == RecordType::OPT)
        {
            return Err(MessageValidationError::OptOutsideAdditional);
        }
        let opt_count = self
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .count();
        if opt_count > 1 {
            return Err(MessageValidationError::MultipleOpt);
        }
        let semantic_rcode = self.extended_rcode();
        if self.has_invalid_authoritative_negative_response(semantic_rcode)
            && !self.is_padding_only_transfer_response(semantic_rcode)
        {
            return Err(MessageValidationError::InvalidAuthoritativeNegativeResponse);
        }
        if !self.headers.qr && semantic_rcode != NOERROR_RCODE {
            return Err(MessageValidationError::ExtendedRcodeInRequest);
        }
        if self.headers.qr
            && semantic_rcode == NOERROR_RCODE
            && matches!(self.questions.as_slice(), [question] if question.qtype == QueryType::AXFR)
            && (self.headers.opcode != OpCode::Query
                || !self.headers.aa
                || self.headers.tc
                || self.headers.ad
                || self.headers.cd
                || !self.authorities.is_empty())
        {
            return Err(MessageValidationError::InvalidAxfrResponseFields);
        }
        let mut previous_records = RecordChecks::default();
        for (section, records) in [
            ("answer", &self.answers),
            ("authority", &self.authorities),
            ("additional", &self.additionals),
        ] {
            for (index, record) in records.iter().enumerate() {
                let validation = if locally_authored {
                    record.validate_locally_authored()
                } else {
                    record.validate_for_forwarding()
                };
                validation.map_err(|error| MessageValidationError::InvalidRecord {
                    section,
                    index,
                    error,
                })?;

                // OPT and TSIG are transaction metadata, not RRSets. Their
                // cardinality and placement were checked above.
                if matches!(record.rtype, RecordType::OPT | RecordType::TSIG) {
                    continue;
                }
                // Each SOA starts a distinct delete/add operation. RRsets in
                // different operations describe different versions of the zone.
                if section == "answer"
                    && ixfr_question.is_some_and(|q| {
                        record.rtype == RecordType::SOA
                            && record.name.eq_dns(&q.qname)
                            && record.class.value() == q.qclass.value()
                    })
                {
                    previous_records.clear();
                    continue;
                }

                previous_records.validate(self, section, index, record, semantic_rcode)?;
                previous_records.push(section, index, record);
            }
        }
        Ok(())
    }

    fn validate_tsig_structure(&self) -> Result<(), MessageValidationError> {
        if self
            .answers
            .iter()
            .chain(&self.authorities)
            .any(|record| record.rtype == RecordType::TSIG)
        {
            return Err(MessageValidationError::TsigOutsideAdditional);
        }
        let indexes = self
            .additionals
            .iter()
            .enumerate()
            .filter_map(|(index, record)| (record.rtype == RecordType::TSIG).then_some(index))
            .collect::<Vec<_>>();
        if indexes.len() > 1 {
            return Err(MessageValidationError::MultipleTsig);
        }
        let Some(index) = indexes.first().copied() else {
            return Ok(());
        };
        if index + 1 != self.additionals.len() {
            return Err(MessageValidationError::TsigNotLast);
        }
        let record = &self.additionals[index];
        let RData::TSIG(tsig) = &record.rdata else {
            return Err(MessageValidationError::InvalidTsigMessage);
        };
        if (!self.headers.qr
            && (tsig.error != crate::TsigErrorCode::NoError || tsig.original_id != self.headers.id))
            || (self.headers.qr
                && ((tsig.error == crate::TsigErrorCode::BadTime && tsig.other_data.len() != 6)
                    || (tsig.error != crate::TsigErrorCode::BadTime
                        && !tsig.other_data.is_empty())))
        {
            return Err(MessageValidationError::InvalidTsigMessage);
        }
        Ok(())
    }

    fn validate_sig0_structure(&self) -> Result<(), MessageValidationError> {
        let is_sig0 =
            |record: &ResourceRecord| matches!(&record.rdata, RData::SIG(sig) if sig.is_sig0());
        if self.answers.iter().chain(&self.authorities).any(is_sig0) {
            return Err(MessageValidationError::Sig0OutsideAdditional);
        }
        let indexes = self
            .additionals
            .iter()
            .enumerate()
            .filter_map(|(index, record)| is_sig0(record).then_some(index))
            .collect::<Vec<_>>();
        if indexes.len() > 1 {
            return Err(MessageValidationError::MultipleSig0);
        }
        let Some(index) = indexes.first().copied() else {
            return Ok(());
        };
        if self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
            .any(|record| record.rtype == RecordType::TSIG)
        {
            return Err(MessageValidationError::MultipleAuthenticationSchemes);
        }
        if index + 1 != self.additionals.len() {
            return Err(MessageValidationError::Sig0NotLast);
        }
        let record = &self.additionals[index];
        let RData::SIG(sig) = &record.rdata else {
            unreachable!("SIG(0) predicate requires SIG RDATA")
        };
        if record.rtype != RecordType::SIG || sig.labels != 0 {
            return Err(MessageValidationError::InvalidSig0Message);
        }
        Ok(())
    }

    fn has_invalid_authoritative_negative_response(&self, semantic_rcode: u16) -> bool {
        if !self.headers.qr || !self.headers.aa || self.headers.tc {
            return false;
        }
        if semantic_rcode == NXDOMAIN_RCODE
            && self
                .answers
                .iter()
                .any(|record| !is_allowed_nxdomain_answer(record.rtype))
        {
            return true;
        }
        let [question] = self.questions.as_slice() else {
            // TCP responses and non-initial AXFR messages may omit the
            // question. A positive answer can still be validated record by
            // record below; an explicit or empty-answer negative cannot prove
            // its required SOA scope without the question.
            return semantic_rcode == NXDOMAIN_RCODE
                || (semantic_rcode == NOERROR_RCODE && self.answers.is_empty());
        };
        let negative_name = self.negative_answer_name(question);
        // RFC 1034 section 4.3.2 permits stopping after a CNAME when the
        // target is outside this server's authority, including at a delegation.
        // AA describes the original owner; it does not assert target NODATA.
        // An SOA asserts a terminal negative and must still be scoped below.
        if semantic_rcode == NOERROR_RCODE
            && !negative_name.eq_dns(&question.qname)
            && !self
                .authorities
                .iter()
                .any(|record| record.rtype == RecordType::SOA)
        {
            return false;
        }
        let negative = semantic_rcode == NXDOMAIN_RCODE
            || (semantic_rcode == NOERROR_RCODE
                && (self.answers.is_empty()
                    || (self
                        .answers
                        .iter()
                        .all(|record| is_allowed_nxdomain_answer(record.rtype))
                        && !self.answers.iter().any(|record| {
                            answer_matches_question(record, question, negative_name)
                        }))));
        if !negative {
            return false;
        }
        !self.authorities.iter().any(|record| {
            record.rtype == RecordType::SOA
                && record.class.value() == question.qclass.value()
                && negative_name.is_descendant_of(&record.name)
                && matches!(record.rdata, RData::SOA { minimum, .. } if record.ttl <= minimum)
        })
    }

    fn is_padding_only_transfer_response(&self, semantic_rcode: u16) -> bool {
        self.headers.qr
            && self.headers.aa
            && !self.headers.tc
            && self.headers.opcode == OpCode::Query
            && semantic_rcode == NOERROR_RCODE
            // RFC 9103 section 7.9.1 requires AXoT clients to accept an
            // otherwise-empty response containing only an OPT RR with
            // Padding. Non-initial transfer messages may omit the question,
            // so the generic wire representation cannot always identify the
            // transfer until its caller applies outstanding-query context.
            && (self.questions.is_empty()
                || matches!(
                    self.questions.as_slice(),
                    [question] if matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
                ))
            && self.answers.is_empty()
            && self.authorities.is_empty()
            && matches!(self.additionals.as_slice(), [record]
                if record.rtype == RecordType::OPT
                    && self
                        .edns()
                        .ok()
                        .flatten()
                        .is_some_and(|edns| edns.padding().is_some()))
    }

    /// Returns the name whose existence/type the terminal response denies.
    /// RFC 2308 section 2.2 defines that as the target of the last CNAME,
    /// rather than unconditionally as the original QNAME.
    fn negative_answer_name<'a>(&'a self, question: &'a super::Question) -> &'a crate::DomainName {
        if matches!(question.qtype, QueryType::CNAME | QueryType::ANY) {
            return &question.qname;
        }
        let mut current = &question.qname;
        // The bound also makes malformed CNAME cycles harmless here; the
        // ordinary strict RR/CNAME validation below reports those records.
        for _ in 0..self.answers.len() {
            let Some(target) = self.answers.iter().find_map(|record| {
                (record.rtype == RecordType::CNAME
                    && record.class.value() == question.qclass.value()
                    && record.name.eq_dns(current))
                .then_some(match &record.rdata {
                    RData::CNAME(target) => Some(target),
                    _ => None,
                })
                .flatten()
            }) else {
                break;
            };
            current = target;
        }
        current
    }

    fn is_valid_ixfr_request(&self) -> bool {
        matches!(
            (self.questions.as_slice(), self.authorities.as_slice()),
            ([question], [soa])
                if question.qtype == QueryType::IXFR
                    && soa.rtype == RecordType::SOA
                    && soa.name.eq_dns(&question.qname)
                    && matches!(
                        question.qclass,
                        crate::QClassType::Class(class) if soa.class == class
                    )
        )
    }

    fn is_transfer_boundary_soa_duplicate(
        &self,
        previous_section: &str,
        previous_index: usize,
        section: &str,
        index: usize,
        record: &ResourceRecord,
        semantic_rcode: u16,
    ) -> bool {
        self.headers.qr
            && self.headers.opcode == OpCode::Query
            && semantic_rcode == NOERROR_RCODE
            && matches!(
                self.questions.as_slice(),
                [question]
                    if matches!(question.qtype, QueryType::AXFR | QueryType::IXFR)
                        && previous_section == "answer"
                        && section == "answer"
                        && previous_index == 0
                        && index + 1 == self.answers.len()
                        && record.rtype == RecordType::SOA
            )
    }
}
