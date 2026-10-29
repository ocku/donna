use super::{Headers, Message, MessageValidationError, Question};
use crate::ResourceRecord;

/// Constructs a DNS message and validates it before returning it.
#[derive(Debug, Clone, Default)]
pub struct MessageBuilder {
    headers: Headers,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    additionals: Vec<ResourceRecord>,
}

impl MessageBuilder {
    /// Creates an empty standard-query message builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the message headers.
    #[must_use]
    pub fn headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    /// Replaces the question section.
    #[must_use]
    pub fn questions(mut self, questions: impl IntoIterator<Item = Question>) -> Self {
        self.questions = questions.into_iter().collect();
        self
    }

    /// Replaces the answer section.
    #[must_use]
    pub fn answers(mut self, answers: impl IntoIterator<Item = ResourceRecord>) -> Self {
        self.answers = answers.into_iter().collect();
        self
    }

    /// Replaces the authority section.
    #[must_use]
    pub fn authorities(mut self, authorities: impl IntoIterator<Item = ResourceRecord>) -> Self {
        self.authorities = authorities.into_iter().collect();
        self
    }

    /// Replaces the additional section.
    #[must_use]
    pub fn additionals(mut self, additionals: impl IntoIterator<Item = ResourceRecord>) -> Self {
        self.additionals = additionals.into_iter().collect();
        self
    }

    /// Builds a strictly valid outbound DNS message.
    ///
    /// # Errors
    ///
    /// Returns an error if any header, question, record, section, or
    /// cross-section relationship is invalid for transmission.
    pub fn build(self) -> Result<Message, MessageValidationError> {
        let message = self.build_unchecked();
        message.validate_strict()?;
        Ok(message)
    }

    /// Builds a message without outbound validation.
    ///
    /// This is reserved for wire decoding and tests that need to exercise
    /// validation performed later in the outbound encoding path.
    pub fn build_unchecked(self) -> Message {
        Message {
            headers: self.headers,
            questions: self.questions,
            answers: self.answers,
            authorities: self.authorities,
            additionals: self.additionals,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{ClassType, QClassType, QueryType, RData, RecordType};

    use super::*;

    #[test]
    fn rejects_every_non_wire_representable_public_value_before_encoding() {
        for headers in [
            Headers {
                opcode: crate::OpCode::Unknown(3),
                ..Headers::default()
            },
            Headers {
                qr: true,
                rcode: crate::RCode::Unknown(11),
                ..Headers::default()
            },
            Headers {
                opcode: crate::OpCode::Unknown(16),
                ..Headers::default()
            },
            Headers {
                qr: true,
                rcode: crate::RCode::Unknown(16),
                ..Headers::default()
            },
        ] {
            assert!(matches!(
                MessageBuilder::new().headers(headers).build(),
                Err(MessageValidationError::InvalidHeader(_))
            ));
        }

        for question in [
            Question {
                qname: crate::DomainName::root(),
                qtype: QueryType::Unknown(1),
                qclass: QClassType::Class(ClassType::IN),
            },
            Question {
                qname: crate::DomainName::root(),
                qtype: QueryType::A,
                qclass: QClassType::Unknown(1),
            },
            Question {
                qname: crate::DomainName::root(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::Unknown(42)),
            },
        ] {
            assert!(matches!(
                MessageBuilder::new().questions([question]).build(),
                Err(MessageValidationError::InvalidQuestion { .. })
            ));
        }

        let base = ResourceRecord {
            name: crate::DomainName::root(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 0,
            rdata: RData::A(Ipv4Addr::LOCALHOST),
        };
        let invalid_records = [
            ResourceRecord {
                rdata: RData::NS(crate::DomainName::root()),
                ..base.clone()
            },
            ResourceRecord {
                rtype: RecordType::Unknown(1),
                rdata: RData::Unknown(Vec::new()),
                ..base.clone()
            },
            ResourceRecord {
                class: ClassType::Unknown(1),
                ..base.clone()
            },
            ResourceRecord {
                rtype: RecordType::HINFO,
                rdata: RData::HINFO {
                    cpu: vec![0; 256],
                    os: Vec::new(),
                },
                ..base.clone()
            },
            ResourceRecord {
                rtype: RecordType::NULL,
                rdata: RData::NULL(vec![0; usize::from(u16::MAX) + 1]),
                ..base.clone()
            },
            ResourceRecord {
                rtype: RecordType::WKS,
                rdata: RData::WKS {
                    address: Ipv4Addr::UNSPECIFIED,
                    protocol: 6,
                    bitmap: vec![0; 8193],
                },
                ..base
            },
        ];
        for record in invalid_records {
            assert!(matches!(
                MessageBuilder::new()
                    .headers(Headers {
                        qr: true,
                        ..Headers::default()
                    })
                    .answers([record])
                    .build(),
                Err(MessageValidationError::InvalidRecord { .. })
            ));
        }
    }
}
