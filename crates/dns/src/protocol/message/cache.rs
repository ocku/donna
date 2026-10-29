//! Shared RFC 2308 negative-response cache lifetime semantics.
use super::Message;

impl Message {
    /// Returns the effective SOA lifetime of a negative response in seconds.
    ///
    /// Follows CNAME chains to the terminal owner and requires an enclosing
    /// SOA of the question's class. The lifetime is bounded by both the SOA
    /// record TTL and SOA.MINIMUM. Returns `None` for positive responses and
    /// response codes other than NOERROR/NXDOMAIN. Returns `Some(0)` when a
    /// negative response has no usable proof, including a cyclic CNAME chain.
    /// Callers must also bound retention by answer TTLs and local policy.
    #[must_use]
    pub fn negative_cache_ttl(&self) -> Option<u32> {
        if !matches!(
            self.headers.rcode,
            crate::RCode::Ok | crate::RCode::NameError
        ) {
            return None;
        }

        let nxdomain = self.headers.rcode == crate::RCode::NameError;
        let mut negative_ttl = None;
        let mut found_negative_question = false;
        for question in &self.questions {
            if !nxdomain && question_has_requested_answer_through_cname(self, question) {
                continue;
            }

            found_negative_question = true;
            let Some(terminal_owner) = terminal_owner_through_cname(self, question) else {
                return Some(0);
            };
            let Some(question_ttl) = self
                .authorities
                .iter()
                .filter_map(|record| match &record.rdata {
                    // RFC 2308 section 5 defines a negative response's cache TTL
                    // as the smaller of the SOA RR TTL and SOA.MINIMUM. An SOA is
                    // applicable only when it encloses this question's terminal
                    // CNAME owner and belongs to the question's class.
                    crate::RData::SOA { minimum, .. }
                        if record.rtype == crate::RecordType::SOA
                            && question_class_matches_record(question.qclass, record.class)
                            && terminal_owner.is_descendant_of(&record.name) =>
                    {
                        Some(record.ttl.min(*minimum))
                    }
                    _ => None,
                })
                .min()
            else {
                return Some(0);
            };
            negative_ttl =
                Some(negative_ttl.map_or(question_ttl, |ttl: u32| ttl.min(question_ttl)));
        }

        if found_negative_question {
            negative_ttl
        } else if self.questions.is_empty() {
            // With no question there is no owner or class against which an SOA can
            // be validated, so a nominally negative response is not cacheable.
            Some(0)
        } else {
            None
        }
    }
}

fn question_has_requested_answer_through_cname(
    message: &Message,
    question: &crate::Question,
) -> bool {
    let mut owner = question.qname.clone();
    for _ in 0..=message.answers.len() {
        if message.answers.iter().any(|record| {
            record.name.eq_dns(&owner)
                && question_class_matches_record(question.qclass, record.class)
                && query_type_matches_record(question.qtype, record.rtype)
        }) {
            return true;
        }
        let Some(target) = cname_target(message, question, &owner) else {
            return false;
        };
        owner = target;
    }
    false
}

fn terminal_owner_through_cname(
    message: &Message,
    question: &crate::Question,
) -> Option<crate::DomainName> {
    let mut owner = question.qname.clone();
    let mut visited = Vec::new();
    loop {
        if visited
            .iter()
            .any(|visited: &crate::DomainName| visited.eq_dns(&owner))
        {
            return None;
        }
        visited.push(owner.clone());
        let Some(target) = cname_target(message, question, &owner) else {
            return Some(owner);
        };
        owner = target;
    }
}

fn cname_target(
    message: &Message,
    question: &crate::Question,
    owner: &crate::DomainName,
) -> Option<crate::DomainName> {
    message.answers.iter().find_map(|record| {
        (record.name.eq_dns(owner) && question_class_matches_record(question.qclass, record.class))
            .then_some(&record.rdata)
            .and_then(|rdata| match rdata {
                crate::RData::CNAME(target) => Some(target.clone()),
                _ => None,
            })
    })
}

fn question_class_matches_record(qclass: crate::QClassType, class: crate::ClassType) -> bool {
    match qclass {
        crate::QClassType::Class(expected) => class == expected,
        crate::QClassType::ANY => true,
        crate::QClassType::Unknown(_) => false,
    }
}

fn query_type_matches_record(qtype: crate::QueryType, rtype: crate::RecordType) -> bool {
    match qtype {
        crate::QueryType::ANY => true,
        crate::QueryType::MAILB => matches!(
            rtype,
            crate::RecordType::MB | crate::RecordType::MG | crate::RecordType::MR
        ),
        crate::QueryType::MAILA => {
            matches!(rtype, crate::RecordType::MD | crate::RecordType::MF)
        }
        _ => u16::from(qtype) == u16::from(rtype),
    }
}
