use std::time::Duration;

use dns::{
    DomainName, Headers, Message, OpCode, QClassType, QueryType, Question, RCode, RecordType,
    ResourceRecord,
};

pub(super) struct PackedResponse {
    pub(super) answers: Box<[ResourceRecord]>,
    pub(super) authorities: Box<[ResourceRecord]>,
    pub(super) composed:
        std::sync::OnceLock<std::sync::Mutex<[Option<Box<super::selected::ComposedPositive>>; 2]>>,
}

impl PackedResponse {
    pub(super) fn from_records(
        answers: Vec<ResourceRecord>,
        authorities: Vec<ResourceRecord>,
    ) -> Self {
        Self {
            answers: answers.into_boxed_slice(),
            authorities: authorities.into_boxed_slice(),
            composed: std::sync::OnceLock::new(),
        }
    }

    pub(super) fn to_message(
        &self,
        question: &Question,
        query_headers: &Headers,
        remaining: Duration,
        authenticated: bool,
    ) -> Message {
        let ttl = remaining.as_secs().min(u64::from(u32::MAX)) as u32;
        Message {
            headers: Headers {
                id: query_headers.id,
                qr: true,
                opcode: query_headers.opcode,
                rd: query_headers.rd,
                aa: false,
                tc: false,
                ra: false,
                ad: authenticated,
                cd: query_headers.cd,
                rcode: RCode::Ok,
            },
            questions: vec![question.clone()],
            answers: records_with_ttl(&self.answers, ttl),
            authorities: records_with_ttl(&self.authorities, ttl),
            additionals: Vec::new(),
        }
    }
}

fn records_with_ttl(records: &[ResourceRecord], ttl: u32) -> Vec<ResourceRecord> {
    records
        .iter()
        .cloned()
        .map(|mut record| {
            record.ttl = ttl;
            record
        })
        .collect()
}

fn single_question(message: &Message) -> Option<&Question> {
    match message.questions.as_slice() {
        [question] => Some(question),
        _ => None,
    }
}

pub(super) fn cacheable_question(message: &Message) -> Option<&Question> {
    let question = single_question(message)?;
    (message.headers.opcode == OpCode::Query
        && !message.headers.qr
        && !question.qname.as_ref().iter().any(|label| label == b"*"))
    .then_some(question)
}

pub(super) fn is_cacheable(query: &Message, reply: &Message, question: &Question) -> bool {
    (!requires_authoritative_source(question) || reply.headers.aa)
        && reply.headers.qr
        && reply.headers.rcode == RCode::Ok
        && reply.headers.id == query.headers.id
        && reply.headers.opcode == query.headers.opcode
        && reply.headers.rd == query.headers.rd
        && !reply.headers.tc
        && single_question(reply)
            .is_some_and(|reply_question| same_question(reply_question, question))
}

pub(super) fn requested_answers(
    question: &Question,
    records: &[ResourceRecord],
) -> Option<(Vec<ResourceRecord>, bool)> {
    let cname = cname_at_owner(question, records, &question.qname).ok()?;
    let mut selected = records
        .iter()
        .filter(|record| {
            !record.rtype.is_meta_type()
                && record.name.eq_dns(&question.qname)
                && class_matches(record, question)
                && type_matches(record, question)
        })
        .cloned()
        .collect::<Vec<_>>();

    let covered_types = selected
        .iter()
        .filter(|record| record.rtype != RecordType::RRSIG)
        .map(|record| u16::from(record.rtype))
        .collect::<Vec<_>>();
    selected.extend(
        records
            .iter()
            .filter(|record| {
                !type_matches(record, question)
                    && record.name.eq_dns(&question.qname)
                    && class_matches(record, question)
                    && matches!(&record.rdata, dns::RData::RRSIG(rrsig)
                if covered_types.contains(&rrsig.type_covered))
            })
            .cloned(),
    );

    if selected.is_empty() {
        cname.map(|_| (selected, false))
    } else {
        Some((selected, true))
    }
}

fn cname_at_owner<'a>(
    question: &Question,
    records: &'a [ResourceRecord],
    owner: &DomainName,
) -> Result<Option<&'a ResourceRecord>, ()> {
    let mut cnames = records.iter().filter(|record| {
        record.rtype == RecordType::CNAME
            && record.name.eq_dns(owner)
            && class_matches(record, question)
    });
    let Some(cname) = cnames.next() else {
        return Ok(None);
    };
    if cnames.next().is_some()
        || records.iter().any(|record| {
            record.name.eq_dns(owner)
                && record.class == cname.class
                && record.rtype != RecordType::CNAME
                && !record.rtype.is_cname_companion()
        })
    {
        return Err(());
    }
    Ok(Some(cname))
}

fn class_matches(record: &ResourceRecord, question: &Question) -> bool {
    match question.qclass {
        QClassType::Class(class) => record.class == class,
        QClassType::ANY => true,
        QClassType::Unknown(code) => record.class.value() == code,
    }
}

pub(super) fn requires_authoritative_source(question: &Question) -> bool {
    question.qclass == QClassType::ANY
        || matches!(
            question.qtype,
            QueryType::ANY | QueryType::MAILA | QueryType::MAILB
        )
}

/// Reports whether two QTYPEs overlap under RFC 1035's legacy aggregates.
///
/// ANY overlaps every ordinary owner RR type, MAILA overlaps only MD/MF, and
/// MAILB overlaps only MB/MG/MR. Aggregate pseudo-types do not overlap one
/// another directly; callers reconcile aggregate entries against their stored
/// concrete answer types. Transfer and meta types never acquire ANY behavior.
pub(crate) fn query_types_overlap(left: u16, right: u16) -> bool {
    left == right || aggregate_includes(left, right) || aggregate_includes(right, left)
}

fn aggregate_includes(aggregate: u16, candidate: u16) -> bool {
    match aggregate {
        255 => is_ordinary_record_type(candidate),
        254 => matches!(candidate, 3 | 4),
        253 => matches!(candidate, 7..=9),
        _ => false,
    }
}

fn is_ordinary_record_type(qtype: u16) -> bool {
    !matches!(qtype, 0 | 41 | 249..=255)
}

fn type_matches(record: &ResourceRecord, question: &Question) -> bool {
    match question.qtype {
        QueryType::ANY => true,
        QueryType::MAILA => {
            matches!(record.rtype, RecordType::MD | RecordType::MF)
        }
        QueryType::MAILB => matches!(
            record.rtype,
            RecordType::MB | RecordType::MG | RecordType::MR
        ),
        qtype => u16::from(record.rtype) == u16::from(qtype),
    }
}

fn same_question(left: &Question, right: &Question) -> bool {
    left.qname.eq_dns(&right.qname) && left.qtype == right.qtype && left.qclass == right.qclass
}

pub(super) fn response_ttl(records: &[ResourceRecord]) -> Option<Duration> {
    records
        .iter()
        .filter(|record| !record.rtype.is_meta_type())
        .map(|record| Duration::from_secs(u64::from(record.ttl)))
        .min()
}
