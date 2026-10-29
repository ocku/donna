mod indexed;

// Small sections avoid allocating an index; larger ones bound comparison work.
const LINEAR_SECTION_LIMIT: usize = 32;
const LINEAR_RANK_LIMIT: usize = 8;

use dns::{Message, QClassType, Question, RCode, RData, RecordType, ResourceRecord};

use super::classification::{
    has_ns_for_question_class, has_requested_answer, has_soa_for_question,
};

/// Applies RFC 2181's inbound TTL rules. A malformed RRSet from a
/// non-authoritative source is ignored; authoritative RRSets are normalized to
/// their lowest TTL before either returning or caching the response.
pub(crate) fn normalize_response_rrsets(reply: &mut Message, question: &Question) -> bool {
    for record in reply
        .answers
        .iter_mut()
        .chain(&mut reply.authorities)
        .chain(&mut reply.additionals)
    {
        // RFC 6891 §6.1.3 assigns OPT's TTL-sized word to extended RCODE,
        // version and flags. RFC 2181's TTL high-bit rule does not apply to it.
        // TSIG's reserved TTL must remain zero on the wire (RFC 8945 §4.2);
        // do not turn a malformed value into a valid one before validation.
        if !matches!(record.rtype, RecordType::OPT | RecordType::TSIG)
            && record.ttl & 0x8000_0000 != 0
        {
            record.ttl = 0;
        }
        // Received CAA and EDNS flag bits are future-extension space. They
        // must be ignored semantically, but retained byte-for-byte so cached
        // or forwarded signed data is not rewritten.
        if record.validate_received().is_err() {
            return false;
        }
    }

    // RFC 2181 §5.4.1 ranks Answer above Authority and both above
    // Additional. Keep only the highest-ranked occurrence of an RRSet rather
    // than merging TTLs or data across trust boundaries.
    remove_lower_ranked(&reply.answers, &mut reply.authorities);
    remove_lower_ranked(&reply.answers, &mut reply.additionals);
    remove_lower_ranked(&reply.authorities, &mut reply.additionals);

    let authoritative = reply.headers.aa;
    let removed_answers = normalize_section(&mut reply.answers, |record| {
        authoritative && record.name.eq_dns(&question.qname)
    });
    let removed_authorities = normalize_section(&mut reply.authorities, |record| {
        authoritative && question.qname.is_descendant_of(&record.name)
    });

    // Additional data is never authoritative merely because AA describes the
    // answer. A malformed optional RRSet can be ignored without discarding an
    // otherwise usable response.
    normalize_section(&mut reply.additionals, |_| false);

    deduplicate_section(&mut reply.answers);
    deduplicate_section(&mut reply.authorities);
    deduplicate_section(&mut reply.additionals);

    if !removed_answers && !removed_authorities {
        return true;
    }
    if has_requested_answer(&reply.answers, question)
        || reply.answers.iter().any(|record| {
            record.name.eq_dns(&question.qname)
                && matches!(record.rdata, RData::CNAME(_))
                && matches!(question.qclass, QClassType::Class(class) if record.class == class)
        })
    {
        return true;
    }
    match reply.headers.rcode {
        RCode::NameError => !removed_answers,
        RCode::Ok => {
            has_soa_for_question(reply, question) || has_ns_for_question_class(reply, question)
        }
        _ => true,
    }
}

fn same_record(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    left.name.eq_dns(&right.name)
        && left.rtype == right.rtype
        && left.class == right.class
        && left.rdata == right.rdata
}

fn same_rrset(left: &ResourceRecord, right: &ResourceRecord) -> bool {
    left.name.eq_dns(&right.name)
        && left.rtype == right.rtype
        && left.class == right.class
        && (left.rtype != RecordType::RRSIG || left.rdata == right.rdata)
}

fn deduplicate_section(records: &mut Vec<ResourceRecord>) {
    if records.len() > LINEAR_SECTION_LIMIT {
        indexed::deduplicate_section(records);
        return;
    }
    let mut unique = Vec::with_capacity(records.len());
    for record in records.drain(..) {
        if !unique.iter().any(|previous| same_record(previous, &record)) {
            unique.push(record);
        }
    }
    *records = unique;
}

fn remove_lower_ranked(higher: &[ResourceRecord], lower: &mut Vec<ResourceRecord>) {
    // A bounded side keeps the linear path cheap while limiting comparisons
    // to a constant multiple of the other section's size.
    if higher.len().min(lower.len()) <= LINEAR_RANK_LIMIT {
        lower.retain(|selected| !higher.iter().any(|record| same_rrset(record, selected)));
    } else {
        indexed::remove_lower_ranked(higher, lower);
    }
}

/// Normalizes authoritative mixed-TTL RRSets and removes non-authoritative
/// mixed-TTL RRSets. Returns whether any RRSet was removed.
fn normalize_section(
    records: &mut Vec<ResourceRecord>,
    is_authoritative: impl Fn(&ResourceRecord) -> bool,
) -> bool {
    if records.len() > LINEAR_SECTION_LIMIT {
        return indexed::normalize_section(records, is_authoritative);
    }
    let malformed = records
        .iter()
        .filter(|selected| {
            // RFC 4035 §2.2: RRSIG records do not form an RRset, so signatures
            // at one owner may legitimately carry different TTLs. OPT carries
            // control metadata rather than a TTL (RFC 6891 §6.1.3).
            !matches!(selected.rtype, RecordType::OPT | RecordType::RRSIG)
                && records
                    .iter()
                    .filter(|candidate| same_rrset(candidate, selected))
                    .any(|candidate| candidate.ttl != selected.ttl)
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut removed = Vec::new();
    for selected in malformed {
        if is_authoritative(&selected) {
            let minimum = records
                .iter()
                .filter(|candidate| same_rrset(candidate, &selected))
                .map(|candidate| candidate.ttl)
                .min()
                .expect("the selected RRSet is present");
            for candidate in records
                .iter_mut()
                .filter(|candidate| same_rrset(candidate, &selected))
            {
                candidate.ttl = minimum;
            }
        } else if !removed
            .iter()
            .any(|candidate| same_rrset(candidate, &selected))
        {
            removed.push(selected);
        }
    }
    records.retain(|record| !removed.iter().any(|selected| same_rrset(record, selected)));
    !removed.is_empty()
}

#[cfg(test)]
mod tests;
