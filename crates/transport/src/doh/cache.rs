use http::header;

use dns::Message;

pub(super) fn apply_age(message: &mut Message, age: u32) {
    if let Some(negative_ttl) = message.negative_cache_ttl() {
        // Age applies to the effective RFC 2308 lifetime, not just the SOA
        // RR's TTL. For TTL=600, MINIMUM=60, and Age=12, min(588, 60)
        // would incorrectly allow another 60 seconds of negative caching.
        // Lowering the RR TTL preserves SOA RDATA and DNSSEC signatures.
        for record in &mut message.authorities {
            if record.rtype == dns::RecordType::SOA {
                record.ttl = record.ttl.min(negative_ttl);
            }
        }
    }
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        if record.rtype != dns::RecordType::OPT {
            record.ttl = record.ttl.saturating_sub(age);
        }
    }
}

pub(super) fn parse_age(value: &header::HeaderValue) -> Option<u32> {
    let first = value
        .as_bytes()
        .split(|byte| *byte == b',')
        .next()
        .unwrap_or_default();
    let start = first
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))?;
    let end = first
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|end| end + 1)?;
    let first = &first[start..end];
    if first.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }

    Some(first.iter().fold(0, |age: u32, byte| {
        age.saturating_mul(10)
            .saturating_add(u32::from(*byte - b'0'))
    }))
}

pub(super) fn freshness_lifetime(message: &Message) -> u32 {
    let answer_ttl = message.answers.iter().map(|record| record.ttl).min();
    let negative_ttl = message.negative_cache_ttl();

    match (answer_ttl, negative_ttl) {
        (Some(answer), Some(negative)) => answer.min(negative),
        (Some(answer), None) => answer,
        (None, Some(negative)) => negative,
        (None, None) => 0,
    }
}
