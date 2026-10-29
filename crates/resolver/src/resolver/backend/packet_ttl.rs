//! Keep received packet TTLs from being renewed during remote cache I/O.
use std::time::{Duration, Instant};

use dns::{Message, RecordType};

pub(in crate::resolver) fn age(response: &mut Message, observed_at: Instant, now: Instant) {
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
    {
        // OPT encodes flags in its TTL word; TSIG reserves that field as zero.
        if matches!(record.rtype, RecordType::OPT | RecordType::TSIG) {
            continue;
        }
        let expires = observed_at
            .checked_add(Duration::from_secs(u64::from(record.ttl)))
            .unwrap_or(observed_at);
        record.ttl = expires
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, DomainName, RData, ResourceRecord};

    #[test]
    fn preserves_edns_flags_while_aging_data() {
        let at = Instant::now();
        let mut response = Message::builder().build().unwrap();
        response.answers.push(ResourceRecord {
            name: DomainName::from_dotted("example.").unwrap(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl: 5,
            rdata: RData::A([192, 0, 2, 1].into()),
        });
        response.additionals.push(ResourceRecord {
            name: DomainName::root(),
            rtype: RecordType::OPT,
            class: ClassType::Unknown(1232),
            ttl: 0x0100_8000,
            rdata: RData::OPT(vec![]),
        });
        age(&mut response, at, at + Duration::from_millis(2200));
        assert_eq!(response.answers[0].ttl, 2);
        assert_eq!(response.additionals[0].ttl, 0x0100_8000);
    }
}
