//! Render live negative-cache entries as structured or prepared UDP replies.

use std::time::Instant;

use dns::{Headers, Message, Question, RData, ResourceRecord};

use super::{CachedNegativeUdp, Entry, NegativeCache, PreparedNegative};

const MAX_PREPARED_AUTHORITY_RECORDS: usize = 64;

/// Borrowed authority projection while the negative entry remains locked.
struct NegativeProjection<'a> {
    entry: &'a Entry,
    now: Instant,
}

pub(crate) fn keep_authority(record: &ResourceRecord, authenticated: bool) -> bool {
    !authenticated
        || !(record.rtype == dns::RecordType::NS
            || matches!(&record.rdata,
        RData::RRSIG(sig) if record.rtype == dns::RecordType::RRSIG && sig.type_covered == u16::from(dns::RecordType::NS)))
}

impl NegativeProjection<'_> {
    pub(crate) fn authorities(&self) -> impl Iterator<Item = (&ResourceRecord, u32)> {
        self.entry.authorities.iter().filter_map(|cached| {
            let expires_at = cached.expires_at.min(self.entry.expires_at);
            (expires_at > self.now && keep_authority(&cached.record, self.entry.authenticated))
                .then(|| {
                    (
                        &cached.record,
                        expires_at
                            .saturating_duration_since(self.now)
                            .as_secs()
                            .min(u64::from(u32::MAX)) as u32,
                    )
                })
        })
    }
}

impl NegativeCache {
    pub(crate) fn get_udp(
        &self,
        request: &Message,
        maximum: usize,
        validating: bool,
    ) -> Option<CachedNegativeUdp> {
        let question = request.questions.first()?;
        self.with_entry(question, |entry, now| {
            let mut projection_now = now;
            let dnssec_ok = matches!(request.additionals.as_slice(),
                [opt] if opt.rtype == dns::RecordType::OPT && opt.ttl & 0x8000 != 0);
            // Explicit DNSSEC queries must not initialize the common filtered
            // NXDOMAIN variant: that entry is shared across question types.
            let explicit_dnssec = matches!(question.qtype.value(), 46 | 47 | 50);
            // Two finite immutable encodings per existing bounded cache entry.
            // Expired optional records, unusual shapes and larger packets keep
            // the ordinary projection, with no repeated lookup or popularity touch.
            if (dnssec_ok || !explicit_dnssec)
                && entry.authorities.len() <= MAX_PREPARED_AUTHORITY_RECORDS
                && entry
                    .authorities
                    .iter()
                    .all(|record| record.expires_at.min(entry.expires_at) > now)
            {
                let prepared = entry.prepared[usize::from(dnssec_ok)]
                    .get_or_init(|| PreparedNegative::from_entry(entry, question, dnssec_ok, now));
                projection_now = Instant::now();
                let now = projection_now;
                if entry.expires_at <= now {
                    return None;
                }
                if let Some(prepared) = prepared
                    && entry
                        .authorities
                        .iter()
                        .all(|record| record.expires_at.min(entry.expires_at) > now)
                {
                    let mut ttls = [0; MAX_PREPARED_AUTHORITY_RECORDS];
                    for (ttl, &index) in ttls.iter_mut().zip(&prepared.indices) {
                        let record = &entry.authorities[index];
                        *ttl = record
                            .expires_at
                            .min(entry.expires_at)
                            .saturating_duration_since(now)
                            .as_secs()
                            .min(u64::from(u32::MAX)) as u32;
                    }
                    if let Some(reply) = prepared.reply.render(
                        request,
                        &ttls[..prepared.indices.len()],
                        maximum,
                        validating,
                    ) {
                        return Some(CachedNegativeUdp::Encoded {
                            reply,
                            implicit_referral: !entry.authenticated
                                && !entry
                                    .authorities
                                    .iter()
                                    .any(|record| record.record.rtype == dns::RecordType::NS),
                        });
                    }
                }
            }
            Some(CachedNegativeUdp::Message(Self::materialize(
                entry,
                question,
                projection_now,
            )))
        })
        .flatten()
    }

    pub(super) fn materialize(entry: &Entry, question: &Question, now: Instant) -> Message {
        let projection = NegativeProjection { entry, now };
        let authorities = projection
            .authorities()
            .map(|(record, ttl)| {
                let mut record = record.clone();
                record.ttl = ttl;
                record
            })
            .collect();
        Message {
            headers: Headers {
                qr: true,
                ad: entry.authenticated,
                rcode: entry.rcode,
                ..Headers::default()
            },
            questions: vec![question.clone()],
            answers: Vec::new(),
            authorities,
            additionals: Vec::new(),
        }
    }
}

impl PreparedNegative {
    fn from_entry(
        entry: &Entry,
        question: &Question,
        dnssec_ok: bool,
        now: Instant,
    ) -> Option<Box<Self>> {
        let indices: Box<[usize]> = entry
            .authorities
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                (keep_authority(&record.record, entry.authenticated)
                    && crate::response::requested_dnssec_record(
                        record.record.rtype,
                        Some(question.qtype.value()),
                        dnssec_ok,
                    ))
                .then_some(index)
            })
            .collect();
        let prototype = Message {
            headers: Headers {
                qr: true,
                ra: true,
                rd: true,
                ad: entry.authenticated,
                rcode: entry.rcode,
                ..Headers::default()
            },
            questions: vec![question.clone()],
            answers: Vec::new(),
            authorities: indices
                .iter()
                .map(|&index| {
                    let record = &entry.authorities[index];
                    let mut value = record.record.clone();
                    value.ttl = record
                        .expires_at
                        .min(entry.expires_at)
                        .saturating_duration_since(now)
                        .as_secs()
                        .min(u64::from(u32::MAX)) as u32;
                    value
                })
                .collect(),
            additionals: vec![
                dns::Edns {
                    dnssec_ok,
                    ..dns::Edns::default()
                }
                .into_record(),
            ],
        };
        dns::wire::PreparedNegativeReply::from_message(&prototype)
            .ok()
            .flatten()
            .map(|reply| Box::new(PreparedNegative { reply, indices }))
    }
}
