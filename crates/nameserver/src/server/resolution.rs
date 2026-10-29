use std::{borrow::Cow, collections::HashSet};

use dns::{Message, QClassType, Question, RCode};
use tracing::instrument;

use crate::{
    name::{dns_name_key, dns_name_key_into},
    response::{annotate_extended_error, base_response},
    zone::{InitialLookup, Lookup, response::contains_record},
};

use super::{
    additional::{
        additional_address_records, append_additionals, referral_additional_address_records,
    },
    zone_index::{
        ZoneIndex, authoritative_zone, authoritative_zone_key, closest_zones_by_class,
        qclass_for_class,
    },
};

#[instrument(
    level = "debug",
    skip(zones, query),
    fields(transaction_id = query.headers.id, zone_count = zones.len)
)]
pub(super) fn resolve(zones: &ZoneIndex, query: &Message) -> Message {
    if matches!(query.questions[0].qclass, QClassType::ANY) {
        return resolve_any_class(zones, query);
    }
    resolve_concrete_class(zones, query)
}

/// Uses the same initial lookup for borrowed negatives and structured fallback.
/// Prepared NODATA bytes are reused only after the current zone selects NODATA.
pub(super) fn resolve_udp(
    zones: &ZoneIndex,
    query: &Message,
    maximum: usize,
) -> transport::ImmediateUdpResponse {
    use transport::ImmediateUdpResponse;
    let question = &query.questions[0];
    if question.qclass == QClassType::ANY {
        return ImmediateUdpResponse::Message(resolve_any_class(zones, query));
    }
    let mut key_storage = [0; 255];
    let key = dns_name_key_into(&question.qname, &mut key_storage);
    let Some(zone) = authoritative_zone_key(zones, question, key) else {
        return ImmediateUdpResponse::Message(resolve_concrete_class(zones, query));
    };
    let lookup = match zone.lookup_initial_key(question, key) {
        InitialLookup::Positive(selection) => {
            if let Some(reply) = super::positive::resolve_positive(zone, query, &selection, maximum)
            {
                return reply;
            }
            Lookup::Answer(selection.into_owned())
        }
        InitialLookup::Final(lookup) => lookup,
    };
    let negative = match &lookup {
        Lookup::NameError => Some((&question.qname, true)),
        Lookup::NoData { proof_owner } => Some((proof_owner, false)),
        _ => None,
    };
    if let Some((owner, name_error)) = negative {
        let dnssec_ok = query
            .edns()
            .ok()
            .flatten()
            .is_some_and(|edns| edns.dnssec_ok);
        // This is metadata on an existing node, not another DNS lookup. The
        // selected NODATA result and immutable zone snapshot remain authoritative.
        let nodata_cache = (!name_error && owner.eq_dns(&question.qname))
            .then(|| zone.nodata_cache(owner))
            .flatten();
        if let Some(encoded) =
            nodata_cache.and_then(|cache| cache.render(query, dnssec_ok, maximum))
        {
            return ImmediateUdpResponse::Encoded(encoded);
        }
        if let Some(authorities) =
            zone.negative_authority_refs(owner, &question.qname, name_error, dnssec_ok)
        {
            if let Ok(Some(encoded)) = dns::wire::EncodedReply::authoritative_negative(
                query,
                &authorities,
                name_error,
                maximum,
            ) {
                // Count/precompute only shapes the normal checked writer already
                // accepts. Include the normalized OPT before spending a slot.
                let opt_extra = if query.additionals.is_empty() { 11 } else { 0 };
                if encoded.as_bytes().len().saturating_add(opt_extra) <= 1232
                    && let Some(cache) = nodata_cache
                {
                    zone.prepare_nodata(cache, query, dnssec_ok, &authorities);
                }
                return ImmediateUdpResponse::Encoded(encoded);
            }
            // Preserve this exact selected/deduplicated response on encoding
            // fallback, including normal validation errors and truncation.
            let mut reply = base_response(query);
            reply.headers.aa = true;
            reply.headers.rcode = if name_error {
                RCode::NameError
            } else {
                RCode::Ok
            };
            reply.authorities = authorities.into_iter().cloned().collect();
            return ImmediateUdpResponse::Message(reply);
        }
    }
    ImmediateUdpResponse::Message(resolve_concrete_class_initial(
        zones,
        query,
        Some((zone, lookup)),
    ))
}

fn resolve_any_class(zones: &ZoneIndex, query: &Message) -> Message {
    let applicable_zones = closest_zones_by_class(zones, &query.questions[0].qname);
    if applicable_zones.is_empty() {
        let mut reply = base_response(query);
        reply.headers.rcode = RCode::Refused;
        annotate_extended_error(&mut reply, dns::ExtendedDnsErrorCode::NotAuthoritative);
        return reply;
    }

    let responses = applicable_zones
        .iter()
        .map(|zone| {
            let mut class_query = query.clone();
            class_query.questions[0].qclass = qclass_for_class(zone.class);
            resolve_concrete_class(zones, &class_query)
        })
        .collect::<Vec<_>>();

    let mut reply = base_response(query);
    // QCLASS=ANY can combine data from several independently authoritative
    // classes, so it must not claim authority for classes the server does not
    // host. Incomplete per-class CNAME or referral results also keep AA clear.
    reply.headers.aa = false;
    reply.headers.rcode = responses
        .iter()
        .find_map(|response| {
            (!matches!(response.headers.rcode, RCode::Ok | RCode::NameError))
                .then_some(response.headers.rcode)
        })
        // Without an all-class completeness guarantee, an aggregate response
        // cannot authoritatively assert that the name does not exist.
        .unwrap_or(RCode::Ok);
    if reply.headers.rcode != RCode::Ok {
        if reply.headers.rcode == RCode::YXDomain {
            // Preserve the DNAME (and any covering signature) that proves
            // which class overflowed during substitution.
            for response in responses
                .iter()
                .filter(|r| r.headers.rcode == RCode::YXDomain)
            {
                for record in &response.answers {
                    if !contains_record(&reply.answers, record) {
                        reply.answers.push(record.clone());
                    }
                }
            }
        }
        return reply;
    }

    let has_positive_answer = responses
        .iter()
        .any(|response| response.headers.rcode == RCode::Ok && !response.answers.is_empty());
    let has_referral = responses.iter().any(|response| {
        response.headers.rcode == RCode::Ok
            && response.answers.is_empty()
            && response
                .authorities
                .iter()
                .any(|record| record.rtype == dns::RecordType::NS)
    });
    let mut additionals = Vec::new();
    for response in responses {
        for record in response.answers {
            if !contains_record(&reply.answers, &record) {
                reply.answers.push(record);
            }
        }
        for record in response.authorities {
            if record.rtype == dns::RecordType::SOA && (has_positive_answer || has_referral) {
                continue;
            }
            if !contains_record(&reply.authorities, &record) {
                reply.authorities.push(record);
            }
        }
        additionals.extend(
            response
                .additionals
                .into_iter()
                .filter(|record| record.rtype != dns::RecordType::OPT),
        );
    }
    append_additionals(&mut reply, additionals);
    reply
}

fn resolve_concrete_class(zones: &ZoneIndex, query: &Message) -> Message {
    resolve_concrete_class_initial(zones, query, None)
}

fn resolve_concrete_class_initial(
    zones: &ZoneIndex,
    query: &Message,
    mut initial: Option<(&crate::zone::Zone, Lookup)>,
) -> Message {
    let original_question = &query.questions[0];
    let dnssec_ok = query
        .edns()
        .ok()
        .flatten()
        .is_some_and(|edns| edns.dnssec_ok);
    let mut reply = base_response(query);
    let mut question = Cow::Borrowed(original_question);
    let mut seen_names = HashSet::new();

    loop {
        let (zone, lookup) = if let Some(initial) = initial.take() {
            initial
        } else {
            let Some(zone) = authoritative_zone(zones, &question) else {
                // An authoritative CNAME is complete outside hosted authority.
                if !reply.answers.is_empty() {
                    return reply;
                }
                reply.headers.rcode = RCode::Refused;
                annotate_extended_error(&mut reply, dns::ExtendedDnsErrorCode::NotAuthoritative);
                return reply;
            };
            (zone, zone.lookup(&question))
        };

        match lookup {
            Lookup::Answer(mut records) => {
                reply.headers.aa = true;
                if dnssec_ok {
                    zone.append_rrsigs_for(&mut records);
                    zone.append_wildcard_denial(&records, &mut reply.authorities);
                }
                reply.answers.extend(records);
                let additionals = additional_address_records(zones, &reply.answers);
                append_additionals(&mut reply, additionals);
                return reply;
            }
            Lookup::Cname {
                mut records,
                target,
            } => {
                reply.headers.aa = true;
                if dnssec_ok {
                    zone.append_rrsigs_for(&mut records);
                    zone.append_wildcard_denial(&records, &mut reply.authorities);
                }
                reply.answers.extend(records);
                if seen_names.is_empty() {
                    seen_names.insert(dns_name_key(&original_question.qname));
                }
                if !seen_names.insert(dns_name_key(&target)) {
                    return server_failure(reply);
                }
                question = Cow::Owned(Question {
                    qname: target,
                    qtype: original_question.qtype,
                    qclass: original_question.qclass,
                });
            }
            Lookup::Dname { record, target } => {
                reply.headers.aa = true;
                let mut records = vec![record.clone()];
                if dnssec_ok {
                    zone.append_rrsigs_for(&mut records);
                }
                reply.answers.extend(records);
                let Some(target) = target else {
                    reply.headers.rcode = RCode::YXDomain;
                    return reply;
                };
                reply.answers.push(dns::ResourceRecord {
                    name: question.qname.clone(),
                    rtype: dns::RecordType::CNAME,
                    class: record.class,
                    ttl: record.ttl,
                    rdata: dns::RData::CNAME(target.clone()),
                });
                // The synthesized CNAME answers CNAME/ANY at the original owner.
                // Do not restart ANY at its target (BIND auth/tests.sh; RFC 6672 §3.2).
                if matches!(
                    original_question.qtype,
                    dns::QueryType::CNAME | dns::QueryType::ANY
                ) {
                    return reply;
                }
                if seen_names.is_empty() {
                    seen_names.insert(dns_name_key(&original_question.qname));
                }
                if !seen_names.insert(dns_name_key(&target)) {
                    return server_failure(reply);
                }
                question = Cow::Owned(Question {
                    qname: target,
                    qtype: original_question.qtype,
                    qclass: original_question.qclass,
                });
            }
            Lookup::Referral(mut records) => {
                if dnssec_ok {
                    zone.append_referral_dnssec(&mut records);
                }
                append_authorities(&mut reply, records);
                let additionals =
                    referral_additional_address_records(zones, zone, &reply.authorities);
                append_additionals(&mut reply, additionals);
                return reply;
            }
            Lookup::NameError => {
                reply.headers.aa = true;
                reply.headers.rcode = RCode::NameError;
                append_authorities(
                    &mut reply,
                    zone.negative_response_authorities(
                        &question.qname,
                        &question.qname,
                        true,
                        dnssec_ok,
                    ),
                );
                return reply;
            }
            Lookup::NoData { proof_owner } => {
                reply.headers.aa = true;
                append_authorities(
                    &mut reply,
                    zone.negative_response_authorities(
                        &proof_owner,
                        &question.qname,
                        false,
                        dnssec_ok,
                    ),
                );
                return reply;
            }
        }
    }
}

fn append_authorities(reply: &mut Message, mut records: Vec<dns::ResourceRecord>) {
    if reply.authorities.is_empty() {
        let mut retained = 0;
        for index in 0..records.len() {
            if !contains_record(&records[..retained], &records[index]) {
                records.swap(retained, index);
                retained += 1;
            }
        }
        records.truncate(retained);
        reply.authorities = records;
        return;
    }
    // Earlier wildcard CNAME hops need their denial proofs even when the
    // terminal lookup contributes a negative answer or delegation.
    for record in records {
        if !contains_record(&reply.authorities, &record) {
            reply.authorities.push(record);
        }
    }
}

fn server_failure(mut reply: Message) -> Message {
    reply.headers.rcode = RCode::ServerFailure;
    reply.headers.aa = false;
    reply.answers.clear();
    reply.authorities.clear();
    reply
        .additionals
        .retain(|record| record.rtype == dns::RecordType::OPT);
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::{ClassType, DomainName, RData, RecordType, ResourceRecord};

    #[test]
    fn authority_dedup_retains_first_ttl_and_order_across_hops() {
        let record = |octet, ttl| ResourceRecord {
            name: DomainName::from_labels(vec![b"example".to_vec()]).unwrap(),
            rtype: RecordType::A,
            class: ClassType::IN,
            ttl,
            rdata: RData::A([192, 0, 2, octet].into()),
        };
        for previous in [vec![], vec![record(3, 17), record(1, 19)]] {
            let incoming = vec![
                record(1, 23),
                record(2, 29),
                record(1, 31),
                record(3, 37),
                record(2, 41),
                record(4, 43),
            ];
            let mut expected = previous.clone();
            for record in &incoming {
                if !contains_record(&expected, record) {
                    expected.push(record.clone());
                }
            }
            let mut reply = Message::builder().build().unwrap();
            reply.authorities = previous;
            append_authorities(&mut reply, incoming);
            assert_eq!(reply.authorities.len(), expected.len());
            for (actual, expected) in reply.authorities.iter().zip(&expected) {
                assert!(actual.eq_dns(expected));
                assert_eq!(actual.ttl, expected.ttl);
            }
        }
    }
}
