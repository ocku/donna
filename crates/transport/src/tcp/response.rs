use super::*;

#[cfg(test)]
#[instrument(level = "debug", skip(handler, packet), fields(packet_length = packet.len()))]
pub(super) async fn responses_for<H>(
    handler: &H,
    peer: SocketAddr,
    packet: &[u8],
) -> Option<Vec<Vec<u8>>>
where
    H: DnsRequestHandler,
{
    responses_for_with_timeout(handler, peer, packet, HANDLER_REPLY_TIMEOUT).await
}

#[cfg(test)]
async fn responses_for_with_timeout<H>(
    handler: &H,
    peer: SocketAddr,
    packet: &[u8],
    handler_reply_timeout: Duration,
) -> Option<Vec<Vec<u8>>>
where
    H: DnsRequestHandler,
{
    match Message::from_wire(packet) {
        Ok(query) if query.headers.qr => None,
        Ok(query) => {
            let request_headers = query.headers.clone();
            let request_questions = query.questions.clone();
            let is_axfr = is_axfr_request(&query);
            let is_ixfr = is_ixfr_request(&query);
            let request_message = query.clone();
            let (request, response) =
                DnsRequest::channel_with_wire(query, packet.to_vec(), peer, TransportProtocol::Tcp);
            let responses = match time::timeout(handler_reply_timeout, async {
                handler.handle(request).await;
                response.await
            })
            .await
            {
                Ok(Ok(DnsResponse::Buffered(responses))) => responses.into_vec(),
                Ok(Ok(DnsResponse::Stream(_))) | Ok(Err(_)) => return None,
                Err(_) => {
                    tracing::debug!(%peer, "TCP request handler timed out");
                    return None;
                }
            };
            if is_axfr {
                prepare_axfr_responses(
                    responses,
                    &request_headers,
                    &request_questions,
                    MAX_AXFR_VALIDATION_RRSETS,
                    None,
                )
            } else if is_ixfr {
                prepare_ixfr_response(
                    responses,
                    &request_headers,
                    request_questions,
                    &request_message,
                    None,
                )
            } else {
                prepare_standard_response(responses, &request_headers, request_questions)
            }
        }
        Err(_) => format_error_response(packet).map(|response| vec![response]),
    }
}

pub(super) fn is_axfr_request(query: &Message) -> bool {
    matches!(
        query.questions.as_slice(),
        [question] if question.qtype == dns::QueryType::AXFR
    )
}

pub(super) fn is_ixfr_request(query: &Message) -> bool {
    matches!(
        query.questions.as_slice(),
        [question] if question.qtype == dns::QueryType::IXFR
    )
}

/// Applies the server-owned fields for a normal one-request/one-response
/// exchange, then enforces the TCP frame ceiling.
#[cfg(test)]
fn prepare_standard_response(
    responses: Vec<Message>,
    request_headers: &dns::Headers,
    request_questions: Vec<dns::Question>,
) -> Option<Vec<Vec<u8>>> {
    prepare_standard_response_for(responses, request_headers, request_questions, None)
}

pub(crate) fn prepare_standard_response_for(
    mut responses: Vec<Message>,
    request_headers: &dns::Headers,
    request_questions: Vec<dns::Question>,
    request: Option<(&Message, TransportProtocol)>,
) -> Option<Vec<Vec<u8>>> {
    let [response] = responses.as_mut_slice() else {
        // Only AXFR has multi-message response semantics. Treat zero or many
        // ordinary responses as an invalid handler result.
        return None;
    };
    if has_tsig(response) {
        if !authenticated_response_headers_match(request_headers, response)
            || (request_headers.opcode == dns::OpCode::Query
                && !same_questions(&response.questions, &request_questions))
        {
            return None;
        }
        let wire = responses.pop()?.into_wire().ok()?;
        return (wire.len() <= MAX_TCP_MESSAGE_OCTETS).then_some(vec![wire]);
    }
    normalize_response_headers(request_headers, response);
    if request_headers.opcode == dns::OpCode::Query {
        if request_questions_are_safe_to_echo(&request_questions) {
            response.questions = request_questions;
        } else {
            response.questions.clear();
        }
    }
    prepare_response_padding(response, request)?;
    truncate_response(responses.pop()?, MAX_TCP_MESSAGE_OCTETS)
        .ok()
        .map(|response| vec![response])
}

pub(crate) fn prepare_ixfr_response(
    mut responses: Vec<Message>,
    request_headers: &dns::Headers,
    request_questions: Vec<dns::Question>,
    request: &Message,
    protocol: Option<TransportProtocol>,
) -> Option<Vec<Vec<u8>>> {
    let [response] = responses.as_mut_slice() else {
        return None;
    };
    // RFC 1995 permits a newer single SOA as a UDP retry signal only. A
    // stream response must carry the transfer when the client is behind.
    if response.extended_rcode() == 0
        && response.answers.len() == 1
        && !request
            .authorities
            .first()
            .and_then(soa_serial)
            .zip(soa_serial(&response.answers[0]))
            .is_some_and(|(requested, current)| ixfr::single_soa_completes_ixfr(requested, current))
    {
        return None;
    }
    if has_tsig(response) {
        if !authenticated_response_headers_match(request_headers, response)
            || !same_questions(&response.questions, &request_questions)
            || !valid_ixfr_response(response, request)
        {
            return None;
        }
        return response
            .clone()
            .into_wire()
            .ok()
            .filter(|wire| wire.len() <= MAX_TCP_MESSAGE_OCTETS)
            .map(|wire| vec![wire]);
    }
    normalize_response_headers(request_headers, response);
    if request_questions_are_safe_to_echo(&request_questions) {
        response.questions = request_questions;
    } else {
        response.questions.clear();
    }
    prepare_response_padding(response, protocol.map(|protocol| (request, protocol)))?;
    if !valid_ixfr_response(response, request) {
        return None;
    }
    responses
        .pop()?
        .into_wire()
        .ok()
        .filter(|wire| wire.len() <= MAX_TCP_MESSAGE_OCTETS)
        .map(|wire| vec![wire])
}

pub(crate) fn valid_ixfr_response(response: &Message, request: &Message) -> bool {
    if response.extended_rcode() != 0 {
        return response.answers.is_empty() && response.authorities.is_empty();
    }
    let Some(question) = request.questions.first() else {
        return false;
    };
    if !response.headers.aa
        || response.headers.tc
        || !response.authorities.is_empty()
        || response.answers.is_empty()
        || response
            .answers
            .iter()
            .any(|record| axfr::validate_transfer_record(record, question).is_err())
    {
        return false;
    }
    let current = &response.answers[0];
    if !is_apex_soa(current, question) {
        return false;
    }
    if response.answers.len() == 1 {
        return true;
    }
    let last = response.answers.last().expect("checked nonempty");
    if !axfr::same_resource_record(current, last) {
        return false;
    }
    if !is_apex_soa(&response.answers[1], question) {
        return response.answers[1..response.answers.len() - 1]
            .iter()
            .all(|record| !is_apex_soa(record, question));
    }

    let Some(mut expected_old) = request.authorities.first().and_then(soa_serial) else {
        return false;
    };
    let Some(current_serial) = soa_serial(current) else {
        return false;
    };
    let mut index = 1;
    let final_index = response.answers.len() - 1;
    while index < final_index {
        let old = &response.answers[index];
        if !is_apex_soa(old, question) || soa_serial(old) != Some(expected_old) {
            return false;
        }
        index += 1;
        while index < final_index && !is_apex_soa(&response.answers[index], question) {
            index += 1;
        }
        if index >= final_index {
            return false;
        }
        let Some(new_serial) = soa_serial(&response.answers[index]) else {
            return false;
        };
        if dns::SerialNumber::new(expected_old).compare(dns::SerialNumber::new(new_serial))
            != Some(std::cmp::Ordering::Less)
        {
            return false;
        }
        expected_old = new_serial;
        index += 1;
        while index < final_index && !is_apex_soa(&response.answers[index], question) {
            index += 1;
        }
    }
    expected_old == current_serial
}

fn is_apex_soa(record: &dns::ResourceRecord, question: &dns::Question) -> bool {
    record.rtype == dns::RecordType::SOA && record.name.eq_dns(&question.qname)
}

fn soa_serial(record: &dns::ResourceRecord) -> Option<u32> {
    match record.rdata {
        dns::RData::SOA { serial, .. } => Some(serial),
        _ => None,
    }
}

/// Normalizes fields whose AXFR values are fixed by RFC 5936, validates the
/// complete series, and only then returns serialized frames to the caller.
pub(crate) fn prepare_axfr_responses(
    responses: Vec<Message>,
    request_headers: &dns::Headers,
    request_questions: &[dns::Question],
    max_axfr_validation_rrsets: usize,
    request: Option<(&Message, TransportProtocol)>,
) -> Option<Vec<Vec<u8>>> {
    let question = request_questions.first()?.clone();
    let request_questions_are_safe_to_echo = request_questions_are_safe_to_echo(request_questions);
    let mut validator = AxfrSeriesValidator::new(
        question,
        request_questions_are_safe_to_echo,
        max_axfr_validation_rrsets,
    );
    let frames = responses
        .into_iter()
        .map(|response| {
            prepare_axfr_response(
                response,
                request_headers,
                request_questions,
                &mut validator,
                request,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    validator.finish().then_some(frames)
}

pub(crate) fn prepare_axfr_response(
    mut response: Message,
    request_headers: &dns::Headers,
    request_questions: &[dns::Question],
    validator: &mut AxfrSeriesValidator,
    request: Option<(&Message, TransportProtocol)>,
) -> Option<Vec<u8>> {
    if has_tsig(&response) {
        if !authenticated_response_headers_match(request_headers, &response) {
            return None;
        }
        validator.accept(&response)?;
        return response.into_wire().ok();
    }
    normalize_response_headers(request_headers, &mut response);

    // RFC 5936 §2.2.1 fixes these header values for AXFR. AA is required on
    // successful messages; an error response retains the handler's AA.
    response.headers.tc = false;
    response.headers.ra = false;
    response.headers.ad = false;
    response.headers.cd = false;
    if response.extended_rcode() == 0 {
        response.headers.aa = true;
    }

    // Preserve Phase 2's atomic question handling. Only canonical requests may
    // have their question restored; a noncanonical immediate terminal error is
    // validated with an empty question section.
    let request_questions_are_safe_to_echo = request_questions_are_safe_to_echo(request_questions);
    if !request_questions_are_safe_to_echo {
        response.questions.clear();
    } else if validator.is_first_message() || response.extended_rcode() != 0 {
        response.questions = request_questions.to_vec();
    }

    // Padding encodes a candidate to calculate its final block size. Restore
    // AXFR's question/header context first so the boundary SOA duplicate is
    // validated under transfer semantics during that measurement.
    prepare_response_padding(&mut response, request)?;
    validator.accept(&response)?;
    response.into_wire().ok()
}

pub(super) fn prepare_response_padding(
    response: &mut Message,
    request: Option<(&Message, TransportProtocol)>,
) -> Option<()> {
    match request {
        Some((request, _protocol @ (TransportProtocol::Tls | TransportProtocol::Quic))) => {
            #[cfg(feature = "doq")]
            let stream_request = (_protocol == TransportProtocol::Quic)
                .then(|| crate::message::stream_padding_request(request));
            #[cfg(feature = "doq")]
            let request = stream_request.as_ref().unwrap_or(request);
            // A valid FORMERR must survive malformed request OPT metadata.
            // Such metadata cannot authorize response padding.
            let Ok(request_edns) = request.edns() else {
                remove_cleartext_padding(response);
                return Some(());
            };
            if request_edns
                .as_ref()
                .is_some_and(|edns| edns.validate_options().is_err())
            {
                remove_cleartext_padding(response);
                return Some(());
            }
            let request_uses_edns = request_edns.is_some();
            let request_uses_padding = request_edns
                .as_ref()
                .is_some_and(|edns| edns.padding().is_some());
            let response_edns = response.edns().ok()?;
            if request_uses_edns && response_edns.is_none() {
                // RFC 6891 requires an OPT response to an OPT request, and RFC
                // 9103 makes that explicit for every message in an AXFR series.
                response
                    .additionals
                    .push(dns::Edns::default().into_record());
            }
            if !request_uses_padding {
                // RFC 7830 permits unsolicited response padding when the
                // request uses EDNS, but this transport's deterministic policy
                // adds it only when the request explicitly asks for it.
                remove_cleartext_padding(response);
                return Some(());
            }
            // An otherwise-empty AXFR/IXFR padding frame is valid only once
            // its OPT contains Padding. Seed the zero-length form before the
            // policy measures the candidate; the policy replaces it with the
            // final block-sized option transactionally.
            if response.answers.is_empty()
                && response.authorities.is_empty()
                && (response.questions.is_empty()
                    || matches!(response.questions.as_slice(), [question]
                        if matches!(question.qtype, dns::QueryType::AXFR | dns::QueryType::IXFR)))
                && matches!(response.additionals.as_slice(), [record]
                    if record.rtype == dns::RecordType::OPT)
                && response
                    .edns()
                    .ok()
                    .flatten()
                    .is_some_and(|edns| edns.padding().is_none())
                && let dns::RData::OPT(options) = &mut response.additionals[0].rdata
            {
                options.push(dns::EdnsOption::padding(0));
            }
            match response.pad_response_for_encrypted_transport(request, MAX_TCP_MESSAGE_OCTETS) {
                Ok(_) => Some(()),
                // RFC 7830 exempts a padded response when padding would exceed
                // the requestor's advertised payload size. Stream transports
                // may still carry the complete unpadded DNS message.
                Err(dns::PaddingPolicyError::MessageTooLarge { .. }) => {
                    remove_cleartext_padding(response);
                    Some(())
                }
                Err(_) => None,
            }
        }
        _ => {
            remove_cleartext_padding(response);
            Some(())
        }
    }
}
