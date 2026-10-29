use std::sync::Arc;

use dns::{Edns, ExtendedDnsError, ExtendedDnsErrorCode, Message, OpCode, RCode, RecordType};
use transport::{DnsRequest, DnsRequestHandler, Transport};

use crate::{ResolveError, Resolver, resolver::AlgorithmSignals};

/// Adapts an iterative [`Resolver`] for use as a recursive DNS request handler.
pub struct RecursiveServer<T: Transport> {
    resolver: Arc<Resolver<T>>,
}

/// One immutable EDNS interpretation shared by request policy and reply shaping.
struct RequestEdns {
    value: Option<Edns>,
    malformed: bool,
    options_valid: bool,
}

impl RequestEdns {
    fn new(request: &Message) -> Self {
        let parsed = request.edns();
        let malformed = parsed.is_err();
        let value = parsed.ok().flatten();
        let options_valid = value
            .as_ref()
            .is_none_or(|edns| edns.validate_options().is_ok());
        Self {
            value,
            malformed,
            options_valid,
        }
    }

    fn dnssec_ok(&self) -> bool {
        self.value.as_ref().is_some_and(|edns| edns.dnssec_ok)
    }
}

impl<T: Transport> RecursiveServer<T> {
    /// Creates a recursive server that sends resolution queries over
    /// `resolution_transport` and uses the default resolver configuration.
    pub fn with_resolution_transport(resolution_transport: T) -> Self {
        Self::with_resolver(Resolver::with_defaults(resolution_transport))
    }

    /// Creates a recursive server backed by a preconfigured `resolver`.
    pub fn with_resolver(resolver: Resolver<T>) -> Self {
        Self {
            resolver: Arc::new(resolver),
        }
    }

    fn request_error_response(&self, request: &Message, edns: &RequestEdns) -> Option<Message> {
        // Preserve BADVERS precedence over header and extended-RCODE errors,
        // but only when the received option structure and contents are valid.
        if edns
            .value
            .as_ref()
            .is_some_and(|value| value.version != Edns::VERSION)
            && edns.options_valid
        {
            return request.edns_error_response(true);
        }
        if let Some(rcode) = request_error(request, edns) {
            return Some(request.error_response(rcode, true));
        }
        if !request.headers.rd {
            return Some(extended_error_response(
                request,
                RCode::Refused,
                ExtendedDnsErrorCode::NotAuthoritative,
            ));
        }
        None
    }

    /// Answers a decoded recursive query without owning a transport reply channel.
    ///
    /// Applies the same request validation, DNSSEC policy, and response shaping
    /// as the transport handler. Applications can wrap this future in an overall
    /// request deadline and retain the reply channel for a timeout response.
    pub async fn answer_message(&self, request: &Message) -> Message {
        self.answer(request).await
    }

    async fn answer(&self, request: &Message) -> Message {
        self.answer_with_cache_check(request, true).await
    }

    async fn answer_with_cache_check(&self, request: &Message, check_cache: bool) -> Message {
        let edns = RequestEdns::new(request);
        if let Some(response) = self.request_error_response(request, &edns) {
            return response;
        }

        let algorithm_signals = edns
            .value
            .as_ref()
            .filter(|edns| edns.dnssec_ok)
            .map_or_else(AlgorithmSignals::default, |edns| {
                AlgorithmSignals::from_edns(edns)
            });
        let result = self
            .resolver
            .resolve_with_cache_check(
                request.questions[0].clone(),
                algorithm_signals,
                request.headers.cd,
                check_cache,
            )
            .await;
        self.client_response(request, result, &edns)
    }

    fn client_response(
        &self,
        request: &Message,
        result: Result<Message, ResolveError>,
        edns: &RequestEdns,
    ) -> Message {
        match result {
            Ok(mut response) => {
                response.headers.id = request.headers.id;
                response.headers.qr = true;
                response.headers.opcode = request.headers.opcode;
                response.headers.aa = false;
                response.headers.rd = true;
                response.headers.ra = true;
                response.headers.ad =
                    should_set_authenticated_data(request, response.headers.ad, edns);
                response.headers.cd = request.headers.cd;
                response.questions.clone_from(&request.questions);
                strip_unrequested_dnssec_records(request, &mut response, edns);
                response
                    .additionals
                    .retain(|record| record.rtype != RecordType::OPT);
                if edns.value.is_some() {
                    response.additionals.push(response_edns(edns).into_record());
                }
                response
            }
            Err(error) => {
                tracing::warn!(error = %error, "recursive DNS resolution failed");
                let rcode = resolve_error_code(&error);
                match resolve_error_extended_code(&error) {
                    Some(code) => extended_error_response(request, rcode, code),
                    None => request.error_response(rcode, true),
                }
            }
        }
    }
}

impl<T: Transport> Clone for RecursiveServer<T> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
        }
    }
}

impl<T: Transport + 'static> DnsRequestHandler for RecursiveServer<T> {
    fn try_handle(
        &self,
        message: &Message,
        _wire_message: &[u8],
        _peer: std::net::SocketAddr,
        _protocol: transport::TransportProtocol,
    ) -> Option<Message> {
        let edns = RequestEdns::new(message);
        if let Some(response) = self.request_error_response(message, &edns) {
            return Some(response);
        }
        match self
            .resolver
            .try_resolve_cached_with_policy(&message.questions[0], !message.headers.cd)
        {
            Ok(Some(response)) => Some(self.client_response(message, Ok(response), &edns)),
            Ok(None) => None,
            Err(error) => Some(self.client_response(message, Err(error), &edns)),
        }
    }

    fn try_handle_udp(
        &self,
        message: &Message,
        _wire: &[u8],
        _peer: std::net::SocketAddr,
        maximum: usize,
    ) -> Option<transport::ImmediateUdpResponse> {
        let edns = RequestEdns::new(message);
        if let Some(response) = self.request_error_response(message, &edns) {
            return Some(transport::ImmediateUdpResponse::Message(response));
        }
        let eligible = message.additionals.is_empty()
            || (message.additionals.len() == 1
                && edns
                    .value
                    .as_ref()
                    .is_some_and(|value| value.options.is_empty()));
        let result = if eligible {
            self.resolver.try_resolve_cached_udp(message, maximum)
        } else {
            self.resolver
                .try_resolve_cached_with_policy(&message.questions[0], !message.headers.cd)
                .map(|response| response.map(transport::ImmediateUdpResponse::Message))
        };
        match result {
            Ok(Some(transport::ImmediateUdpResponse::Message(response))) => {
                Some(transport::ImmediateUdpResponse::Message(
                    self.client_response(message, Ok(response), &edns),
                ))
            }
            Ok(Some(transport::ImmediateUdpResponse::Encoded(response))) => {
                Some(transport::ImmediateUdpResponse::Encoded(response))
            }
            Ok(None) => None,
            Err(error) => Some(transport::ImmediateUdpResponse::Message(
                self.client_response(message, Err(error), &edns),
            )),
        }
    }

    fn handle<'future>(&'future self, request: DnsRequest) -> transport::BoxFuture<'future, ()> {
        Box::pin(async move {
            let response = if request.immediate_handling_attempted_by(self) {
                self.answer_with_cache_check(request.message(), false).await
            } else {
                self.answer_message(request.message()).await
            };
            let _ = request.respond(response);
        })
    }
}

fn request_error(request: &Message, edns: &RequestEdns) -> Option<RCode> {
    if request.headers.qr
        || request.headers.aa
        || request.headers.tc
        || request.headers.ra
        || request.headers.rcode != RCode::Ok
        || request.questions.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
    {
        return Some(RCode::FormatError);
    }
    if request.headers.opcode != OpCode::Query {
        return Some(RCode::NotImplemented);
    }
    if !request.questions[0].is_wire_canonical()
        || edns.malformed
        || edns
            .value
            .as_ref()
            .is_some_and(|value| value.extended_rcode != 0)
        || !edns.options_valid
        || contains_noncanonical_opt(request)
    {
        return Some(RCode::FormatError);
    }
    None
}

fn should_set_authenticated_data(
    request: &Message,
    validated_secure: bool,
    edns: &RequestEdns,
) -> bool {
    validated_secure && !request.headers.cd && (request.headers.ad || edns.dnssec_ok())
}

fn strip_unrequested_dnssec_records(request: &Message, response: &mut Message, edns: &RequestEdns) {
    if edns.dnssec_ok() {
        return;
    }
    let explicitly_requested = request
        .questions
        .first()
        .map(|question| question.qtype.value());
    let retain = |record: &dns::ResourceRecord| {
        crate::response::requested_dnssec_record(record.rtype, explicitly_requested, false)
    };
    response.answers.retain(retain);
    response.authorities.retain(retain);
    response.additionals.retain(retain);
}

fn contains_noncanonical_opt(request: &Message) -> bool {
    request
        .additionals
        .iter()
        .any(|record| u16::from(record.rtype) == 41 && record.rtype != RecordType::OPT)
}

fn resolve_error_code(error: &ResolveError) -> RCode {
    match error {
        ResolveError::UnsupportedQuestion => RCode::NotImplemented,
        _ => RCode::ServerFailure,
    }
}

fn resolve_error_extended_code(error: &ResolveError) -> Option<ExtendedDnsErrorCode> {
    match error {
        ResolveError::UnsupportedQuestion => Some(ExtendedDnsErrorCode::NotSupported),
        ResolveError::NoReachableServer => Some(ExtendedDnsErrorCode::NoReachableAuthority),
        ResolveError::Transport(_) => Some(ExtendedDnsErrorCode::NetworkError),
        ResolveError::DnssecBogus(_) => Some(ExtendedDnsErrorCode::DnssecBogus),
        ResolveError::DnssecIndeterminate(_) => Some(ExtendedDnsErrorCode::DnssecIndeterminate),
        ResolveError::TemporaryServerFailure
        | ResolveError::CachedNameServerFailure
        | ResolveError::CachedDelegationFailure
        | ResolveError::DelegationRefreshInProgress
        | ResolveError::WorkLimitExceeded
        | ResolveError::CnameLoop
        | ResolveError::CacheBackend(_) => None,
    }
}

fn response_edns(edns: &RequestEdns) -> Edns {
    Edns {
        dnssec_ok: edns.dnssec_ok(),
        ..Edns::default()
    }
}

fn extended_error_response(request: &Message, rcode: RCode, code: ExtendedDnsErrorCode) -> Message {
    let mut response = request.error_response(rcode, true);
    let Some(record) = response.additionals.first_mut() else {
        return response;
    };
    let mut edns =
        Edns::try_from_record(record).expect("error response creates a valid OPT record");
    edns.push_extended_dns_error(ExtendedDnsError::without_text(code))
        .expect("named EDE codes are canonical");
    *record = edns.into_record();
    response
}

#[cfg(test)]
mod tests;
