#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use dns::{RCode, Sig0SigningKey, TsigKey, TsigStreamSigner};
use tokio::sync::mpsc;

use crate::{name::dns_name_key, response::error_response};

use super::{
    NameServer, TransferPlan, UpdateIdentity, axfr, remember_sig0_request, sig0,
    tsig::{
        RequestAuthentication, authenticate, sign_response, signed_badtime_response, unix_time_now,
    },
};

mod authentication;

enum AuthenticatedRequest {
    Tsig {
        key: TsigKey,
        request_mac: Vec<u8>,
        original_id: u16,
        fudge: u16,
    },
    Sig0 {
        key: Sig0SigningKey,
        request_wire: Vec<u8>,
    },
}

const AXFR_RESPONSE_CHANNEL_CAPACITY: usize = 1;

impl transport::DnsRequestHandler for NameServer {
    fn try_handle(
        &self,
        query: &dns::Message,
        _wire: &[u8],
        _peer: std::net::SocketAddr,
        protocol: transport::TransportProtocol,
    ) -> Option<dns::Message> {
        if !ordinary_immediate_query(query, protocol) {
            return None;
        }
        // Respect queued writers and preserve the existing asynchronous wait
        // when a publication or update currently prevents a read lock.
        let zones = self.zones.try_read()?;
        let response = super::resolve(&zones, query);
        super::log_response(&response, "DNS request resolved");
        Some(response)
    }

    fn try_handle_udp(
        &self,
        query: &dns::Message,
        _wire: &[u8],
        _peer: std::net::SocketAddr,
        maximum: usize,
    ) -> Option<transport::ImmediateUdpResponse> {
        if !ordinary_immediate_query(query, transport::TransportProtocol::Udp) {
            return None;
        }
        // try_read respects pending publication/update writers as before.
        let zones = self.zones.try_read()?;
        let response = super::resolution::resolve_udp(&zones, query, maximum);
        match &response {
            transport::ImmediateUdpResponse::Message(response) => {
                super::log_response(response, "DNS request resolved")
            }
            transport::ImmediateUdpResponse::Encoded(_) => tracing::debug!(
                transaction_id = query.headers.id,
                "DNS negative request resolved"
            ),
        }
        Some(response)
    }

    fn handle<'future>(
        &'future self,
        request: transport::DnsRequest,
    ) -> transport::BoxFuture<'future, ()> {
        Box::pin(async move {
            let (query, authenticated) = match self.authenticate_request(&request).await {
                Ok(accepted) => accepted,
                Err(response) => {
                    if let Some(response) = response {
                        let _ = request.respond(response);
                    }
                    return;
                }
            };
            let response_query = query.clone();
            let update_identity =
                authenticated
                    .as_ref()
                    .map(|authentication| match authentication {
                        AuthenticatedRequest::Tsig { key, .. } => {
                            UpdateIdentity::Tsig(key.name().clone())
                        }
                        AuthenticatedRequest::Sig0 { key, .. } => {
                            UpdateIdentity::Sig0(key.verification_key().name().clone())
                        }
                    });
            let plan = self
                .transfer_plan(
                    request.peer(),
                    query,
                    request.protocol(),
                    update_identity.as_ref(),
                )
                .await;
            self.respond_to_plan(request, &response_query, authenticated, plan)
                .await;
        })
    }
}

impl NameServer {
    async fn respond_to_plan(
        &self,
        request: transport::DnsRequest,
        response_query: &dns::Message,
        authenticated: Option<AuthenticatedRequest>,
        plan: TransferPlan,
    ) {
        match plan {
            TransferPlan::Single(mut response) => {
                if let Some(authenticated) = authenticated {
                    let signing_failed = authenticated.signing_failed(
                        &mut response,
                        response_query,
                        request.protocol(),
                    );
                    if signing_failed {
                        return;
                    }
                }
                let _ = request.respond(response);
            }
            TransferPlan::Zone { query, zone } => {
                if let Some(AuthenticatedRequest::Sig0 { key, request_wire }) = authenticated {
                    let mut response = error_response(&query, RCode::NotImplemented);
                    if sig0::sign_response(
                        &key,
                        &request_wire,
                        &mut response,
                        &query,
                        request.protocol(),
                    )
                    .is_ok()
                    {
                        let _ = request.respond(response);
                    }
                    return;
                }
                let (responses, receiver) = mpsc::channel(AXFR_RESPONSE_CHANNEL_CAPACITY);
                if !request.respond_stream(receiver) {
                    return;
                }
                let signing = authenticated.map(|authenticated| match authenticated {
                    AuthenticatedRequest::Tsig {
                        key,
                        request_mac,
                        original_id,
                        fudge,
                    } => axfr::TsigStreamSigning {
                        signer: TsigStreamSigner::new(key, request_mac),
                        original_id,
                        fudge,
                    },
                    AuthenticatedRequest::Sig0 { .. } => unreachable!("handled above"),
                });
                let _ = axfr::stream_axfr_responses(
                    &query,
                    zone.transfer_records_iter(),
                    responses,
                    signing,
                )
                .await;
            }
        }
    }
}

impl AuthenticatedRequest {
    fn signing_failed(
        self,
        response: &mut dns::Message,
        response_query: &dns::Message,
        protocol: transport::TransportProtocol,
    ) -> bool {
        match self {
            AuthenticatedRequest::Tsig {
                key,
                request_mac,
                original_id,
                fudge,
            } => sign_response(
                &key,
                &request_mac,
                original_id,
                fudge,
                response,
                response_query,
                protocol,
            )
            .is_err(),
            AuthenticatedRequest::Sig0 { key, request_wire } => {
                sig0::sign_response(&key, &request_wire, response, response_query, protocol)
                    .is_err()
            }
        }
    }
}

fn ordinary_immediate_query(query: &dns::Message, protocol: transport::TransportProtocol) -> bool {
    // Only unsigned ordinary UDP lookups can avoid the authentication,
    // replay tracking, mutation, and transfer machinery below. DNSSEC
    // signatures in the zone's answer still follow normal resolution.
    if protocol != transport::TransportProtocol::Udp
        || query.headers.opcode != dns::OpCode::Query
        || query.questions.len() != 1
        || matches!(
            query.questions[0].qtype,
            dns::QueryType::AXFR | dns::QueryType::IXFR
        )
        || query
            .answers
            .iter()
            .chain(&query.authorities)
            .chain(&query.additionals)
            .any(|record| {
                record.rtype == dns::RecordType::TSIG
                    || matches!(&record.rdata, dns::RData::SIG(sig) if sig.is_sig0())
            })
    {
        return false;
    }
    if query
        .edns()
        .ok()
        .flatten()
        .is_some_and(|edns| edns.version != dns::Edns::VERSION)
        || super::request_error(query).is_some()
    {
        return false;
    }
    true
}
