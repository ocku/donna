use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{Mutex, atomic::AtomicUsize},
    task::Poll,
    time::{Duration, Instant},
};

use dns::{Message, RCode, RecordType};
use tracing::{debug, instrument, warn};
use transport::{TransitionReason, Transport, TransportError, TransportProtocol};

use crate::{protocol::is_correlated_response, response::consume_work};

use super::{ResolutionStatsContext, Resolver, response_handling::has_minimum_response_structure};

enum ExchangeError {
    Transport(TransportError),
    InvalidResponse,
    WorkLimit,
    AttemptsExhausted,
}

enum ExchangeState<'a> {
    Initial(&'a dyn Transport),
    Transitioned(&'a dyn Transport),
}

impl<'a> ExchangeState<'a> {
    fn new(transport: &'a dyn Transport) -> Self {
        Self::Initial(transport)
    }

    fn transport(&self) -> &'a dyn Transport {
        match self {
            Self::Initial(transport) | Self::Transitioned(transport) => *transport,
        }
    }

    fn transition(
        &mut self,
        reason: TransitionReason,
        target: (SocketAddr, &Message),
        attempts: &Mutex<super::retry_budget::RetryBudget>,
        remaining_steps: &AtomicUsize,
        max_attempts: u8,
        stats: &ResolutionStatsContext,
    ) -> Result<bool, ExchangeError> {
        let (server, request) = target;
        let Some(next) = self.transport().transition(reason) else {
            return Ok(false);
        };
        match reserve_transmission(
            attempts,
            remaining_steps,
            server,
            request,
            max_attempts,
            next,
            stats,
        ) {
            ReserveResult::Reserved => {}
            ReserveResult::AttemptsExhausted => return Err(ExchangeError::AttemptsExhausted),
            ReserveResult::WorkExhausted => return Err(ExchangeError::WorkLimit),
        }
        *self = Self::Transitioned(next);
        if next.protocol() == Some(TransportProtocol::Tcp)
            && let Some(stats) = stats
        {
            stats.increment_tcp_transitions();
        }
        Ok(true)
    }

    fn is_transitioned(&self) -> bool {
        matches!(self, Self::Transitioned(_))
    }
}

impl<T: Transport> Resolver<T> {
    /// Runs one query against one server through the transport state machine.
    ///
    /// Each pass is in the `Exchange` state. A transport error or a correlated
    /// truncated response may move the query to the `Transition` state, which
    /// selects the next transport and returns to `Exchange`. A usable response
    /// or a terminal failure completes the machine.
    #[instrument(
        level = "debug",
        skip(self, request, remaining_steps, attempts, stats),
        fields(server = %server, transaction_id = request.headers.id)
    )]
    async fn exchange(
        &self,
        server: SocketAddr,
        request: &Message,
        remaining_steps: &AtomicUsize,
        attempts: &Mutex<super::retry_budget::RetryBudget>,
        stats: ResolutionStatsContext,
    ) -> Result<Option<ExchangeResponse>, ExchangeError> {
        match reserve_transmission(
            attempts,
            remaining_steps,
            server,
            request,
            self.config.max_attempts_per_server,
            self.transport.as_ref(),
            &stats,
        ) {
            ReserveResult::Reserved => {}
            ReserveResult::AttemptsExhausted => return Err(ExchangeError::AttemptsExhausted),
            ReserveResult::WorkExhausted => return Err(ExchangeError::WorkLimit),
        }

        let question = request
            .questions
            .first()
            .expect("resolver queries always contain one question");
        let mut state = ExchangeState::new(self.transport.as_ref());
        let mut active_request = request.clone();
        let mut tried_unextended_dns = false;
        let mut responsive_protocols = Vec::new();

        loop {
            let started = Instant::now();
            let (reply, elapsed) = match state
                .transport()
                .exchange(server, &active_request, self.config.timeout)
                .await
            {
                Ok(reply) => {
                    let elapsed = started.elapsed();
                    if state.is_transitioned()
                        && state.transport().protocol() == Some(TransportProtocol::Tcp)
                        && let Some(stats) = &stats
                    {
                        stats.increment_tcp_completions();
                    }
                    (reply, elapsed)
                }
                Err(error) => {
                    match &error {
                        TransportError::Timeout => {
                            if let Some(stats) = &stats {
                                stats.increment_timeouts();
                            }
                            self.server_metrics
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .record_timeout(server, &stats);
                        }
                        TransportError::Io(_) => {
                            if let Some(stats) = &stats {
                                stats.increment_transient_transport_failures();
                            }
                            self.server_metrics
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .record_io_failure(server, &stats);
                        }
                        _ => {}
                    }
                    let Some(reason) = transition_reason(&error) else {
                        return Err(ExchangeError::Transport(error));
                    };
                    if state.transition(
                        reason,
                        (server, &active_request),
                        attempts,
                        remaining_steps,
                        self.config.max_attempts_per_server,
                        &stats,
                    )? {
                        debug!(?reason, "DNS exchange failed; transitioning transport");
                        continue;
                    }
                    return terminal_transport_failure(error);
                }
            };

            if !is_correlated_response(&reply, active_request.headers.id, question) {
                return Err(ExchangeError::InvalidResponse);
            }
            if tried_unextended_dns && !matches!(reply.edns(), Ok(None)) {
                debug!(%server, "discarding EDNS response to unextended fallback request");
                return Err(ExchangeError::InvalidResponse);
            }
            if reply.headers.tc {
                if has_minimum_response_structure(&reply, question) {
                    self.server_metrics
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .record_success(server, elapsed, &stats);
                    responsive_protocols.push(state.transport().protocol());
                }
                if state.transition(
                    TransitionReason::TruncatedResponse,
                    (server, &active_request),
                    attempts,
                    remaining_steps,
                    self.config.max_attempts_per_server,
                    &stats,
                )? {
                    debug!("DNS response was truncated; transitioning transport");
                    continue;
                }
            }
            if !tried_unextended_dns
                && signals_edns_unawareness(&reply)
                && edns_fallback_allowed(&active_request)
            {
                match reserve_transmission(
                    attempts,
                    remaining_steps,
                    server,
                    &active_request,
                    self.config.max_attempts_per_server,
                    state.transport(),
                    &stats,
                ) {
                    ReserveResult::Reserved => {
                        if let Some(stats) = &stats {
                            stats.increment_edns_fallbacks();
                        }
                        if has_minimum_response_structure(&reply, question) {
                            self.server_metrics
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .record_success(server, elapsed, &stats);
                        }
                    }
                    ReserveResult::AttemptsExhausted => {
                        debug!(%server, "EDNS fallback blocked by per-server attempt limit");
                        return Ok(Some(ExchangeResponse {
                            reply,
                            elapsed,
                            protocol: state.transport().protocol(),
                            responsive_protocols,
                        }));
                    }
                    ReserveResult::WorkExhausted => return Err(ExchangeError::WorkLimit),
                }
                active_request
                    .additionals
                    .retain(|record| record.rtype != RecordType::OPT);
                tried_unextended_dns = true;
                debug!(%server, "server rejected EDNS; retrying same server without OPT");
                continue;
            }
            return Ok(Some(ExchangeResponse {
                reply,
                elapsed,
                protocol: state.transport().protocol(),
                responsive_protocols,
            }));
        }
    }

    /// Starts one query against several candidate servers.
    ///
    /// The returned round owns each exchange future until semantic response
    /// handling accepts a result, replaces the candidate set, or exhausts the
    /// round. Polling the round again resumes the same futures without another
    /// attempt reservation or work-budget charge.
    pub(super) fn exchange_round<'a>(
        &'a self,
        servers: &[SocketAddr],
        request: &'a Message,
        remaining_steps: &'a AtomicUsize,
        attempts: &'a Mutex<super::retry_budget::RetryBudget>,
        stats: ResolutionStatsContext,
    ) -> ExchangeRound<'a> {
        let exchanges = servers
            .iter()
            .map(|server| ExchangeSlot {
                server: *server,
                future: Box::pin(self.exchange(
                    *server,
                    request,
                    remaining_steps,
                    attempts,
                    stats.clone(),
                )),
                started: false,
            })
            .collect();
        ExchangeRound {
            exchanges,
            failure: RaceFailure::default(),
            stats,
            counts_race_cancellations: servers.len() > 1,
        }
    }
}

pub(super) struct ExchangeResponse {
    pub(super) protocol: Option<TransportProtocol>,
    pub(super) responsive_protocols: Vec<Option<TransportProtocol>>,
    pub(super) reply: Message,
    pub(super) elapsed: Duration,
}

struct ExchangeSlot<'a> {
    server: SocketAddr,
    future: ExchangeFuture<'a>,
    started: bool,
}

pub(super) struct ExchangeRound<'a> {
    exchanges: Vec<ExchangeSlot<'a>>,
    failure: RaceFailure,
    stats: ResolutionStatsContext,
    counts_race_cancellations: bool,
}

impl Drop for ExchangeRound<'_> {
    fn drop(&mut self) {
        if self.counts_race_cancellations
            && let Some(stats) = &self.stats
        {
            stats.add_canceled_losers(
                self.exchanges
                    .iter()
                    .filter(|exchange| exchange.started)
                    .count(),
            );
        }
    }
}

impl ExchangeRound<'_> {
    /// Yields the next correlated transport response while retaining every
    /// pending exchange. Transport failures are aggregated until no member of
    /// the round remains.
    pub(super) async fn next_response(
        &mut self,
    ) -> Result<(SocketAddr, ExchangeResponse), RaceFailure> {
        while !self.exchanges.is_empty() {
            let (index, server, result) = poll_fn(|cx| {
                for (index, exchange) in self.exchanges.iter_mut().enumerate() {
                    exchange.started = true;
                    if let Poll::Ready(result) = exchange.future.as_mut().poll(cx) {
                        return Poll::Ready((index, exchange.server, result));
                    }
                }
                Poll::Pending
            })
            .await;
            drop(self.exchanges.remove(index));
            match result {
                Ok(Some(reply)) => return Ok((server, reply)),
                Ok(None) => self.failure.timed_out.push(server),
                Err(ExchangeError::WorkLimit) => self.failure.work_exhausted = true,
                Err(ExchangeError::AttemptsExhausted) => {}
                Err(ExchangeError::InvalidResponse) => {}
                Err(ExchangeError::Transport(TransportError::Io(error)))
                    if error.kind() == std::io::ErrorKind::InvalidData =>
                {
                    // TLS certificate/handshake rejection is reported here
                    // by tokio-rustls. Retrying the same invalid peer cannot
                    // repair it; retain other members of this server race.
                    warn!(%server, %error, "discarding invalid DNS transport peer data");
                }
                Err(ExchangeError::Transport(TransportError::Io(error)))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::OutOfMemory
                    ) =>
                {
                    // Local request/resource failures are neither retryable
                    // remote failures nor eligible for failure-cache admission.
                    self.failure.fatal.get_or_insert(TransportError::Io(error));
                }
                Err(ExchangeError::Transport(error @ TransportError::Io(_))) => {
                    warn!(
                        %server,
                        error = %error,
                        "retrying after a transient DNS transport failure"
                    );
                    self.failure.transient.push(server);
                }
                Err(ExchangeError::Transport(error @ TransportError::Decode(_))) => {
                    warn!(%server, error = %error, "discarding malformed DNS server response");
                }
                Err(ExchangeError::Transport(error)) => {
                    // Encode and transfer-policy failures are deterministic
                    // for this request; retrying other servers cannot help.
                    self.failure.fatal.get_or_insert(error);
                }
            }
        }
        Err(std::mem::take(&mut self.failure))
    }
}

/// RFC 6891 section 7 identifies FORMERR without an OPT response as the
/// interoperable signal that a responder does not implement EDNS.
fn signals_edns_unawareness(reply: &Message) -> bool {
    reply.headers.rcode == RCode::FormatError && matches!(reply.edns(), Ok(None))
}

/// Falling back is safe only when EDNS was used for payload negotiation alone.
/// DO or any option makes the request's meaning depend on EDNS and therefore
/// forbids silently retrying it as classic DNS.
fn edns_fallback_allowed(request: &Message) -> bool {
    request.edns().ok().flatten().is_some_and(|edns| {
        edns.version == dns::Edns::VERSION
            && edns.extended_rcode == 0
            && !edns.dnssec_ok
            && edns.z == 0
            && edns.options.is_empty()
    })
}

fn transition_reason(error: &TransportError) -> Option<TransitionReason> {
    match error {
        TransportError::MessageTooLong { .. } => Some(TransitionReason::QueryTooLarge),
        TransportError::Timeout => Some(TransitionReason::Timeout),
        TransportError::Io(_) => Some(TransitionReason::IoError),
        TransportError::Encode(_)
        | TransportError::Decode(_)
        | TransportError::InvalidTransfer(_)
        | TransportError::InsecureEdnsPadding
        | TransportError::Padding(_)
        | TransportError::InvalidTlsProtocol(_)
        | TransportError::InvalidHttpProtocol(_)
        | TransportError::InvalidQuicProtocol(_)
        | TransportError::InvalidDnscryptProtocol(_) => None,
    }
}

fn terminal_transport_failure(
    error: TransportError,
) -> Result<Option<ExchangeResponse>, ExchangeError> {
    match error {
        TransportError::Timeout => Ok(None),
        error => Err(ExchangeError::Transport(error)),
    }
}

/// Groups the outcomes of a fully failed query race so the caller can decide
/// which servers to retry.
#[derive(Default)]
pub(super) struct RaceFailure {
    pub(super) timed_out: Vec<SocketAddr>,
    pub(super) transient: Vec<SocketAddr>,
    pub(super) fatal: Option<TransportError>,
    pub(super) work_exhausted: bool,
}

#[derive(Clone, Copy)]
enum ReserveResult {
    Reserved,
    AttemptsExhausted,
    WorkExhausted,
}

fn reserve_transmission(
    attempts: &Mutex<super::retry_budget::RetryBudget>,
    remaining_steps: &AtomicUsize,
    server: SocketAddr,
    request: &Message,
    max_attempts: u8,
    transport: &dyn Transport,
    stats: &ResolutionStatsContext,
) -> ReserveResult {
    if !attempts
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .reserve(
            &request.questions[0],
            server,
            transport.protocol(),
            max_attempts,
        )
    {
        return ReserveResult::AttemptsExhausted;
    }
    if !consume_work(remaining_steps) {
        return ReserveResult::WorkExhausted;
    }
    if transport.protocol() == Some(TransportProtocol::Udp)
        && let Some(stats) = stats
    {
        stats.increment_udp_transmissions();
    }
    ReserveResult::Reserved
}

type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ExchangeResponse>, ExchangeError>> + Send + 'a>>;

#[cfg(test)]
mod tests;
