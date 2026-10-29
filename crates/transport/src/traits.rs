//! Object-safe transport and application request interfaces.
use std::{future::Future, net::SocketAddr, time::Duration};

use crate::{DnsRequest, ImmediateUdpResponse, TransportError, TransportProtocol};
use dns::Message;

/// Handles stateful DNS requests accepted by a transport listener.
pub trait DnsRequestHandler: Send + Sync {
    /// Optionally answers a request immediately without creating a reply channel.
    ///
    /// Returning `None` delegates to [`Self::handle`]. The listener applies the
    /// same response validation, size limits, and authentication rules to either
    /// path. Implementations must return promptly; pending work belongs in
    /// `handle`. The wire bytes are the exact received image, including its
    /// compression and letter case, and are borrowed only for this call.
    fn try_handle(
        &self,
        _message: &Message,
        _wire_message: &[u8],
        _peer: SocketAddr,
        _protocol: TransportProtocol,
    ) -> Option<Message> {
        None
    }

    /// Optionally returns an immediate UDP reply using checked prepared encoding.
    ///
    /// The default forwards to `try_handle` on the same concrete handler. The
    /// listener discards mismatched request contexts and checks the actual UDP
    /// ceiling. Oversized correlated packets are decoded into the ordinary
    /// pipeline without calling the handler again, preserving preparation and
    /// popularity side effects.
    fn try_handle_udp(
        &self,
        message: &Message,
        wire_message: &[u8],
        peer: SocketAddr,
        _maximum: usize,
    ) -> Option<ImmediateUdpResponse> {
        self.try_handle(message, wire_message, peer, TransportProtocol::Udp)
            .map(ImmediateUdpResponse::Message)
    }

    /// Handles one request and responds through its single-use reply path.
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()>;
}

impl<F, Fut> DnsRequestHandler for F
where
    F: Fn(Message) -> Fut + Send + Sync,
    Fut: Future<Output = Message> + Send,
{
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            let response = self(request.message().clone()).await;
            let _ = request.respond(response);
        })
    }
}

/// Exchanges DNS messages using one wire protocol.
pub trait Transport: Send + Sync {
    /// Returns the wire protocol used for exchanges, when it is known.
    ///
    /// Custom transports may leave this unspecified. Protocol-specific
    /// consumers must not infer UDP or TCP from an unspecified value.
    fn protocol(&self) -> Option<TransportProtocol> {
        None
    }

    /// Exchanges one DNS message with `server`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the request can't be encoded, the
    /// exchange times out, network I/O fails, or the response is invalid.
    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>>;

    /// Returns the transport required after `reason`, if this protocol defines
    /// a transition for that event.
    ///
    /// Concrete transports use this for protocol-defined behavior. Wrappers
    /// may add application-policy transitions for reasons the concrete
    /// transport does not handle itself.
    fn transition(&self, _reason: TransitionReason) -> Option<&dyn Transport> {
        None
    }
}

/// The event that caused a resolver to consider another transport.
///
/// Routes assign meaning to transitions rather than assuming that every
/// change of protocol is a downgrade to a single fallback. This permits, for
/// example, UDP to transition to TCP after truncation while an encrypted
/// transport transitions to another encrypted transport after an I/O error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransitionReason {
    /// The query was too large for the current transport.
    QueryTooLarge,
    /// The server returned a truncated response.
    TruncatedResponse,
    /// The exchange timed out.
    Timeout,
    /// Network I/O failed.
    IoError,
}

/// Adds application-policy transitions between transports.
///
/// A target may itself be a `TransportRoute`, allowing any finite tree of
/// policy-driven upgrades, downgrades, and lateral protocol changes. A
/// concrete transport's protocol-defined transition always takes precedence.
/// Keeping routes finite also prevents a single exchange from cycling forever
/// between protocols.
///
/// An exchange directly returns the selected transport's future. Constructing
/// that future happens when `exchange` is called; work inside its async block
/// starts when polled. Custom synchronous construction work is not deferred.
pub struct TransportRoute {
    transport: Box<dyn Transport>,
    transitions: Vec<RouteTransition>,
}

struct RouteTransition {
    reasons: Vec<TransitionReason>,
    target: Box<dyn Transport>,
}

impl TransportRoute {
    /// Creates a route whose first exchange uses `transport`.
    pub fn new<T>(transport: T) -> Self
    where
        T: Transport + 'static,
    {
        Self {
            transport: Box::new(transport),
            transitions: Vec::new(),
        }
    }

    /// Adds a transition to `target` for any of `reasons`.
    ///
    /// The concrete transport's protocol-defined transition wins first. Among
    /// policy transitions, the first one containing the same reason wins. Pass
    /// another `TransportRoute` as `target` to continue routing after the next
    /// exchange.
    pub fn on<T, I>(mut self, reasons: I, target: T) -> Self
    where
        T: Transport + 'static,
        I: IntoIterator<Item = TransitionReason>,
    {
        self.transitions.push(RouteTransition {
            reasons: reasons.into_iter().collect(),
            target: Box::new(target),
        });
        self
    }
}

impl Transport for TransportRoute {
    fn protocol(&self) -> Option<TransportProtocol> {
        self.transport.protocol()
    }

    fn exchange<'future>(
        &'future self,
        server: SocketAddr,
        query: &'future Message,
        timeout: Duration,
    ) -> crate::BoxFuture<'future, Result<Message, TransportError>> {
        self.transport.exchange(server, query, timeout)
    }

    fn transition(&self, reason: TransitionReason) -> Option<&dyn Transport> {
        self.transport.transition(reason).or_else(|| {
            self.transitions
                .iter()
                .find(|transition| transition.reasons.contains(&reason))
                .map(|transition| transition.target.as_ref())
        })
    }
}

/// Serves DNS requests using one wire protocol.
pub trait TransportServer: Send + Sync {
    /// Serves DNS requests on `address` until the listener fails.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the listener can't bind or accept traffic.
    fn serve<'future, H>(
        self,
        address: SocketAddr,
        handler: H,
    ) -> crate::BoxFuture<'future, Result<(), std::io::Error>>
    where
        Self: Sized,
        H: DnsRequestHandler + 'static,
        Self: 'future;
}
