mod additional;
mod axfr;
mod handler;
mod ixfr;
mod notify;
mod positive;
mod publication;
mod request;
mod resolution;
mod sig0;
mod signed_response;
mod storage;
mod tsig;
mod update;
mod zone_index;

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::AtomicU16},
};

use dns::{Message, RCode, Sig0SigningKey, TsigKey};
#[cfg(test)]
use tokio::sync::mpsc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, instrument};

use crate::{
    name::dns_name_key,
    response::{bad_version_response, error_response},
    zone::Zone,
};

#[cfg(test)]
use self::{axfr::stream_axfr_responses, tsig::unix_time_now};
use self::{
    axfr::{address_matches, pack_axfr_responses},
    ixfr::{IxfrAnswer, IxfrDelta},
    request::{axfr_request_error, request_error},
    resolution::resolve,
    update::handle_update,
    zone_index::{ZoneIndex, exact_authoritative_zone},
};

pub use notify::{NotifyConfig, NotifyTarget};
pub use publication::{InstallError, InstallOutcome};
pub use storage::{ZoneSnapshot, ZoneStore, ZoneStoreError};

/// Authenticated identity presented with a secure Dynamic Update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateIdentity {
    /// A shared-secret TSIG key name.
    Tsig(dns::DomainName),
    /// A public-key SIG(0) signer name.
    Sig0(dns::DomainName),
}

impl UpdateIdentity {
    fn eq_dns(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Tsig(left), Self::Tsig(right)) | (Self::Sig0(left), Self::Sig0(right)) => {
                left.eq_dns(right)
            }
            _ => false,
        }
    }
}

/// A default-deny authorization grant for secure Dynamic Update.
#[derive(Clone, Debug)]
pub struct UpdateRule {
    /// Authenticated key identity to which this grant applies.
    pub identity: UpdateIdentity,
    /// Exact zone apex to which this grant applies.
    pub zone: dns::DomainName,
    /// Exact owner, or subtree root when `include_subdomains` is true.
    pub name: dns::DomainName,
    /// Permitted concrete RR types; empty permits all types and broad deletes.
    pub record_types: Vec<dns::RecordType>,
    /// Whether names below `name` are included.
    pub include_subdomains: bool,
}

impl UpdateRule {
    fn permits(
        &self,
        identity: &UpdateIdentity,
        zone: &dns::DomainName,
        record: &dns::ResourceRecord,
    ) -> bool {
        self.identity.eq_dns(identity)
            && self.zone.eq_dns(zone)
            && if self.include_subdomains {
                record.name.is_descendant_of(&self.name)
            } else {
                record.name.eq_dns(&self.name)
            }
            && (self.record_types.is_empty()
                || (u16::from(record.rtype) != 255 && self.record_types.contains(&record.rtype)))
    }
}

#[cfg(test)]
use dns::{OpCode, Question, ResourceRecord};

/// Configures optional authoritative server behavior.
///
/// AXFR is disabled by default: an authoritative server must not leak its
/// zones unless the operator explicitly opts in (RFC 5936, Section 5).
#[derive(Clone, Debug)]
pub struct NameServerConfig {
    /// Network IP and netmask pairs permitted to receive TCP AXFR responses.
    ///
    /// An empty list disables AXFR. IPv4 and IPv6 entries only match peers from
    /// the same address family.
    pub allow_axfr_to: Vec<(IpAddr, IpAddr)>,
    /// Durable storage used before an accepted dynamic update is published.
    ///
    /// With built-in zone storage, `None` keeps RFC 2136 UPDATE disabled.
    /// A provider must not return success until the supplied snapshot can
    /// survive process and power failure. A custom [`ZoneStore`] owns atomic
    /// durability itself and does not invoke this callback.
    pub update_persistence: Option<Arc<dyn UpdatePersistence>>,
    /// Explicit RFC 3007 authorization grants, evaluated with default deny.
    pub update_rules: Vec<UpdateRule>,
    /// Permits legacy unauthenticated RFC 2136 updates when durable storage is configured.
    ///
    /// This is disabled by default and is not RFC 3007 secure update.
    pub allow_insecure_updates: bool,
    /// Outbound RFC 1996 notification policy for changed primary zones.
    ///
    /// `None` disables outbound NOTIFY. Configured targets form the
    /// operator-selected notify set permitted by RFC 1996 section 2.1.
    pub notify: Option<NotifyConfig>,
    /// Shared TSIG keys accepted for authenticating requests and responses.
    ///
    /// An empty list leaves transaction authentication disabled. Each key name
    /// should occur only once and is associated with exactly one algorithm.
    pub tsig_keys: Vec<TsigKey>,
    /// Ed25519 SIG(0) keys accepted for request verification and response signing.
    ///
    /// An empty list leaves public-key transaction authentication disabled.
    pub sig0_keys: Vec<Sig0SigningKey>,
    /// Maximum permitted distance from the server clock to either endpoint of
    /// an authenticated SIG(0) request's validity interval.
    ///
    /// The default is five minutes. This also bounds how long a replay-cache
    /// entry can be retained after a request is accepted.
    pub sig0_validity_window: std::time::Duration,
    /// Maximum retained per-zone changes usable for IXFR.
    ///
    /// Zero disables incremental history; IXFR can still use an AXFR-format
    /// fallback over an authorized stream transport.
    pub max_ixfr_history: usize,
}

impl Default for NameServerConfig {
    fn default() -> Self {
        Self {
            allow_axfr_to: Vec::new(),
            update_persistence: None,
            update_rules: Vec::new(),
            allow_insecure_updates: false,
            notify: None,
            tsig_keys: Vec::new(),
            sig0_keys: Vec::new(),
            sig0_validity_window: std::time::Duration::from_secs(300),
            max_ixfr_history: 0,
        }
    }
}

/// An error returned while durably storing an updated zone snapshot.
pub type UpdatePersistenceError = Box<dyn Error + Send + Sync + 'static>;

/// Persists dynamic zone updates before they become visible or acknowledged.
pub trait UpdatePersistence: fmt::Debug + Send + Sync {
    /// Commits `zone` to nonvolatile storage.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot was not durably committed.
    fn persist<'future>(
        &'future self,
        zone: &'future Zone,
    ) -> transport::BoxFuture<'future, Result<(), UpdatePersistenceError>>;
}

/// Stores validated zone snapshots for an authoritative DNS server.
#[derive(Clone)]
pub struct NameServer {
    zones: storage::ZoneStorage,
    config: NameServerConfig,
    notify_sequence: Arc<AtomicU16>,
    notify_tasks: Arc<Mutex<NotifyTasks>>,
    tsig_times: Arc<Mutex<HashMap<crate::name::DnsNameKey, u64>>>,
    sig0_replays: Arc<Mutex<Sig0ReplayCache>>,
    ixfr_history: Arc<Mutex<IxfrHistories>>,
    zone_mutations: Arc<Mutex<ZoneMutationLocks>>,
}

type IxfrHistories = HashMap<(crate::name::DnsNameKey, u16), VecDeque<IxfrDelta>>;
type ZoneMutationLocks = HashMap<(crate::name::DnsNameKey, u16), Arc<Mutex<()>>>;
type NotifyTaskKey = (crate::name::DnsNameKey, u16, SocketAddr);
type NotifyTasks = HashMap<NotifyTaskKey, Option<Message>>;
type Sig0PrincipalReplays = HashMap<Vec<u8>, u32>;
type Sig0ReplayCache = HashMap<crate::name::DnsNameKey, Sig0PrincipalReplays>;

const MAX_SIG0_REPLAYS_PER_PRINCIPAL: usize = 4_096;

fn sig0_time_is_acceptable(
    inception: u32,
    expiration: u32,
    now: u32,
    validity_window: std::time::Duration,
) -> bool {
    let window = u32::try_from(validity_window.as_secs()).unwrap_or(u32::MAX);
    now.wrapping_sub(inception) <= window && expiration.wrapping_sub(now) <= window
}

fn remember_sig0_request(
    replays: &mut Sig0ReplayCache,
    principal: crate::name::DnsNameKey,
    signature: Vec<u8>,
    expiration: u32,
    now: u32,
) -> bool {
    replays.retain(|_, principal_replays| {
        principal_replays.retain(|_, expires| expires.wrapping_sub(now) < (1_u32 << 31));
        !principal_replays.is_empty()
    });
    let principal_replays = replays.entry(principal).or_default();
    if principal_replays.contains_key(&signature)
        || principal_replays.len() >= MAX_SIG0_REPLAYS_PER_PRINCIPAL
    {
        return false;
    }
    principal_replays.insert(signature, expiration);
    true
}

impl Default for NameServer {
    fn default() -> Self {
        Self::with_config(NameServerConfig::default())
    }
}

impl NameServer {
    /// Creates an authoritative server with AXFR disabled.
    pub fn new() -> Self {
        Self::with_config(NameServerConfig::default())
    }

    /// Creates an authoritative server with `config`.
    pub fn with_config(config: NameServerConfig) -> Self {
        Self::with_storage(
            config,
            storage::ZoneStorage::BuiltIn(Arc::new(RwLock::new(ZoneIndex::default()))),
        )
    }

    fn with_storage(config: NameServerConfig, zones: storage::ZoneStorage) -> Self {
        Self {
            zones,
            config,
            notify_sequence: Arc::new(AtomicU16::new(1)),
            notify_tasks: Arc::new(Mutex::new(HashMap::new())),
            tsig_times: Arc::new(Mutex::new(HashMap::new())),
            sig0_replays: Arc::new(Mutex::new(HashMap::new())),
            ixfr_history: Arc::new(Mutex::new(HashMap::new())),
            zone_mutations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Creates a server whose authoritative catalog is supplied by `store`.
    ///
    /// The built-in zone map is not allocated. Storage errors map to SERVFAIL;
    /// immediate synchronous handling falls back to the asynchronous path.
    pub fn with_zone_store(config: NameServerConfig, store: Arc<dyn ZoneStore>) -> Self {
        Self::with_storage(config, storage::ZoneStorage::External(store))
    }

    /// Processes one DNS request without performing transport I/O.
    #[instrument(
        level = "debug",
        skip(self, query),
        fields(transaction_id = query.headers.id, question_count = query.questions.len())
    )]
    pub async fn handle(&self, query: Message) -> Message {
        self.handle_with_identity(query, None).await
    }

    async fn handle_with_identity(
        &self,
        query: Message,
        identity: Option<&UpdateIdentity>,
    ) -> Message {
        if query.edns().ok().flatten().is_some_and(|edns| {
            edns.version != dns::Edns::VERSION && edns.validate_options().is_ok()
        }) {
            return bad_version_response(&query);
        }
        if query.headers.opcode == dns::OpCode::Update {
            return handle_update(self, query, identity).await;
        }
        if query.headers.opcode == dns::OpCode::Notify {
            let rcode = if query.validate_for_forwarding().is_ok() {
                RCode::NotImplemented
            } else {
                RCode::FormatError
            };
            return error_response(&query, rcode);
        }
        if let Some(rcode) = request_error(&query) {
            debug!(?rcode, "DNS request rejected");
            return error_response(&query, rcode);
        }
        let zones = match self.zones.read().await {
            Ok(zones) => zones,
            Err(error) => {
                tracing::warn!(%error, "failed to read authoritative catalog");
                return error_response(&query, RCode::ServerFailure);
            }
        };
        let reply = resolve(&zones, &query);
        log_response(&reply, "DNS request resolved");
        reply
    }

    /// Produces a collected response sequence for a request from `peer`.
    ///
    /// The network-facing [`transport::DnsRequestHandler`] implementation streams
    /// authorized AXFR responses. This collecting API remains available for
    /// callers that explicitly need all messages in memory.
    pub async fn handle_transfer(&self, peer: SocketAddr, query: Message) -> Vec<Message> {
        match self
            .transfer_plan(peer, query, transport::TransportProtocol::Tcp, None)
            .await
        {
            TransferPlan::Single(response) => vec![response],
            TransferPlan::Zone { query, zone } => {
                pack_axfr_responses(&query, zone.transfer_records_iter())
                    .unwrap_or_else(|| vec![error_response(&query, RCode::ServerFailure)])
            }
        }
    }

    async fn transfer_plan(
        &self,
        peer: SocketAddr,
        query: Message,
        protocol: transport::TransportProtocol,
        update_identity: Option<&UpdateIdentity>,
    ) -> TransferPlan {
        let qtype = query.questions.first().map(|question| question.qtype);
        let is_axfr = qtype == Some(dns::QueryType::AXFR);
        let is_ixfr = qtype == Some(dns::QueryType::IXFR);
        if !is_axfr && !is_ixfr {
            return TransferPlan::Single(self.handle_with_identity(query, update_identity).await);
        }
        if query.edns().ok().flatten().is_some_and(|edns| {
            edns.version != dns::Edns::VERSION && edns.validate_options().is_ok()
        }) {
            return TransferPlan::Single(bad_version_response(&query));
        }
        if is_axfr {
            if let Some(rcode) = axfr_request_error(&query) {
                return TransferPlan::Single(error_response(&query, rcode));
            }
        } else if query.validate_for_forwarding().is_err() {
            return TransferPlan::Single(error_response(&query, RCode::FormatError));
        }
        if self.config.allow_axfr_to.is_empty() {
            return TransferPlan::Single(error_response(&query, RCode::NotImplemented));
        }
        if !self
            .config
            .allow_axfr_to
            .iter()
            .any(|&(network, netmask)| address_matches(network, netmask, peer.ip()))
        {
            return TransferPlan::Single(error_response(&query, RCode::Refused));
        }
        let zone = {
            let zones = match self.zones.read().await {
                Ok(zones) => zones,
                Err(_) => {
                    return TransferPlan::Single(error_response(&query, RCode::ServerFailure));
                }
            };
            let Some(zone) = exact_authoritative_zone(&zones, &query.questions[0]) else {
                return TransferPlan::Single(error_response(&query, RCode::NotAuthoritative));
            };
            zone
        };
        if is_ixfr {
            let mut history = self
                .ixfr_history
                .lock()
                .await
                .get(&(dns_name_key(zone.apex()), zone.class().value()))
                .cloned()
                .unwrap_or_default();
            let udp_limit = (protocol == transport::TransportProtocol::Udp).then(|| {
                query
                    .edns()
                    .ok()
                    .flatten()
                    .map_or(usize::from(dns::Edns::MIN_UDP_PAYLOAD_SIZE), |edns| {
                        usize::from(edns.effective_udp_payload_size())
                    })
                    .min(usize::from(dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE))
            });
            match ixfr::answer(&query, &zone, history.make_contiguous(), udp_limit) {
                IxfrAnswer::Current(response) | IxfrAnswer::Incremental(response) => {
                    return TransferPlan::Single(response);
                }
                IxfrAnswer::Full => {}
            }
        }
        TransferPlan::Zone { query, zone }
    }
}

enum TransferPlan {
    Single(Message),
    Zone { query: Message, zone: Arc<Zone> },
}

fn log_response(reply: &Message, message: &'static str) {
    debug!(
        rcode = ?reply.headers.rcode,
        authoritative = reply.headers.aa,
        answer_count = reply.answers.len(),
        authority_count = reply.authorities.len(),
        additional_count = reply.additionals.len(),
        message
    );
}

#[cfg(test)]
mod tests;
