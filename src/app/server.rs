use super::{
    cli::Role,
    config::Config,
    listeners::{self, PreparedListener},
    net,
};
use anyhow::{Context, Result, bail};
use dns::{DomainName, Message, RCode, master::MasterFile};
use nameserver::{NameServer, NameServerConfig, Zone};
use resolver::{Forwarder, RecursiveServer, Resolver};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{sync::Semaphore, task::JoinSet};
use transport::*;

pub struct Runtime {
    authority: NameServer,
    origins: Vec<DomainName>,
    resolution: Resolution,
    access: Vec<ipnet::IpNet>,
    inflight: Semaphore,
    timeout: Duration,
    log_queries: bool,
}

enum Resolution {
    Disabled,
    Recursive(RecursiveServer<UdpTransport>),
    Forward(Box<Forwarder<net::Client>>),
}

impl Resolution {
    fn enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn cached(
        &self,
        message: &Message,
        wire: &[u8],
        peer: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<Message> {
        match self {
            Self::Disabled => None,
            Self::Recursive(server) => server.try_handle(message, wire, peer, protocol),
            Self::Forward(server) => server.try_answer_cached(message),
        }
    }

    async fn answer(&self, message: &Message) -> Message {
        match self {
            Self::Disabled => message.error_response(RCode::Refused, false),
            Self::Recursive(server) => server.answer_message(message).await,
            Self::Forward(server) => server.answer_message(message).await,
        }
    }
}

impl Runtime {
    fn local(&self, message: &Message) -> bool {
        message.questions.first().is_some_and(|q| {
            self.origins
                .iter()
                .any(|apex| q.qname.is_descendant_of(apex))
        })
    }

    fn recursive_allowed(&self, peer: SocketAddr) -> bool {
        let ip = match peer.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        self.access.iter().any(|network| network.contains(&ip))
    }

    fn recursive_enabled(&self) -> bool {
        self.resolution.enabled()
    }

    fn deny(&self, message: &Message, peer: SocketAddr) -> Option<Message> {
        if self.recursive_enabled() && !self.local(message) && !self.recursive_allowed(peer) {
            Some(
                message
                    .edns_error_response(false)
                    .unwrap_or_else(|| message.error_response(RCode::Refused, false)),
            )
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub(super) struct Handler(Arc<RwLock<Arc<Runtime>>>);
impl Handler {
    fn snapshot(&self) -> Arc<Runtime> {
        self.0.read().unwrap().clone()
    }
}

impl DnsRequestHandler for Handler {
    fn try_handle(
        &self,
        message: &Message,
        wire: &[u8],
        peer: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<Message> {
        let runtime = self.snapshot();
        if let Some(response) = runtime.deny(message, peer) {
            return Some(response);
        }
        if runtime.log_queries {
            return None;
        }
        if runtime.local(message) || !runtime.recursive_enabled() {
            runtime.authority.try_handle(message, wire, peer, protocol)
        } else {
            runtime.resolution.cached(message, wire, peer, protocol)
        }
    }

    fn try_handle_udp(
        &self,
        message: &Message,
        wire: &[u8],
        peer: SocketAddr,
        maximum: usize,
    ) -> Option<ImmediateUdpResponse> {
        let runtime = self.snapshot();
        if let Some(response) = runtime.deny(message, peer) {
            return Some(ImmediateUdpResponse::Message(response));
        }
        if runtime.log_queries {
            return None;
        }
        if runtime.local(message) || !runtime.recursive_enabled() {
            return runtime
                .authority
                .try_handle_udp(message, wire, peer, maximum);
        }
        match &runtime.resolution {
            Resolution::Recursive(server) => server.try_handle_udp(message, wire, peer, maximum),
            _ => runtime
                .resolution
                .cached(message, wire, peer, TransportProtocol::Udp)
                .map(ImmediateUdpResponse::Message),
        }
    }

    fn handle<'a>(&'a self, request: DnsRequest) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let runtime = self.snapshot();
            if let Some(response) = runtime.deny(request.message(), request.peer()) {
                request.respond(response);
                return;
            }
            let Ok(_permit) = runtime.inflight.try_acquire() else {
                let response = request
                    .message()
                    .error_response(RCode::ServerFailure, runtime.recursive_enabled());
                request.respond(response);
                return;
            };
            if runtime.log_queries {
                tracing::info!(
                    peer = %request.peer(),
                    protocol = ?request.protocol(),
                    question = ?request.message().questions,
                    "DNS query"
                );
            }
            let failure = request
                .message()
                .error_response(RCode::ServerFailure, runtime.recursive_enabled());
            if runtime.local(request.message()) || !runtime.recursive_enabled() {
                DnsRequestHandler::handle(&runtime.authority, request).await;
            } else {
                let response = tokio::time::timeout(
                    runtime.timeout,
                    runtime.resolution.answer(request.message()),
                )
                .await
                .unwrap_or(failure);
                request.respond(response);
            }
        })
    }
}

pub async fn prepare(
    config: &Config,
    base: &Path,
) -> Result<(Arc<Runtime>, Vec<PreparedListener>)> {
    config.validate()?;
    let resolver_config = config.resolver.build(base)?;
    let mut listeners = Vec::new();
    for c in &config.listen {
        listeners.push(
            listeners::prepare(c, base).with_context(|| {
                format!("configure {:?} listener {}", c.protocol(), c.address())
            })?,
        );
    }
    let allow_axfr_to = config
        .authority
        .allow_transfer
        .iter()
        .map(|network| match network {
            ipnet::IpNet::V4(n) => (IpAddr::V4(n.network()), IpAddr::V4(n.netmask())),
            ipnet::IpNet::V6(n) => (IpAddr::V6(n.network()), IpAddr::V6(n.netmask())),
        })
        .collect();
    let authority = NameServer::with_config(NameServerConfig {
        allow_axfr_to,
        ..NameServerConfig::default()
    });
    let mut origins = Vec::new();
    for z in &config.zones {
        let apex = DomainName::from_dotted(&z.origin)?;
        let master = MasterFile::from_path(base.join(&z.file), Some(apex.clone()))
            .with_context(|| format!("load zone {}", z.origin))?;
        authority
            .install(Zone::from_master(apex.clone(), master)?)
            .await?;
        origins.push(apex);
    }
    let runtime = Runtime {
        authority,
        origins,
        resolution: match config.role {
            Role::Authoritative => Resolution::Disabled,
            Role::Recursive => Resolution::Recursive(RecursiveServer::with_resolver(
                Resolver::new(UdpTransport, resolver_config),
            )),
            Role::Forward => {
                let mut upstreams = Vec::new();
                for upstream in &config.upstream {
                    upstreams.push((
                        upstream.address,
                        net::client(&upstream.endpoint(base), upstream.address.port())?,
                    ));
                }
                Resolution::Forward(Box::new(Forwarder::new(
                    upstreams,
                    (&resolver_config).into(),
                )))
            }
        },
        access: config.access.recursion.clone(),
        inflight: Semaphore::new(config.max_inflight),
        timeout: Duration::from_secs(config.request_timeout_secs),
        log_queries: config.log_queries,
    };
    Ok((Arc::new(runtime), listeners))
}

pub async fn serve(path: &Path) -> Result<()> {
    let path = path
        .canonicalize()
        .with_context(|| format!("open configuration {}", path.display()))?;
    let (mut config, base) = Config::load(&path)?;
    let (runtime, listeners) = prepare(&config, &base).await?;
    let handler = Handler(Arc::new(RwLock::new(runtime)));
    let mut tasks = JoinSet::new();
    for listener in listeners {
        listener.start(&mut tasks, handler.clone());
    }
    eprintln!(
        "donna: {:?} service starting ({} listeners, {} local zones)",
        config.role,
        config.listen.len(),
        config.zones.len()
    );
    #[cfg(unix)]
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            result = tasks.join_next() => {
                tasks.abort_all();
                match result {
                    Some(Ok(Err(error))) => return Err(error).context("DNS listener failed"),
                    Some(Err(error)) => return Err(error.into()),
                    _ => bail!("DNS listener stopped unexpectedly"),
                }
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
            _ = async {
                #[cfg(unix)]
                terminate.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => break,
            _ = async {
                #[cfg(unix)]
                reload.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => {
                match reload_config(&path, &config).await {
                    Ok((new_config, runtime)) => {
                        *handler.0.write().unwrap() = runtime;
                        config = new_config;
                        eprintln!("donna: configuration and zones reloaded; caches reset");
                    }
                    Err(error) => {
                        eprintln!("donna: reload rejected; retaining current configuration: {error:#}");
                    }
                }
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    eprintln!("donna: stopped");
    Ok(())
}

async fn reload_config(path: &Path, current: &Config) -> Result<(Config, Arc<Runtime>)> {
    let (config, base) = Config::load(path)?;
    if config.listen != current.listen {
        bail!("listener changes require a restart");
    }
    let (runtime, _) = prepare(&config, &base).await?;
    Ok((config, runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authoritative_zone_and_recursive_acl_are_separate() {
        let c = Config {
            zones: vec![super::super::config::ZoneConfig {
                origin: "example.test".into(),
                file: std::path::PathBuf::from("example.test.zone"),
            }],
            ..Config::default()
        };
        let (r, _) = prepare(&c, Path::new("config")).await.unwrap();
        let q = |n| {
            super::super::client::query(dns::Question {
                qname: DomainName::from_dotted(n).unwrap(),
                qtype: dns::QueryType::A,
                qclass: dns::QClassType::Class(dns::ClassType::IN),
            })
            .unwrap()
        };
        let peer = "192.0.2.10:1234".parse().unwrap();
        assert!(r.deny(&q("example.test"), peer).is_none());
        assert_eq!(
            r.deny(&q("outside.test"), peer).unwrap().headers.rcode,
            RCode::Refused
        );
        assert!(r.recursive_allowed("127.0.0.1:1234".parse().unwrap()));
        assert!(r.recursive_allowed("[::ffff:127.0.0.1]:1234".parse().unwrap()));
        let h = Handler(Arc::new(RwLock::new(r)));
        let q = q("example.test");
        let reply = h.try_handle(&q, &[], peer, TransportProtocol::Udp).unwrap();
        assert!(reply.headers.aa);
        assert_eq!(reply.answers.len(), 1);
    }
}
