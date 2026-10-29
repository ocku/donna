use super::constants::*;
use super::{
    anchors::ROOT_TRUST_ANCHORS,
    cli::{EndpointArgs, Protocol, Role},
};
use anyhow::{Context, Result, bail};
use dns::{DomainName, RecordType, master::MasterFile};
use ipnet::IpNet;
use resolver::ResolverConfig;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub role: Role,
    pub listen: Vec<Listener>,
    pub access: Access,
    pub resolver: ResolverSettings,
    pub upstream: Vec<Upstream>,
    pub zones: Vec<ZoneConfig>,
    pub authority: AuthoritySettings,
    pub max_inflight: usize,
    pub request_timeout_secs: u64,
    pub log_queries: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::Recursive,
            listen: vec![
                Listener::Udp {
                    address: DEFAULT_LISTEN_ADDRESS.parse().unwrap(),
                },
                Listener::Tcp {
                    address: DEFAULT_LISTEN_ADDRESS.parse().unwrap(),
                },
            ],
            access: Access::default(),
            resolver: ResolverSettings::default(),
            upstream: vec![],
            zones: vec![],
            authority: AuthoritySettings::default(),
            max_inflight: DEFAULT_MAX_INFLIGHT,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            log_queries: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Access {
    pub recursion: Vec<IpNet>,
}

impl Default for Access {
    fn default() -> Self {
        Self {
            recursion: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Listener {
    Udp {
        address: SocketAddr,
    },
    Tcp {
        address: SocketAddr,
    },
    Tls {
        address: SocketAddr,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    Https {
        address: SocketAddr,
        certificate: PathBuf,
        private_key: PathBuf,
        #[serde(default = "https_path")]
        https_path: String,
    },
    Quic {
        address: SocketAddr,
        certificate: PathBuf,
        private_key: PathBuf,
    },
    DnscryptUdp {
        address: SocketAddr,
        provider_name: String,
        provider_key: String,
        dnscrypt_certificate: PathBuf,
        dnscrypt_secret_key: PathBuf,
    },
    DnscryptTcp {
        address: SocketAddr,
        provider_name: String,
        provider_key: String,
        dnscrypt_certificate: PathBuf,
        dnscrypt_secret_key: PathBuf,
    },
}

fn https_path() -> String {
    DEFAULT_HTTPS_PATH.into()
}

impl Listener {
    pub fn address(&self) -> SocketAddr {
        match self {
            Self::Udp { address }
            | Self::Tcp { address }
            | Self::Tls { address, .. }
            | Self::Https { address, .. }
            | Self::Quic { address, .. }
            | Self::DnscryptUdp { address, .. }
            | Self::DnscryptTcp { address, .. } => *address,
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            Self::Udp { .. } => Protocol::Udp,
            Self::Tcp { .. } => Protocol::Tcp,
            Self::Tls { .. } => Protocol::Tls,
            Self::Https { .. } => Protocol::Https,
            Self::Quic { .. } => Protocol::Quic,
            Self::DnscryptUdp { .. } => Protocol::DnscryptUdp,
            Self::DnscryptTcp { .. } => Protocol::DnscryptTcp,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    pub origin: String,
    pub file: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthoritySettings {
    pub allow_transfer: Vec<IpNet>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResolverSettings {
    pub root_servers: Vec<SocketAddr>,
    pub validate: bool,
    pub trust_anchors: Option<PathBuf>,
    pub timeout_secs: u64,
    pub edns_udp_payload_size: u16,
    pub max_steps: u16,
    pub max_attempts_per_server: u8,
    pub max_concurrent_queries: usize,
    pub max_ttl_secs: u64,
    pub max_negative_ttl_secs: u64,
    pub cache_capacity: usize,
    pub max_bad_ttl_secs: u64,
    pub failure_ttl_secs: u64,
    pub max_nsec3_iterations: u16,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        let c = ResolverConfig::default();
        Self {
            root_servers: vec![],
            validate: true,
            trust_anchors: None,
            timeout_secs: c.timeout.as_secs(),
            edns_udp_payload_size: c.edns_udp_payload_size,
            max_steps: c.max_steps,
            max_attempts_per_server: c.max_attempts_per_server,
            max_concurrent_queries: c.max_concurrent_queries,
            max_ttl_secs: c.max_ttl.as_secs(),
            max_negative_ttl_secs: c.max_negative_ttl.as_secs(),
            cache_capacity: c.cache_capacity,
            max_bad_ttl_secs: c.max_bad_ttl.as_secs(),
            failure_ttl_secs: c.failure_ttl.as_secs(),
            max_nsec3_iterations: c.max_nsec3_iterations,
        }
    }
}

impl ResolverSettings {
    pub fn build(&self, base: &Path) -> Result<ResolverConfig> {
        if self.timeout_secs == 0
            || self.timeout_secs > MAX_EXCHANGE_TIMEOUT_SECS
            || self.max_steps == 0
            || !(1..=MAX_ATTEMPTS).contains(&self.max_attempts_per_server)
            || self.max_concurrent_queries == 0
            || self.edns_udp_payload_size < MIN_UDP_PAYLOAD_SIZE
        {
            bail!("invalid resolver timeout, work, concurrency, attempt, or EDNS limits");
        }
        if !self.validate && self.trust_anchors.is_some() {
            bail!("trust_anchors requires validate = true");
        }
        let anchors = if self.validate {
            let master = if let Some(path) = &self.trust_anchors {
                MasterFile::from_path(base.join(path), Some(DomainName::root()))?
            } else {
                MasterFile::parse(ROOT_TRUST_ANCHORS, Some(DomainName::root()))?
            };
            if master.records.is_empty()
                || master.records.iter().any(|r| r.rtype != RecordType::DNSKEY)
            {
                bail!("trust anchors must contain one or more DNSKEY records only");
            }
            master.validate_strict()?;
            master.records
        } else {
            vec![]
        };
        Ok(ResolverConfig {
            root_servers: if self.root_servers.is_empty() {
                ResolverConfig::default().root_servers
            } else {
                self.root_servers.clone()
            },
            timeout: Duration::from_secs(self.timeout_secs),
            edns_udp_payload_size: self.edns_udp_payload_size,
            max_steps: self.max_steps,
            max_attempts_per_server: self.max_attempts_per_server,
            max_concurrent_queries: self.max_concurrent_queries,
            max_ttl: Duration::from_secs(self.max_ttl_secs),
            max_negative_ttl: Duration::from_secs(self.max_negative_ttl_secs),
            cache_capacity: self.cache_capacity,
            max_bad_ttl: Duration::from_secs(self.max_bad_ttl_secs),
            failure_ttl: Duration::from_secs(self.failure_ttl_secs),
            trust_anchors: anchors,
            max_nsec3_iterations: self.max_nsec3_iterations,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub address: SocketAddr,
    #[serde(default = "udp")]
    pub protocol: Protocol,
    pub tls_name: Option<String>,
    pub ca: Option<PathBuf>,
    pub https_authority: Option<String>,
    #[serde(default = "https_path")]
    pub https_path: String,
    #[serde(default)]
    pub https_get: bool,
    pub provider_name: Option<String>,
    pub provider_key: Option<String>,
}

fn udp() -> Protocol {
    Protocol::Udp
}

impl Upstream {
    pub fn endpoint(&self, base: &Path) -> EndpointArgs {
        EndpointArgs {
            protocol: self.protocol,
            tls_name: self.tls_name.clone(),
            ca: self.ca.as_ref().map(|p| base.join(p)),
            https_authority: self.https_authority.clone(),
            https_path: self.https_path.clone(),
            https_get: self.https_get,
            provider_name: self.provider_name.clone(),
            provider_key: self.provider_key.clone(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<(Self, PathBuf)> {
        let path = path
            .canonicalize()
            .with_context(|| format!("open configuration {}", path.display()))?;
        let config: Self = toml::from_str(&std::fs::read_to_string(&path)?)
            .with_context(|| format!("parse {}", path.display()))?;
        config.validate()?;
        Ok((config, path.parent().unwrap_or(Path::new(".")).to_owned()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.listen.is_empty() {
            bail!("configure at least one [[listen]] endpoint");
        }
        if self.max_inflight == 0
            || self.max_inflight > MAX_INFLIGHT
            || self.request_timeout_secs == 0
            || self.request_timeout_secs > MAX_REQUEST_TIMEOUT_SECS
        {
            bail!("invalid max_inflight or request_timeout_secs");
        }
        if self.role == Role::Forward && self.upstream.is_empty() {
            bail!("forward role requires at least one [[upstream]]");
        }
        if self.role != Role::Forward && !self.upstream.is_empty() {
            bail!("[[upstream]] requires role = 'forward'");
        }
        if self.role == Role::Authoritative && self.zones.is_empty() {
            bail!("authoritative role requires at least one [[zones]]");
        }
        for (i, listener) in self.listen.iter().enumerate() {
            if matches!(listener.protocol(), Protocol::Udp | Protocol::DnscryptUdp)
                && listener.address().ip().is_unspecified()
            {
                bail!(
                    "UDP listeners require an explicit local IP address to preserve response source addresses"
                );
            }
            if listener.address().port() == 0 {
                bail!("listener port must be nonzero");
            }
            if listener.protocol() == Protocol::Quic && listener.address().port() == 53 {
                bail!("DNS over QUIC listeners must not use port 53");
            }
            if self.listen[..i].iter().any(|other| {
                other.address() == listener.address()
                    && other.protocol().socket_kind() == listener.protocol().socket_kind()
            }) {
                bail!("duplicate listener socket {}", listener.address());
            }
        }
        for (i, zone) in self.zones.iter().enumerate() {
            let name = DomainName::from_dotted(&zone.origin)?;
            if self.zones[..i].iter().any(|other| {
                DomainName::from_dotted(&other.origin).is_ok_and(|other| other.eq_dns(&name))
            }) {
                bail!("duplicate zone {}", zone.origin);
            }
        }
        if self.upstream.iter().any(|u| u.address.port() == 0) {
            bail!("upstream port must be nonzero");
        }
        if self
            .upstream
            .iter()
            .any(|u| u.protocol == Protocol::Quic && u.address.port() == 53)
        {
            bail!("DNS over QUIC upstreams must not use port 53");
        }
        Ok(())
    }
}

pub fn example(role: Role) -> String {
    let mut text = include_str!("../../config/donna.toml").to_owned();
    match role {
        Role::Recursive => {}
        Role::Forward => {
            text = text.replacen("role = \"recursive\"", "role = \"forward\"", 1);
            text.push_str("\n[[upstream]]\naddress = \"1.1.1.1:853\"\nprotocol = \"tls\"\ntls_name = \"cloudflare-dns.com\"\n");
        }
        Role::Authoritative => {
            text = text.replacen("role = \"recursive\"", "role = \"authoritative\"", 1);
            text.push_str(
                "\n[[zones]]\norigin = \"example.test.\"\nfile = \"example.test.zone\"\n",
            );
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn examples_parse_and_unknown_settings_fail() {
        for role in [Role::Recursive, Role::Forward, Role::Authoritative] {
            let config: Config = toml::from_str(&example(role)).unwrap();
            config.validate().unwrap();
        }
        assert!(toml::from_str::<Config>("rol = 'recursive'").is_err());
        assert!(toml::from_str::<Config>("[resolver]\nvalidat = false").is_err());
        let c = ResolverSettings::default().build(Path::new(".")).unwrap();
        assert_eq!(c.trust_anchors.len(), 2);
    }

    #[test]
    fn roles_and_socket_conflicts_are_checked() {
        let mut c = Config {
            role: Role::Forward,
            ..Config::default()
        };
        assert!(c.validate().is_err());
        c.role = Role::Recursive;
        c.listen.push(c.listen[0].clone());
        assert!(c.validate().is_err());
    }

    #[test]
    fn datagram_listeners_require_concrete_addresses_except_quic() {
        for protocol in ["udp", "dnscrypt-udp", "quic"] {
            for address in ["0.0.0.0:853", "[::]:853", "127.0.0.1:853", "[::1]:853"] {
                let credentials = match protocol {
                    "dnscrypt-udp" => {
                        "provider_name = '2.dnscrypt-cert.example.test'\nprovider_key = ''\n\
                         dnscrypt_certificate = 'cert.bin'\ndnscrypt_secret_key = 'key.hex'\n"
                    }
                    "quic" => "certificate = 'cert.pem'\nprivate_key = 'key.pem'\n",
                    _ => "",
                };
                let text = format!(
                    "[[listen]]\nprotocol = '{protocol}'\naddress = '{address}'\n{credentials}"
                );
                let config: Config = toml::from_str(&text).unwrap();
                let wildcard = config.listen[0].address().ip().is_unspecified();
                assert_eq!(
                    config.validate().is_ok(),
                    protocol == "quic" || !wildcard,
                    "{protocol} {address}"
                );
            }
        }
    }

    #[test]
    fn quic_port_53_is_rejected_for_listeners_and_upstreams() {
        for port in [53, 853] {
            let listener = format!(
                "[[listen]]\nprotocol = 'quic'\naddress = '127.0.0.1:{port}'\n\
                 certificate = 'cert.pem'\nprivate_key = 'key.pem'\n"
            );
            let upstream = format!(
                "role = 'forward'\n[[upstream]]\nprotocol = 'quic'\n\
                 address = '127.0.0.1:{port}'\ntls_name = 'localhost'\n"
            );
            for text in [listener, upstream] {
                let config: Config = toml::from_str(&text).unwrap();
                assert_eq!(config.validate().is_ok(), port != 53, "{text}");
            }
        }
    }
}
