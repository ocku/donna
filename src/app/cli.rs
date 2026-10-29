use super::constants::*;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{ffi::OsString, net::IpAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "donna",
    version,
    about = "DNS queries, iterative resolution, and DNS service",
    after_help = "Examples:\n  donna example.com AAAA\n  donna query example.com -s 1.1.1.1 --json\n  donna resolve example.com --stats\n  donna -c /etc/donna/donna.toml\n  donna serve -c config/donna.toml"
)]
pub struct Cli {
    /// TOML daemon configuration (without a command, starts the daemon)
    #[arg(short = 'c', long, global = true)]
    pub config: Option<PathBuf>,
    /// Enable diagnostic logging on stderr (RUST_LOG overrides this)
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse_from(normalize_args(std::env::args_os().collect()))
    }
}

// Keep the common `donna example.com AAAA` spelling while preserving clap's
// normal subcommands, global flags and help/error handling.
fn normalize_args(mut args: Vec<OsString>) -> Vec<OsString> {
    let mut i = 1;
    let mut has_config = false;

    while i < args.len() {
        let word = args[i].to_string_lossy();
        if matches!(word.as_ref(), "-h" | "--help" | "-V" | "--version") {
            return args;
        }
        if word == "-c" || word == "--config" {
            if i + 1 == args.len() {
                return args;
            }

            has_config = true;
            i += 2;
            continue;
        }
        if word.starts_with("--config=") || (word.starts_with("-c") && word.len() > 2) {
            has_config = true;
            i += 1;
            continue;
        }
        if word == "-v" || word == "--verbose" {
            i += 1;
            continue;
        }
        if !matches!(
            word.as_ref(),
            "query"
                | "resolve"
                | "serve"
                | "check"
                | "check-zone"
                | "config"
                | "completions"
                | "help"
        ) {
            args.insert(i, "query".into());
        }
        return args;
    }
    if has_config {
        args.push("serve".into());
    }
    args
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Query a DNS server (uses /etc/resolv.conf when --server is omitted)
    Query(QueryArgs),
    /// Resolve iteratively from the roots, with local DNSSEC validation
    Resolve(ResolveArgs),
    /// Run the DNS daemon in the foreground
    Serve,
    /// Validate configuration, zones, trust anchors and listener credentials
    Check,
    /// Validate a DNS master file, including $INCLUDE files
    CheckZone { origin: String, file: PathBuf },
    /// Print a documented starter TOML configuration
    Config {
        #[arg(value_enum, default_value = "recursive")]
        role: Role,
    },
    /// Generate shell completions
    Completions { shell: clap_complete::Shell },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Recursive,
    Forward,
    Authoritative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    DnscryptUdp,
    DnscryptTcp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Datagram,
    Stream,
}

impl Protocol {
    pub fn socket_kind(self) -> SocketKind {
        match self {
            Self::Udp | Self::Quic | Self::DnscryptUdp => SocketKind::Datagram,
            Self::Tcp | Self::Tls | Self::Https | Self::DnscryptTcp => SocketKind::Stream,
        }
    }

    pub fn port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => DNS_PORT,
            Self::Tls => transport::DOT_PORT,
            Self::Quic => transport::DOQ_PORT,
            Self::Https => transport::DOH_PORT,
            Self::DnscryptUdp | Self::DnscryptTcp => transport::DNSCRYPT_PORT,
        }
    }
}

#[derive(Debug, Args)]
pub struct QuestionArgs {
    /// Domain to query (or use --reverse / --batch)
    pub name: Option<String>,
    /// Record types; repeat or separate with commas (e.g. A,AAAA,MX,TYPE65)
    #[arg(default_value = "A", value_delimiter = ',')]
    pub types: Vec<dns::QueryType>,
    /// Query class, including `CLASS<number>`
    #[arg(long, default_value = "IN")]
    pub class: dns::QClassType,
    /// Reverse lookup an IPv4 or IPv6 address
    #[arg(short = 'x', long, conflicts_with_all = ["name", "batch"])]
    pub reverse: Option<IpAddr>,
    /// Read one domain per line from a file; - reads stdin
    #[arg(short = 'f', long, conflicts_with = "name")]
    pub batch: Option<PathBuf>,
    /// Emit one JSON object per response
    #[arg(long, conflicts_with = "short")]
    pub json: bool,
    /// Print answer data only
    #[arg(long)]
    pub short: bool,
    /// Overall deadline per question, in seconds
    #[arg(long, default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..=MAX_REQUEST_TIMEOUT_SECS))]
    pub deadline: u64,
}

impl QuestionArgs {
    pub fn output_format(&self) -> super::output::Format {
        if self.json {
            super::output::Format::Json
        } else if self.short {
            super::output::Format::Short
        } else {
            super::output::Format::Text
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct EndpointArgs {
    /// DNS transport
    #[arg(long, value_enum, default_value = "udp")]
    pub protocol: Protocol,
    /// DNS name authenticated by TLS (required for TLS, HTTPS and QUIC)
    #[arg(long)]
    pub tls_name: Option<String>,
    /// Additional trusted CA certificates, PEM encoded
    #[arg(long)]
    pub ca: Option<PathBuf>,
    /// HTTP authority; defaults to TLS name and port
    #[arg(long)]
    pub https_authority: Option<String>,
    /// DNS-over-HTTPS endpoint path
    #[arg(long, default_value = DEFAULT_HTTPS_PATH)]
    pub https_path: String,
    /// Use HTTP GET instead of POST
    #[arg(long)]
    pub https_get: bool,
    /// DNSCrypt provider name
    #[arg(long)]
    pub provider_name: Option<String>,
    /// DNSCrypt provider Ed25519 public key (64 hexadecimal digits)
    #[arg(long)]
    pub provider_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    #[command(flatten)]
    pub question: QuestionArgs,
    /// Server IP, hostname, or socket address; repeat for comparison/failover
    #[arg(short = 's', long)]
    pub server: Vec<String>,
    /// Override the transport's default port
    #[arg(short = 'p', long, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    #[command(flatten)]
    pub endpoint: EndpointArgs,
    /// Per-exchange timeout, in seconds
    #[arg(long, default_value_t = DEFAULT_EXCHANGE_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..=MAX_EXCHANGE_TIMEOUT_SECS))]
    pub timeout: u64,
    /// Attempts per server
    #[arg(long, default_value_t = DEFAULT_ATTEMPTS, value_parser = clap::value_parser!(u8).range(1..=i64::from(MAX_ATTEMPTS)))]
    pub attempts: u8,
    /// Query every configured server
    #[arg(long)]
    pub compare: bool,
    /// Request DNSSEC records (enabled by default; does not locally validate)
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = true, conflicts_with_all = ["no_dnssec", "no_edns"])]
    pub dnssec: bool,
    /// Disable requesting DNSSEC records (clear the DO bit)
    #[arg(long)]
    pub no_dnssec: bool,
    /// Disable upstream DNSSEC checking (CD bit)
    #[arg(long)]
    pub checking_disabled: bool,
    /// Do not request recursion
    #[arg(long)]
    pub no_recurse: bool,
    /// Disable EDNS
    #[arg(long)]
    pub no_edns: bool,
    /// Advertised EDNS UDP payload size
    #[arg(long, default_value_t = DEFAULT_UDP_PAYLOAD_SIZE, value_parser = clap::value_parser!(u16).range(i64::from(MIN_UDP_PAYLOAD_SIZE)..))]
    pub udp_size: u16,
}

#[derive(Debug, Args)]
pub struct ResolveArgs {
    #[command(flatten)]
    pub question: QuestionArgs,
    /// Override root hints with a socket address; repeat for multiple roots
    #[arg(long)]
    pub root: Vec<std::net::SocketAddr>,
    /// DNSKEY master file to use instead of the bundled root anchors
    #[arg(long)]
    pub trust_anchors: Option<PathBuf>,
    /// Disable local DNSSEC validation
    #[arg(long, conflicts_with = "trust_anchors")]
    pub no_validate: bool,
    /// Show each iterative DNS exchange on stderr
    #[arg(long)]
    pub trace: bool,
    /// Print resolution and cache statistics on stderr
    #[arg(long)]
    pub stats: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_and_global_configuration() {
        for (input, expected) in [
            (vec!["donna", "example.com", "AAAA"], "query"),
            (vec!["donna", "-c", "dns.toml"], "serve"),
            (vec!["donna", "-cdns.toml"], "serve"),
            (vec!["donna", "--config=dns.toml"], "serve"),
            (vec!["donna", "-v", "example.com"], "query"),
        ] {
            let args = normalize_args(input.into_iter().map(Into::into).collect());
            assert!(args.iter().any(|a| a == expected));
            Cli::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn command_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
