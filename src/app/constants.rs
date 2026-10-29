use std::path::Path;

pub const DNS_PORT: u16 = 53;
pub const DEFAULT_CONFIG_PATH: &str = "/etc/donna/donna.toml";
pub const DEFAULT_HTTPS_PATH: &str = "/dns-query";
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
pub const MAX_REQUEST_TIMEOUT_SECS: u64 = 86_400;
pub const DEFAULT_EXCHANGE_TIMEOUT_SECS: u64 = 5;
pub const MAX_EXCHANGE_TIMEOUT_SECS: u64 = 3_600;
pub const DEFAULT_ATTEMPTS: u8 = 2;
pub const MAX_ATTEMPTS: u8 = 3;
pub const DEFAULT_MAX_INFLIGHT: usize = 1_024;
pub const MAX_INFLIGHT: usize = 1_000_000;
pub const MIN_UDP_PAYLOAD_SIZE: u16 = dns::Edns::MIN_UDP_PAYLOAD_SIZE;
pub const DEFAULT_UDP_PAYLOAD_SIZE: u16 = dns::Edns::RECOMMENDED_UDP_PAYLOAD_SIZE;
pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:53";
pub const HEX_KEY_BYTES: usize = 32;

pub fn default_config_path() -> &'static Path {
    Path::new(DEFAULT_CONFIG_PATH)
}
