/// Limits a DNS-over-UDP payload without EDNS to 512 octets.
pub const MAX_UDP_MESSAGE_OCTETS: usize = 512;

/// Limits outbound EDNS queries to the implementation's conservative UDP
/// payload policy, avoiding platform-specific datagram limits and excessive
/// IP fragmentation while preserving TCP fallback for larger queries.
#[cfg(feature = "udp")]
pub(crate) const MAX_EDNS_UDP_QUERY_OCTETS: usize = 4096;

/// Limits inbound EDNS UDP datagrams to the DNS message length space.
pub const MAX_EDNS_UDP_MESSAGE_OCTETS: usize = u16::MAX as usize;

/// Limits a DNS-over-TCP payload to the two-octet frame length.
pub const MAX_TCP_MESSAGE_OCTETS: usize = u16::MAX as usize;
