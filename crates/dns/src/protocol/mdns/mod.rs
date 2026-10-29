use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use crate::constants::MAX_TTL;
use crate::wire::{
    Decoder, Encoder, WireError, class, decode_mdns_header, decode_name, decode_rdata,
    encode_header, encode_rdata, qclass, query_type, record_type,
};
use crate::{Headers, OpCode, Question, RCode, ResourceRecord, SectionCounts};

/// UDP port assigned to Multicast DNS.
pub const MDNS_PORT: u16 = 5353;
/// IPv4 link-local Multicast DNS group.
pub const MDNS_IPV4_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// IPv6 link-local Multicast DNS group.
pub const MDNS_IPV6_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// Required IP TTL or IPv6 hop limit for received mDNS packets.
pub const MDNS_HOP_LIMIT: u8 = 255;

mod cache;
mod duplicate_questions;
mod error;
mod packet;
mod probe;
mod registration;

pub use cache::MdnsCache;
pub use duplicate_questions::MdnsDuplicateQuestionCache;
pub use error::MdnsError;
pub use packet::{MdnsPacket, MdnsQuestion, MdnsRecord};
pub use probe::{ProbeTieBreak, is_local_name, known_answer_suppresses, probe_tie_break};
pub use registration::{MdnsRegistration, MdnsRegistrationAction, MdnsRegistrationState};

#[cfg(test)]
mod tests;
