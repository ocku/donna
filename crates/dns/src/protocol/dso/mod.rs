use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use crate::constants::MAX_TTL;
use crate::wire::{
    Decoder, Encoder, WireError, class, decode_name, decode_rdata, encode_rdata, qclass,
    query_type, record_type,
};
use crate::{ClassType, DomainName, Question, RecordType, ResourceRecord};

/// DNS Stateful Operations OPCODE.
pub const DSO_OPCODE: u8 = 6;
/// DSO Keepalive TLV code.
pub const DSO_KEEPALIVE: u16 = 1;
/// DSO Retry Delay TLV code.
pub const DSO_RETRY_DELAY: u16 = 2;
/// DNS Push SUBSCRIBE TLV code.
pub const DNS_PUSH_SUBSCRIBE: u16 = 0x0040;
/// DNS Push update TLV code.
pub const DNS_PUSH_UPDATE: u16 = 0x0041;
/// DNS Push UNSUBSCRIBE TLV code.
pub const DNS_PUSH_UNSUBSCRIBE: u16 = 0x0042;
/// DNS Push RECONFIRM TLV code.
pub const DNS_PUSH_RECONFIRM: u16 = 0x0043;

mod error;
mod message;
mod push;
mod session;
mod subscriptions;
mod tlv;

pub use error::DsoError;
pub use message::DsoMessage;
pub use push::{
    PushChange, parse_push_reconfirm, parse_push_subscribe, parse_push_unsubscribe,
    parse_push_update, push_reconfirm_tlv, push_subscribe_tlv, push_unsubscribe_tlv,
    push_update_tlv,
};
pub use session::{DsoEndpoint, DsoSession, DsoSessionAction};
pub use subscriptions::DnsPushSubscriptions;
#[cfg(test)]
use subscriptions::same_question;
pub use tlv::DsoTlv;

#[cfg(test)]
mod tests;
