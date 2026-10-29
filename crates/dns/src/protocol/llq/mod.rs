use std::{
    fmt,
    time::{Duration, Instant},
};

use crate::constants::MAX_TTL;
use crate::wire::{
    Decoder, Encoder, WireError, class, decode_header, decode_name, decode_question, decode_rdata,
    decode_record, encode_header, encode_question, encode_rdata, encode_record, record_type,
};
use crate::{
    DomainName, DomainNameError, Edns, EdnsOption, Headers, OpCode, QueryType, Question, RCode,
    ResourceRecord, SectionCounts,
};

/// EDNS option code allocated to Apple Long-Lived Queries.
pub const LLQ_OPTION_CODE: u16 = 1;
/// Default UDP port used by LLQ servers.
pub const LLQ_PORT: u16 = 5352;
/// LLQ protocol version documented by RFC 8764.
pub const LLQ_VERSION: u16 = 1;

mod client;
mod error;
mod event;
mod option;

pub use client::{LlqClient, LlqClientStatus};
pub use error::{LlqError, LlqEventAck};
pub use event::{LlqEventChange, LlqEventMessage};
pub use option::{LlqOpcode, LlqOption, LlqResponseCode, llq_service_name};

#[cfg(test)]
mod tests;
