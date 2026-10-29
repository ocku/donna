use std::net::Ipv6Addr;

use crate::wire::{Encoder, FromWire, IntoWire, WireError};
use crate::{
    Caa, CertificateAssociation, ClassType, Csync, DomainName, Nsec3, Nsec3param, RData,
    RecordType, ResourceRecord, Tsig, TsigAlgorithm, TsigErrorCode, TypeBitmap,
};

mod caa;
mod csync_tsig_and_certificates;
/// RFC 3596 §2.2: an AAAA RDATA value is exactly 128 bits in network
/// byte order.
mod standard_and_unknown;
