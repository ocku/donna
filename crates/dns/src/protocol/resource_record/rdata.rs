use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::{
    Caa, CertificateAssociation, Csync, Dnskey, Ds, EdnsOption, Key, Nsec, Nsec3, Nsec3param,
    Rrsig, Sig, Tsig, message::DomainName,
};

/// Resource-record data for the supported RFC 1034, RFC 1035, RFC 2782, and
/// RFC 3596 RR types.
///
/// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1>
/// RFC 3596: <https://www.rfc-editor.org/rfc/rfc3596#section-2>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RData {
    /// IPv4 host address.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1>
    A(Ipv4Addr),
    /// IPv6 host address.
    /// RFC 3596: <https://www.rfc-editor.org/rfc/rfc3596#section-2.2>
    AAAA(Ipv6Addr),
    /// Canonical name for an alias.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1>
    CNAME(DomainName),
    /// Replacement suffix for descendants of the DNAME owner (RFC 6672 §2.1).
    DNAME(DomainName),
    /// Mail destination host.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.4>
    MD(DomainName),
    /// Mail forwarder host.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.5>
    MF(DomainName),
    /// Mailbox domain name.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.3>
    MB(DomainName),
    /// Mail group member mailbox.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.6>
    MG(DomainName),
    /// Renamed mailbox.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.8>
    MR(DomainName),
    /// Host CPU and operating-system information.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2>
    HINFO {
        /// CPU type character-string octets.
        cpu: Vec<u8>,
        /// Operating-system type character-string octets.
        os: Vec<u8>,
    },
    /// Mailbox or mail-list information.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.7>
    MINFO {
        /// Responsible mailbox.
        rmailbx: DomainName,
        /// Mailbox to receive error messages.
        emailbx: DomainName,
    },
    /// Mail exchange and its preference.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9>
    MX {
        /// Relative preference; lower values are preferred.
        preference: u16,
        /// Host willing to act as the mail exchange.
        exchange: DomainName,
    },
    /// Authoritative name server.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11>
    NS(DomainName),
    /// Opaque data from a NULL resource record.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.10>
    NULL(Vec<u8>),
    /// Well-known services supported by an IPv4 host.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.4.2>
    WKS {
        /// IPv4 address of the host.
        address: Ipv4Addr,
        /// Internet protocol number.
        protocol: u8,
        /// Service-port bitmap octets.
        bitmap: Vec<u8>,
    },
    /// Domain-name pointer.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12>
    PTR(DomainName),
    /// Service location.
    /// RFC 2782: <https://www.rfc-editor.org/rfc/rfc2782#section-2>
    SRV {
        /// Relative priority; lower values are attempted first.
        priority: u16,
        /// Relative selection weight among records with the same priority.
        weight: u16,
        /// TCP or UDP port on the target host.
        port: u16,
        /// Host providing the service, or root when the service is unavailable.
        target: DomainName,
    },
    /// Start of a zone of authority.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13>
    SOA {
        /// Original or primary source name server.
        mname: DomainName,
        /// Responsible mailbox encoded as a domain name.
        rname: DomainName,
        /// Unsigned 32-bit zone version.
        serial: u32,
        /// Unsigned zone refresh interval in seconds.
        refresh: u32,
        /// Unsigned retry interval after a failed refresh, in seconds.
        retry: u32,
        /// Unsigned upper authoritative lifetime, in seconds.
        expire: u32,
        /// Upper bound for the negative-cache TTL, in seconds.
        minimum: u32,
    },
    /// One or more character-strings.
    /// RFC 1035: <https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14>
    TXT(Vec<Vec<u8>>),
    /// DNSSEC signature data. A zero Type Covered value is SIG(0).
    SIG(Sig),
    /// DNSSEC public-key data.
    KEY(Key),
    /// Delegation signer data.
    DS(Ds),
    /// DNSSEC RRSet signature data.
    RRSIG(Rrsig),
    /// Authenticated next-owner and present-type data.
    NSEC(Nsec),
    /// DNSSEC public-key data.
    DNSKEY(Dnskey),
    /// Hashed authenticated denial-of-existence data.
    NSEC3(Nsec3),
    /// NSEC3 chain parameters.
    NSEC3PARAM(Nsec3param),
    /// TLS server certificate association.
    /// RFC 6698: <https://www.rfc-editor.org/rfc/rfc6698#section-2>
    TLSA(CertificateAssociation),
    /// S/MIME certificate association.
    /// RFC 8162: <https://www.rfc-editor.org/rfc/rfc8162#section-2>
    SMIMEA(CertificateAssociation),
    /// Ordered option tuples carried by an EDNS OPT pseudo-record.
    OPT(Vec<EdnsOption>),
    /// Certification Authority Authorization property.
    /// RFC 6844: <https://www.rfc-editor.org/rfc/rfc6844#section-5.1>
    CAA(Caa),
    /// Child-to-parent synchronization request.
    /// RFC 7477: <https://www.rfc-editor.org/rfc/rfc7477#section-2.1>
    CSYNC(Csync),
    /// Transaction Signature authentication data.
    /// RFC 8945: <https://www.rfc-editor.org/rfc/rfc8945#section-4.2>
    TSIG(Tsig),
    /// Opaque RDATA for an RR TYPE not otherwise represented by this
    /// implementation.
    Unknown(Vec<u8>),
}
