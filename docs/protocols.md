# Protocol and security scope

This inventory distinguishes data-model support, executable service behavior,
and operational automation. The [coverage matrix](../examples/interop/docs/coverage.md)
maps checks to requirements and records gaps. Passing the test corpus does not
establish complete RFC compliance.

## DNS data

Typed records include A, AAAA, NS, SOA, CNAME, DNAME, PTR, MX, TXT, SRV, CAA,
TLSA, SMIMEA, CSYNC, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, OPT, TSIG,
legacy SIG/KEY, MD/MF/MB/MG/MR, HINFO, MINFO, NULL and WKS. Other types retain
opaque RDATA through `RData::Unknown`; querying `TYPE65` does not imply a typed
SVCB/HTTPS implementation. Master files support generic RFC 3597 RDATA.

Authoritative processing includes wildcards, empty nonterminals, aliases,
delegation cuts, glue, negative SOA lifetime handling, DNSSEC denial selection,
and longest matching zone selection. The [BIND-derived behavior corpus](../tests/behaviour/README.md)
and [upstream semantics notes](../examples/interop/docs/upstream-semantics.md)
provide executable examples and peer differences.

## Network protocols

| Protocol | Client and listener scope |
| --- | --- |
| UDP | EDNS-aware sizing, query/response correlation, whole-RRset truncation and required TCP fallback. Plain DNS defaults to port 53. |
| TCP | Two-byte framing, reusable connections, pipelining and bounded AXFR series. |
| DNS over TLS | TLS 1.3, explicit server identity, `dot` ALPN policy, reusable sessions; library XoT and optional mTLS verification hooks. |
| DNS over HTTPS | HTTP/2 over TLS 1.3, GET and POST, configured endpoint, bounded bodies, DNS TTL/HTTP Age handling. HTTP/3 is not implemented. |
| DNS over QUIC | TLS 1.3, `doq` ALPN, one transaction per bidirectional stream, length framing and wire ID zero. QUIC port 53 and early data are rejected. |
| DNSCrypt | Version 2 certificate verification, X25519-based encryption, UDP/TCP and authenticated TCP fallback. Certificate/key lifecycle is external. |

Client-facing encryption does not select the upstream protocol. The daemon's
iterative resolver uses UDP/TCP; its forwarder can use any listed client
transport. Transfers are bounded operations with series checks and separate
authorization, rather than arbitrary sequences of ordinary answers. The CLI
exposes an AXFR client. The daemon also handles IXFR with current-SOA or
AXFR-format fallback responses; retaining incremental history requires the
nameserver library configuration. See the [transport reference](../crates/transport/README.md)
for exact framing, handshake, connection and allocation limits.

## DNSSEC and transaction authentication

Current cryptographic DNSSEC verification supports algorithms 5 and 7
(RSA/SHA-1), 8 (RSA/SHA-256), 10 (RSA/SHA-512), and 13 (ECDSA P-256/SHA-256).
DS digest types 1, 2 and 4 use SHA-1, SHA-256 and SHA-384. This list comes from
[`supports_dnssec_algorithm` and `supports_ds_digest`](../crates/dns/src/protocol/dnssec/mod.rs).
Ed25519 DNSSEC algorithm 15 and ECDSA P-384 algorithm 14 are not supported by
that verifier. Ed25519 use in SIG(0) or DNSCrypt does not change this list.
Unsupported-algorithm chain handling follows resolver security policy; do not
interpret unsupported cryptography as a validated signature.

The DNS library exposes RSA and ECDSA P-256 signing primitives, authenticated
RRsets and DNSKEY sets, DS authentication and NSEC/NSEC3 denial checks. These
are building blocks; the daemon serves externally signed zones and does not
schedule signing or key rollover. Local iterative validation bounds NSEC3 work
and limits authenticated cache lifetime by evidence and signature validity.
Full aggressive NSEC synthesis (RFC 8198) remains separate work.

TSIG includes HMAC algorithms and stream authentication. SIG(0) uses Ed25519
keys with time/replay checks in the nameserver. Secure updates require explicit
default-deny grants and durable publication. The CLI does not configure those
keys or sign outgoing updates/transfers. Library examples use public fixture
credentials; they establish interoperability, not a credential provisioning
system.

DO requests DNSSEC records, CD asks a recursive peer to disable checking, and
AD reports authenticated data under the responder's policy. These bits have
different meanings. `query` trusts an upstream answer; `resolve` validates
locally. Forwarding similarly trusts configured upstream validation rather
than building an independent chain of trust.

## Discovery and session protocols

The `dns` crate exports mDNS packet, registration, duplicate-question and cache
types; DNS-SD service/type/TXT parsing; LLQ client state; DSO session and TLV
handling; and DNS Push subscription/update types. These are in-memory protocol
components. An application supplies socket scope, multicast membership,
hop-limit handling, timers, discovery policy and service lifecycle. The shipped
daemon does not replace Avahi or Bonjour.

## Verification boundaries

Bounds exist at multiple layers: wire lengths and section counts, listener
admission, stream connection and handshake limits, resolver work budgets,
deadlines, cache retention and cryptographic work limits. An application-level
`max_inflight` setting is not a global bound on every buffer or cache. Capacity
must be evaluated with the complete transport and backend configuration.

The [validation guide](development.md) distinguishes local regressions,
independent peers, native harness checks and optional public DNS tests. Security
or protocol claims should cite the corresponding check and its tested scope.
