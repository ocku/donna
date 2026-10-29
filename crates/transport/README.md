# `transport`

See the [project architecture](../../docs/architecture.md) for embedding and
feature selection, and [protocol scope](../../docs/protocols.md) for the
client/daemon boundary. This reference details transport invariants and limits.

`transport` is the DNS wire-protocol boundary. It turns semantic `dns::Message`
values into UDP datagrams, length-prefixed streams, HTTPS messages, QUIC
streams, or DNSCrypt packets; correlates replies with requests; and delivers
inbound messages to application handlers. Resolver retry policy and
authoritative answer policy belong in their respective crates.

## Why the implementation has these branches

Several choices that can look arbitrary are protocol invariants:

| Decision | Reason |
| --- | --- |
| UDP payload limits account for EDNS | Classic DNS is limited to 512 octets. Outbound EDNS queries are capped at 4,096 octets, while inbound EDNS datagrams may use the DNS message length space up to 65,535 octets. |
| UDP receives into a 65,536-octet buffer | A 65,535-octet buffer cannot distinguish an exact-size datagram from a larger datagram truncated by `recv`. The extra octet makes oversize detection unambiguous. |
| UDP packet admission is shared across receive workers | Linux uses at most 64 independently registered descriptors for one exclusively bound socket. With multiple workers, nonblocking receive batches hold at most 16 datagrams each and reserve from the same 256-permit budget before receiving. Batch size scales with worker count to cap fixed receive buffers at 64 total (4 MiB), plus per-thread syscall headers. Unsupported or denied batch syscalls fall back to ordinary receives. Single receivers retain one packet waiting for admission. Handler and send deadlines remain bounded, and handler panics are isolated to their packet. |
| UDP sockets are connected before sending | The kernel then filters replies by the exact server IP and port. Transaction-ID matching alone is insufficient. |
| UDP rejects AXFR | RFC 1035 requires zone transfers to use a virtual circuit; RFC 5936 specifies AXFR over TCP. |
| Oversize or truncated UDP exchanges transition to TCP | TCP support for messages that UDP cannot carry intact is required by RFC 1035 and RFC 7766. Timeout and I/O fallback remain application policy. |
| Listener I/O retries are bounded in frequency | Recoverable peer/network errors and temporary Unix descriptor or socket-buffer exhaustion retain the listening socket. Consecutive failures back off from 10 ms to 1 s, and a successful receive or accept resets the delay. Invalid descriptors and configuration errors propagate. This policy covers UDP, TCP, TLS, HTTPS, QUIC and DNSCrypt listeners. |
| TCP messages have a two-octet prefix | RFC 1035 defines that framing, which imposes the 65,535-octet payload ceiling. |
| DoT uses TLS 1.3 and offers `dot` ALPN | The `tls` feature supplies strict authenticated DNS over TLS. Ordinary DoT accepts the IANA `dot` token or no negotiated ALPN, as permitted for RFC 7858 interoperability, but rejects every other token. XoT requires `dot` ALPN. |
| DoT authenticates a configured DNS name | Socket addresses select a route; they are never treated as authentication identities. PKIX roots, operator-supplied SPKI/raw-public-key verifiers, and optional mTLS are supported. |
| TLS sessions, connects, and accepts are bounded | Clients retain at most 64 reusable sessions and admit at most 64 simultaneous connection handshakes. Servers admit at most 256 live connections, bound every handshake, and retain at most 16 pipelined requests per connection. Rustls tickets provide stateless resumption. |
| Padding is applied only inside TLS | EDNS queries are padded to RFC 8467's recommended block size, and a padded request triggers a padded response. Cleartext UDP/TCP retain their prohibition. |
| AXFR can use TLS | `TlsTransport::transfer_with_limits` applies the same framing, correlation, series validation, and cumulative byte/record bounds as cleartext TCP. A separate persistent transfer session is reused per server. XoT servers can require an authorizing client-certificate verifier. |
| DoH uses one configured HTTPS endpoint | `DohClientConfig` keeps the HTTP authority, TLS authentication name, path, and GET/POST preference explicit. GET uses POST at the same endpoint when base64url expansion exceeds the HTTP library's URI limit. The server implements both RFC 8484 mappings over TLS 1.3 and HTTP/2, bounds bodies at 65,535 octets and request headers at 128 KiB, and derives HTTP freshness from DNS TTLs. Clients subtract the HTTP `Age` value from DNS TTLs, including the effective negative lifetime bounded by SOA.MINIMUM, without modifying signed RDATA. |
| DoH and DoQ ignore the EDNS UDP size | Stream padding uses the 65,535-octet DNS message budget, while preserving the original UDP advertisement on the wire. The UDP and DoT padding policies remain independent. |
| Ordinary DoH messages use DNS ID zero | HTTP identifies the transaction, so unsigned requests use ID zero for cache friendliness and the caller's ID is restored on return. Signed TSIG/SIG(0) messages are never rewritten after authentication. |
| DoQ uses one bidirectional stream per transaction | QUIC connections are authenticated with TLS 1.3 and `doq` ALPN. Every stream contains exactly one two-octet-length-prefixed query and its response; on-wire DNS IDs are zero. Port 53, unidirectional streams, early data, and extra messages are rejected. Both peers pad QUIC application datagrams to the current path MTU, protecting signed messages and peers without EDNS as well as EDNS-padded messages. |
| DoQ carries bounded AXFR series | `DoqTransport::transfer_with_limits` keeps a complete transfer on one QUIC stream and reuses the TCP AXFR validator and cumulative limits. Concurrent AXFR and IXFR streams share a connection. Client cancellation, including a dropped exchange future, uses the registered DoQ request-cancelled code and interrupts stalled response producers. A server's STOP_SENDING is a connection-level protocol error. |
| DNSCrypt authenticates before parsing | The classical v2 Box-XChaChaPoly profile verifies Ed25519-signed certificates, rejects low-order X25519 keys and reserved certificate selectors, uses independent CSPRNG nonces without a stable counter prefix, and accepts only authenticated ISO/IEC 7816-4-padded plaintext. Minimal padding is supported when a full block cannot fit. TCP closes after one transaction. UDP never amplifies a response beyond its request; shortening any response section sets `TC` and triggers authenticated TCP fallback while adapting the next padding target. UDP certificate retrieval reserves time for TCP fallback within the original deadline. |
| One deadline covers connect, send, and receive | The caller's timeout bounds the whole exchange, rather than restarting for every I/O operation. |
| Unrelated replies are skipped | DNS responses are correlated by response bit, opcode, transaction ID, and (where required) question. |
| Optional Additional RRSets are removed first | Additional data can be omitted without declaring the core answer truncated. Answer and Authority removal sets `TC`. |
| Records are removed as whole RRSets | RFC 2181 says a non-truncated response must not contain a partial RRSet. |
| AXFR is validated across response messages | Its opening SOA, closing SOA, question placement, zone/class boundaries, and RRSet TTL rules describe one transfer, not independent packets. Buffered handler responses are checked before writing; bounded streams are checked one frame at a time and must end in a valid terminal state. |

The server-side TCP idle timeout is different: it is local resource policy, not
a DNS wire invariant. It is named in the implementation so it cannot be
mistaken for a value mandated by an RFC.

## Request and response ownership

`TransportServer::serve` creates a `DnsRequest` for each accepted request. The
request owns a one-shot response channel tied to that UDP socket, TCP
connection, TLS/QUIC session, HTTP stream, or DNSCrypt exchange. Consuming
`DnsRequest::respond` or `respond_all` therefore makes it impossible for an
application handler to accidentally reply twice or on a different response
path.

For ordinary queries, exactly one response message is accepted. AXFR is the
only current operation that accepts a response series. `respond_all` retains
all-or-nothing series validation, while `respond_stream` accepts a bounded Tokio
channel and validates each AXFR frame before writing it. Dropping the connection
receiver stops the producer.

AXFR clients use finite cumulative payload-byte and observed-record defaults.
`TcpTransport::transfer_with_limits` and `TlsTransport::transfer_with_limits`
allow callers to select larger or smaller `AxfrLimits`; `transfer` uses the
documented defaults.

## Feature flags

- `udp`: DNS over UDP plus its required TCP transition.
- `tcp`: cleartext DNS over TCP and AXFR.
- `tls`: TLS 1.3 DoT/XoT support plus TCP framing. This uses Rustls with the
  `ring` provider; it does not add a general-purpose ASN.1 parser.
- `doh`: authenticated TLS 1.3, HTTP/2, and both RFC 8484 GET and POST
  mappings. It is independent of DNS-over-TCP framing.
- `doq`: authenticated QUIC v1 and DNS over QUIC, including bounded AXFR on a
  single stream. It uses Quinn with Rustls and reuses the TCP frame/transfer
  validators.
- `dnscrypt`: the classical DNSCrypt v2 Box-XChaChaPoly profile over TCP and
  UDP. UDP listeners require a concrete local IP to preserve reply source
  addresses. Post-quantum certificates, tickets, and Anonymized DNSCrypt relay roles
  are outside this feature.

`TlsClientConfig` implements Strict Privacy by default and never silently falls
back to cleartext. An application that explicitly selects Opportunistic Privacy
can compose a `TlsTransport` and a cleartext transport with `TransportRoute`.
That policy choice stays visible to the caller. Raw-public-key deployments use
the custom verifier/resolver constructors and must pin the expected SPKI.
`TlsServerConfig::new` is for ordinary DoT. An XoT primary must use
`TlsServerConfig::with_client_verifier` (or its certificate-resolver variant)
with an authorization verifier; transfer authorization remains authoritative
application policy.

## Source layout

- `lib.rs`: public abstractions, response correlation, header normalization,
  malformed-request replies, and whole-RRSet truncation.
- `udp/`: one-query datagram exchange and independent datagram serving.
- `tcp/`: two-octet framing, connection serving, and ordinary TCP exchanges.
- `tcp/axfr/`: AXFR client/server series validation and transfer assembly.
- `tls/`: TLS 1.3 configuration, authenticated sessions, DoT serving, encrypted
  padding, and XoT client support.
- `doh/`: authenticated HTTP/2 sessions, RFC 8484 request mappings, HTTP cache
  metadata, and DoH serving.
- `doq/`: Quinn configuration, one-transaction streams, cancellation, DoQ
  serving, and AXFR over QUIC.
- `dnscrypt/`: classical certificates, authenticated encryption, TCP and UDP
  clients/listeners, anti-amplification, and authenticated TCP fallback.
- `constants.rs`: public wire-size limits.

The normative text used by this repository is vendored under `../../rfcs/`, in
particular RFC 1035, RFC 2181, RFC 5936, RFC 7301, RFC 7766, RFC 7858,
RFC 8310, RFC 8446, RFC 8484, RFC 9000, RFC 9001, RFC 9103, RFC 9250, and
the vendored DNSCrypt v2 draft.

The workspace carries a small `quinn-proto` 0.11.19 patch under
`../../vendor/quinn-proto/`. It keeps ACK-only packets outside the QUIC MTU
padding policy so their congestion credit cannot block large DNS exchanges.
`README.donna` in that directory records the upstream checksum and patch scope.
