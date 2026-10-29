# Roles and deployment boundaries

Donna consists of a command line application and four Rust libraries. The daemon
selects one resolution policy and can serve local authoritative zones alongside
that policy. Libraries expose additional building blocks for applications that
own storage, authentication, or service discovery.

| Role | Shipped interface | Behavior and boundary |
| --- | --- | --- |
| Diagnostic DNS client | `donna query`, or `donna NAME TYPE` | Explicit or system resolver, multiple types, reverse queries, batch input, server comparison, text or JSON Lines output. |
| Iterative diagnostic client | `donna resolve` | Starts at root hints, follows referrals, validates DNSSEC locally, exposes exchange traces and cache statistics. |
| Caching recursive resolver | `role = "recursive"` | Iterates over UDP with required TCP fallback; maintains answer, delegation, key, negative, BAD and terminal failure caches. |
| Caching forwarder | `role = "forward"` | Uses ordered upstreams over any supported client transport; caches complete eligible responses and suppresses repeated failures. Trusts upstream validation. |
| Primary authoritative server | `role = "authoritative"` | Loads master files, answers for multiple zones, serves pre-signed NSEC/NSEC3 zones, and permits transfers only to configured networks. |
| Resolver with local authoritative zones | `recursive` or `forward`, plus `[[zones]]` | Chooses local zone service for names beneath a configured apex; otherwise applies the selected resolution policy and recursion ACL. |
| Encrypted DNS endpoint | `[[listen]]` | TLS, HTTP/2 HTTPS, QUIC, and DNSCrypt UDP/TCP listeners can serve each daemon role. Credentials are supplied by the operator. |
| Encrypted forwarding gateway | `forward`, plus encrypted `[[upstream]]` | Client-facing and upstream protocols are independent. A UDP client can use a TLS upstream, for example. |
| Embedded DNS client or server | `transport` and `DnsRequestHandler` | Application-owned sockets and handlers, explicit resource policies, reusable connections, AXFR streams. |
| Embedded recursive or forwarding resolver | `Resolver`, `RecursiveServer`, `Forwarder` | Retain caches across requests inside an application; supply a custom `Transport` or cache engine. |
| Authenticated dynamic primary | `nameserver` library and [update example](../examples/updates/README.md) | Default-deny TSIG/SIG(0) update grants, durable publication hooks, bounded IXFR history, outbound NOTIFY. No daemon TOML switches for these capabilities. |
| Database-backed authority or resolver | `ZoneStore`, `CacheEngine` | Application provides coherent zone transactions or per-entry cache indexing and eviction. [Redis/PostgreSQL examples](../examples/adapters/remote/README.md) demonstrate both. |
| DNS data and security toolkit | `dns` | Master files, binary codecs, RRsets, DNSSEC validation/signing primitives, TSIG/SIG(0), certificate associations. |
| Service discovery component | `dns` protocol types | mDNS registration/cache state, DNS-SD, LLQ, DSO and DNS Push state machines. Applications supply multicast networking, timers and orchestration. No standalone discovery daemon is shipped. |

## Choosing a role

Use `query` to inspect a known server. Its DO bit requests DNSSEC records; it
does not establish a chain of trust. Use `resolve` when the diagnostic question
requires independent validation and access to authoritative servers is available.

Use a recursive daemon when the host can contact authoritative DNS over UDP and
TCP port 53. Encrypted listeners protect the client-to-Donna path; they do not
encrypt iterative queries to authorities. Use forwarding when a network requires
a designated recursive service or an encrypted upstream connection.

Use authoritative mode for a master-file primary with explicit reloads. The
application does not schedule secondary refresh/expiry, maintain signing keys,
or automatically renew pre-signed zones. Its libraries support constructing a
more specialized primary; that requires an application and durable storage.

Local zones are authoritative boundaries, including negative answers and
delegations. A name missing from a local zone does not fall through to an
upstream resolver. The recursion ACL does not restrict access to local zones.
Clients outside that ACL can still query the authoritative data.

## Capability limits

The daemon has no configured views, RPZ policy language, catalog-zone manager,
automatic RFC 5011 trust-anchor rollover, DNSSEC signing scheduler, secondary
refresh service, metrics HTTP endpoint, or response-rate-limiting policy.
Transport admission limits and resolution failure suppression serve different
purposes from response rate limiting. A library API for one protocol primitive
does not provide the operational machinery of a complete service.

See [configuration](configuration.md), [library architecture](architecture.md),
[protocol scope](protocols.md), and the [service comparison](comparison.md).
