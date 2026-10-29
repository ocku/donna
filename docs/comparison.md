# Comparison with dig, Knot, Hickory and BIND 9

**For production, prefer the established projects below over Donna.** Donna is
vibe coded with AI assistance and is not production ready. Bounded tests and
favorable throughput results do not establish equivalent reliability or field
experience. Large-scale hostile traffic and combined failure conditions remain
unvalidated; generating those workloads would require substantial infrastructure
beyond the current lab. Read the [AI notice](../README.md#ai-notice-and-production-readiness).

Donna combines diagnostic queries, a configurable daemon and independently
usable Rust crates. Its useful differentiators are the common transport layer,
explicit reply ownership, replaceable cache/zone storage, and one binary for
client, recursive, forwarding and authoritative work. Replacing an existing
service depends on its operational responsibilities as well as its query path.
Measured results and reproduction commands are in [benchmarks](benchmarks.md).

Upstream features below were checked on 2026-10-29. Benchmark versions are
recorded separately; distribution build flags can restrict encrypted transports
or cryptography. Knot DNS and Knot Resolver are separate projects and are
compared in their respective roles.

## Query tools

| Operation | Donna | ISC dig |
| --- | --- | --- |
| UDP/TCP, reverse lookup, generic type/class | Yes | Yes |
| Batch input | Domain list with shared types; JSON Lines output | dig batch command format with per-query options |
| TLS and HTTPS | Included in shipped binary; explicit authentication name | Available in modern builds; inspect version and build capabilities |
| QUIC and DNSCrypt | Both clients included | Not exposed by the cited dig interface |
| Local DNSSEC validation | `resolve` iterates and validates | DO/AD inspection in dig; use ISC delv for local validation |
| Iterative trace | `resolve --trace`, with validation by default | `+trace` |
| AXFR / IXFR client | AXFR; no IXFR serial interface | Both |
| TSIG request signing | Library API; no client flag | Key flags supported |
| Output and scripting | Text, short RDATA, JSON Lines, multi-server comparison | Detailed text, short output, extensive wire/debug options |

dig is a mature wire-diagnostic interface with more per-message controls.
Donna's JSON records, shared transport implementation and validating iterative
command are useful for scripts and applications that also run Donna services.
These interfaces are not command-compatible; translate options explicitly.
The [ISC manual](https://bind9.readthedocs.io/en/v9.20.15/manpages.html#dig-dns-lookup-utility)
documents dig and delv, including their distinct validation behavior.

```sh
# Equivalent basic intent; Donna requests DNSSEC records by default.
dig @127.0.0.1 -p 5300 www.example.test A +short
donna query www.example.test A -s 127.0.0.1:5300 --short --no-dnssec

# Trace and validation have different semantics.
dig example.com A +trace
donna resolve example.com A --trace
```

## Server and library roles

“Library” means an API is available but the shipped Donna daemon does not
configure the capability. “External” means an operator or separate application
must supply the lifecycle.

| Capability | Donna daemon | Knot DNS | Knot Resolver | Hickory DNS | BIND 9 named |
| --- | --- | --- | --- | --- | --- |
| Authoritative primary | Yes | Yes | Separate Knot DNS service | Yes | Yes |
| Automatic secondary refresh | External | Yes | Separate Knot DNS service | No primary/refresh settings in cited 0.26.3 daemon schema | Yes |
| Iterative recursive resolver | Yes | No | Yes | Yes, recursor feature | Yes |
| Forwarding cache | Yes | Proxy module is a different role | Yes | Yes | Yes |
| DNSSEC validation | Iterative mode | Authoritative data validation is a different role | Yes | Yes | Yes |
| Forwarded-answer local validation | No; upstream judgment | Not a recursive resolver | Yes by default | Resolver feature/configuration dependent | Yes with validation enabled |
| Serve pre-signed NSEC/NSEC3 | Yes | Yes | Not an authoritative primary | Yes | Yes |
| Automatic DNSSEC signing/key lifecycle | External; signing primitives in library | Signing and rollover policy | Not an authoritative signer | Online signing; inspect key lifecycle requirements | Signing and key policy |
| AXFR / IXFR serving | AXFR; IXFR fallback; library delta history | Both | Not an authoritative primary | AXFR policy; incremental history not established by this comparison | Both |
| Authenticated durable updates / NOTIFY | Library application | Configured server features | Not an authoritative primary | SQLite update store; NOTIFY workflow not assessed here | Configured server features |
| Views / RPZ / catalog management | No daemon interfaces | Authority modules/catalog support | Resolver policy modules | Server handlers/blocklists; not configuration compatible | Configured views, RPZ and catalogs |
| Custom Rust cache/zone storage | Public `CacheEngine` / `ZoneStore` | Different extension/module APIs | Different extension/module APIs | Rust libraries and server stores | Different extension APIs |

Knot DNS supplies primary/secondary operation, transfers, updates, automatic
signing, catalogs and authority modules. Its operational surface covers zone
management that Donna currently delegates to an application or external process.
See the [Knot DNS manual](https://www.knot-dns.cz/docs/latest/html/) and
[configuration reference](https://www.knot-dns.cz/docs/latest/html/reference.html).

Knot Resolver validates and caches iterative and forwarded answers, with
separate upstream and downstream protocol configuration. Donna's forwarding
mode differs materially because it trusts the upstream validator. See
[Knot Resolver networking](https://knot.pages.nic.cz/knot-resolver/config-network.html)
and [forwarding policy](https://www.knot-resolver.cz/documentation/v6.1.0/config-forward.html).

Hickory has Rust protocol, client, resolver and server libraries, including
recursive validation, NSEC/NSEC3, online signing, and feature-selected encrypted
transports. Its project documents HTTP/3, which Donna does not implement.
Hickory therefore has substantial overlap with Donna's embedding use cases.
See the [project's feature overview](https://hickory-dns.org/) and
[0.26 release records](https://github.com/hickory-dns/hickory-dns/releases).
The pinned [daemon schema](https://github.com/hickory-dns/hickory-dns/blob/bd37cafbdd86112a6da32878f8c9bab22e14377e/bin/src/config/mod.rs)
and [SQLite handler](https://github.com/hickory-dns/hickory-dns/blob/bd37cafbdd86112a6da32878f8c9bab22e14377e/crates/server/src/store/sqlite/mod.rs)
support the store-specific qualifications above. A configured `Secondary` zone
type alone does not establish automatic refresh and expiry behavior.

BIND 9 supplies authoritative primary/secondary service and recursive/forwarding
resolution, with views, response policy and signing policy. Its secondary and
key-management workflows are broader than Donna's daemon surface. See
[BIND server configurations](https://bind9.readthedocs.io/en/v9.20.15/chapter3.html),
[RPZ configuration](https://bind9.readthedocs.io/en/stable/reference.html#response-policy-zone-rpz-rewriting),
and [DNSSEC policy](https://bind9.readthedocs.io/en/v9.20.2/reference.html#dnssec-policy-block-definition-and-usage).

## Transport selection

| Service surface | Donna | Relevant peer distinction |
| --- | --- | --- |
| UDP/TCP | Clients and every daemon role | Shared by the compared servers. |
| DoT / HTTP/2 DoH | Clients, listeners and forwarding upstreams | BIND and Knot Resolver expose encrypted service; Hickory enables transports through features. |
| DoQ | Clients, listeners and forwarding upstreams | Knot DNS and Knot Resolver also document DoQ; selected builds and protocol maturity matter. |
| HTTP/3 DoH | No | Hickory documents support. |
| DNSCrypt v2 | Clients, listeners and forwarding upstreams | Native Donna interface; no equivalent was used in the peer measurements. |
| Encrypted iterative authority queries | Daemon uses UDP/TCP iteration | An encrypted client listener alone says nothing about upstream iteration. |

Knot Resolver documents DoQ as beta in the cited
[encrypted protocol reference](https://knot.pages.nic.cz/knot-resolver/config-network-server-tls.html).
Avoid treating a feature's presence as identical deployment maturity or identical
behavior across these projects. The measured Hickory image enables plain DNS,
recursion and DNSSEC, not every encrypted feature listed by the project.

## Replacement decisions

Use dig for diagnostics, BIND 9 or Knot DNS for production authoritative
service, and BIND 9 or Knot Resolver for production recursive service. Prefer
Hickory over Donna when its Rust libraries meet the application's requirements.
Donna's measured performance is not a reason to assume comparable reliability
or replace an established production deployment.

For controlled experimentation, Donna can cover ordinary dig queries,
JSON-oriented DNS scripts, a local recursive cache, an encrypted forwarding
gateway, and a master-file primary.
Its libraries are particularly relevant when DNS must participate in an
application-owned storage or authentication model. Those are concrete reasons
to investigate its design and APIs, without treating that overlap as evidence
of production readiness.

Retain or explicitly implement the missing workflow before migrating automatic
secondaries, scheduled signing/rollover, views/RPZ, catalog operations, or TSIG
client scripts. Also inventory DNSSEC algorithms: Donna's current verifier
supports 5, 7, 8, 10 and 13, with the limitations described in
[protocol scope](protocols.md). A shared feature name is insufficient evidence
that a production configuration can be translated without behavior changes.

The [benchmarks](benchmarks.md) compare the relevant execution roles. CLI process
time, authoritative throughput and recursive cache-hit throughput answer different
questions and should not be combined into one service ranking.
