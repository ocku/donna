# Donna

## AI notice and production readiness

Donna is vibe coded with AI assistance. **Do not treat it as production ready.**
Its tests and benchmarks cover bounded laboratory scenarios. It has not been
validated under sustained, large-scale hostile traffic and combined failure
conditions, which would require substantial traffic-generation infrastructure
beyond the current setup.

Higher throughput than some implementations on selected benchmarks does not
establish comparable reliability, security, or operational maturity. Donna
should not be trusted to be as reliable or battle tested as the established
projects it is compared with.

**For production, use those projects over Donna:** BIND 9 or Knot DNS for
authoritative service, BIND 9 or Knot Resolver for recursive service, dig for
diagnostics, and Hickory when its Rust libraries fit the application. Donna is
an experimental project for learning, investigation, and controlled evaluation.

Donna and its libraries are deliberately not published on crates.io. I do not
want to fill Cargo's package registry with AI-generated slop; that is not the
vision I have for this project. Build from this repository if you want to
experiment with it.

## Overview

Donna is a DNS client, validating recursive resolver, caching forwarder, and
authoritative server written in Rust. One binary provides diagnostic queries
and foreground DNS service over UDP, TCP, TLS, HTTP/2 HTTPS, QUIC, and DNSCrypt.
Four reusable crates expose the DNS model, transports, resolver, and nameserver
independently.

For experimentation, it can serve as a local recursive cache, an encrypted
forwarding gateway, a master-file primary, or an embedded DNS service with
application-owned storage.
The daemon serves pre-signed zones; authenticated updates, NOTIFY, incremental
history, and custom stores are library capabilities requiring application
configuration. Automatic secondary refresh and signing/key rollover are
external responsibilities.

## Documentation

| Subject | Reference |
| --- | --- |
| Roles and supported deployment models | [Roles](docs/roles.md) |
| Commands, query controls, JSON output and diagnostics | [Client reference](docs/client.md) |
| Every daemon setting, working configurations, lifecycle and troubleshooting | [Configuration and operation](docs/configuration.md) |
| Container client and forwarding, recursive and authoritative servers | [Docker images](packaging/docker/README.md) |
| Domain blocking with a local UDP/TCP listener and Quad9 DoQ upstreams | [Ad blocker example](examples/adblock/README.md) |
| Crate boundaries, embedding, cache engines and zone publication | [Architecture](docs/architecture.md) |
| Records, transports, cryptographic algorithms and discovery components | [Protocol scope](docs/protocols.md) |
| Features and migration tradeoffs against dig, Knot DNS, Knot Resolver, Hickory and BIND 9 | [Comparison](docs/comparison.md) |
| Measured CLI, authoritative and recursive performance with reproducible evidence | [Benchmarks](docs/benchmarks.md) |
| Repository map, builds, tests and interoperability | [Development](docs/development.md) |

Build with `cargo build --locked --release --bin donna`. For a first local
server, run `target/release/donna serve -c examples/authority/donna.toml`, then
query it with `target/release/donna www.example.test -s 127.0.0.1:5300`.

## Crate boundaries

Each crate owns one layer and depends only on lower layers.

| Package | Responsibility | Runtime workspace dependencies |
| --- | --- | --- |
| `dns` | Defines DNS data, master files, validation, and wire encoding. | None |
| `transport` | Exchanges and serves DNS over UDP, TCP, TLS, HTTPS, QUIC, and DNSCrypt, including bounded AXFR mechanics. | `dns` |
| `resolver` | Resolves questions iteratively or through recursive peers and manages referrals, retries, and caches. | `dns`, `transport` |
| `nameserver` | Loads authoritative zones and applies authoritative query and AXFR policy. | `dns`, `transport` |
| `donna` | Composes runnable applications and hosts cross-crate integration tests. | `dns`, `nameserver`, `resolver`, `transport` |

Keep shared DNS representation and validation in `dns`. Keep socket and framing code in `transport`. Resolver policy belongs in `resolver`; authoritative zone policy belongs in `nameserver`. The root package contains composition code, not reusable domain logic.

Protocol implementations are opt-in `transport` features (`udp`, `tcp`, `tls`,
`doh`, `doq`, and `dnscrypt`). A client transport and its server listener are
separate capabilities. Each transport owns its protocol-required transitions:
`UdpTransport`, for example, retries over TCP when a query is too large or a
response is truncated.
`TransportRoute` is available only for application policy beyond those
normative transitions, such as choosing a fallback after an I/O failure.
Listeners deliver a stateful `DnsRequest` whose single-use reply capability is
bound to the protocol and connection that accepted it. A recursive server's
outbound route is therefore independent of its client-facing response path.

The root package uses `nameserver` for the authoritative server example and to
exercise the complete local stack in integration tests.

## DNS client and daemon

Build the application with `cargo build --release`. `donna --help` and each
subcommand's `--help` describe the complete command line. The binary supports
UDP, TCP, TLS, HTTP/2 HTTPS, QUIC, and DNSCrypt over UDP or TCP.

```sh
# Query the system's configured resolver, with readable record output.
cargo run -- example.com AAAA

# Multiple record types, JSON Lines, explicit server and transport.
cargo run -- query example.com A,AAAA,MX -s 1.1.1.1 --json
cargo run -- query example.com --protocol tls -s 1.1.1.1 --tls-name cloudflare-dns.com
cargo run -- query example.com --protocol https -s 1.1.1.1 --tls-name cloudflare-dns.com
cargo run -- query example.test --protocol quic -s 127.0.0.1:8530 --tls-name localhost --ca ca.pem

# Reverse lookup, batch input (one domain per line), and server comparison.
cargo run -- query -x 192.0.2.1 --short
cargo run -- query --batch domains.txt --json
cargo run -- query example.com -s 1.1.1.1 -s 8.8.8.8 --compare

# Iterate from the roots and validate locally, showing each exchange and stats.
cargo run -- resolve example.com --trace --stats

# DNSSEC records are requested by default (DO); opt out with --no-dnssec.
cargo run -- query example.com DNSKEY -s 1.1.1.1
cargo run -- query example.com --no-dnssec -s 1.1.1.1

# Authorized zone transfer, zone validation, and shell completions.
cargo run -- query example.test AXFR --protocol tcp -s 127.0.0.1:5300
cargo run -- check-zone example.test config/example.test.zone
cargo run -- completions zsh > _donna
```

TLS transports require an explicit authentication name and verify certificates
against bundled public CA roots. `--ca` adds PEM roots for private deployments.
`--https-path`, `--https-authority`, and `--https-get` customize HTTPS requests.
DNSCrypt uses `--provider-name` for the full certificate owner name (for example,
`2.dnscrypt-cert.example.test`) and `--provider-key` for its Ed25519 public key
in hexadecimal. `TYPE<number>` and `CLASS<number>` support generic DNS codes.

`--timeout` bounds one exchange, `--attempts` bounds retries per server, and
`--deadline` bounds a whole question. UDP automatically falls back to TCP when
required. `--no-recurse`, `--checking-disabled`, `--no-edns`, and `--udp-size`
control query flags and EDNS. Queries set the DNSSEC DO bit by default;
`--no-dnssec` clears it, and `--no-edns` omits EDNS entirely. Ordinary queries
rely on the upstream resolver for validation; `resolve` validates locally. Diagnostics and `--trace`/`--stats` go to stderr;
`--json` writes one object per DNS response to stdout. NXDOMAIN and NODATA are
successful DNS exchanges; transport failures, SERVFAIL and REFUSED exit nonzero.

### Daemon configuration

The daemon runs in the foreground so the service manager owns its lifecycle.
Both spellings below load the same TOML configuration:

```sh
donna serve -c /etc/donna/donna.toml
donna -c /etc/donna/donna.toml
```

The default path is `/etc/donna/donna.toml`. Use the commented
[starter configuration](config/donna.toml), or generate a role-specific one:

```sh
donna config recursive > donna.toml
donna config forward > forward.toml
donna config authoritative > authoritative.toml
donna check -c donna.toml
```

`recursive` iterates from configured roots with local DNSSEC validation and the
library's positive, negative, delegation, DNSKEY and failure caches. Validation
uses the bundled root DNSKEYs, or an explicit `resolver.trust_anchors` master
file. Operators maintain these anchors; automatic RFC 5011 rollover is not
configured by this application. `resolver.validate = false` disables validation.

`forward` sends RD queries to ordered `[[upstream]]` endpoints, supports all
client transports, and fails over on transport errors, SERVFAIL and REFUSED.
It suppresses repeated terminal failures with the resolver library's failure
cache and caches complete positive and SOA-backed negative responses until their
shortest retained TTL, bounded by the configured TTL limits. Requests with EDNS
options bypass that cache. Forwarding trusts the configured upstream's DNSSEC
judgment; `resolver.validate` controls local iterative validation only.

`authoritative` serves one or more `[[zones]]` loaded from DNS master files,
including `$INCLUDE`, wildcards, delegations, and pre-signed DNSSEC zones.
Recursive and forward modes can also serve local zones. Local authoritative
answers are public; `[access].recursion` independently restricts recursion and
forwarding to explicit CIDRs, defaulting to loopback. Transfers are denied
unless `[authority].allow_transfer` grants the client's network access.

All relative file paths resolve from the configuration file's directory.
Configuration rejects unknown fields, invalid limits, duplicate zones and
duplicate sockets. Each `[[listen]]` selects its protocol and address; TLS,
HTTPS and QUIC require PEM `certificate` and `private_key` paths. UDP requires
an explicit local IP address to preserve the response's source address.
DNSCrypt listeners require `provider_name`, `provider_key`,
`dnscrypt_certificate` (signed binary certificate), and `dnscrypt_secret_key`
(a file containing the hexadecimal X25519 secret). Certificate generation and
renewal remain operator responsibilities.

`donna check -c FILE` loads zones, anchors, and credentials without binding
sockets. SIGHUP validates a replacement configuration and atomically replaces
zones, resolver settings and ACLs; a rejected reload leaves the current service
running. Successful reloads reset caches. Listener changes and TLS/DNSCrypt
credential renewal require a restart. SIGINT and SIGTERM stop the service.
`max_inflight` and `request_timeout_secs` bound outstanding resolution work.
Set `RUST_LOG=info` with `log_queries = true` for query logs.

The application currently provides primary master-file zones, ordinary queries,
and AXFR clients. Automatic secondary refresh, configured durable dynamic
updates, client TSIG signing, and IXFR clients remain outside this CLI surface.
The underlying libraries expose additional APIs for these applications.

### Linux services

The [systemd unit](packaging/systemd/donna.service) uses a dedicated account and
grants permission to bind DNS ports. Install on a systemd host:

```sh
sudo install -m 0755 target/release/donna /usr/local/bin/donna
sudo install -m 0644 packaging/systemd/donna.sysusers /usr/lib/sysusers.d/donna.conf
sudo systemd-sysusers /usr/lib/sysusers.d/donna.conf
sudo install -d -m 0750 -o root -g donna /etc/donna
sudo install -m 0640 -o root -g donna config/donna.toml /etc/donna/donna.toml
sudo install -m 0644 packaging/systemd/donna.service /etc/systemd/system/donna.service
sudo systemctl daemon-reload
sudo systemctl enable --now donna
sudo systemctl reload donna
```

The [OpenRC script](packaging/openrc/donna) runs as `donna:donna` and validates
configuration before starting or reloading. For Alpine Linux:

```sh
sudo addgroup -S donna
sudo adduser -S -D -H -G donna donna
sudo install -m 0755 target/release/donna /usr/local/bin/donna
# libcap's setcap grants the dedicated account access to ports below 1024.
sudo setcap cap_net_bind_service=+ep /usr/local/bin/donna
sudo install -d -m 0750 -o root -g donna /etc/donna
sudo install -m 0640 -o root -g donna config/donna.toml /etc/donna/donna.toml
sudo install -m 0755 packaging/openrc/donna /etc/init.d/donna
sudo install -m 0644 packaging/openrc/donna.confd /etc/conf.d/donna
sudo rc-update add donna default
sudo rc-service donna start
sudo rc-service donna reload
```

Reapply the file capability after replacing the OpenRC binary. Both services
need read access to configured zones and credentials; keep private keys
restricted to root and the `donna` group. Edit the starter configuration before
starting if another DNS service already uses the configured sockets.

## Runnable servers

The [examples index](examples/README.md) starts with independent Rust packages
for authorities, clients, recursive resolution, domain blocking, updates and
storage adapters. Plain UDP/TCP examples run locally without Docker or
certificates. The [ad blocker](examples/adblock/README.md) serves local UDP/TCP
queries, blocks listed names and their subdomains, and forwards allowed queries
to Quad9 over authenticated DNS over QUIC (DoQ). It includes a Docker image with
a bundled domain list and requires outbound UDP port 853.

The [interoperability lab](examples/interop/README.md) adds independent peers for
all supported transports. Run it from the repository root:

```sh
python3 examples/interop/run.py
```

## Replaceable cache algorithms

`Resolver::new` keeps the synchronous native caches. Applications can select a
technology-neutral per-entry `CacheEngine` with `Resolver::with_cache_engine` and
`CacheEngineConfig`. The provider owns indexed lookup, admission, retention and
eviction for positive/negative answers, delegations, authenticated DNSKEYs, BAD
state and terminal failures. Core keeps DNS coherence, sealed provenance and
original expiry checks. Targeted consistent readsets and atomic mutations avoid
serializing the whole cache; custom entry views construct no native indexes or
mandatory native eviction policy. A nonzero native capacity does not limit the
provider's retained population; zero disables all engine I/O.

The provider must preserve complete read predicates and non-reusable atomic
namespace revisions, including missing-key/family conflicts. Entry MACs do not
prove backend non-rollback, and persistent cross-host expiry requires a trusted,
sufficiently synchronized wall clock. A provider may choose no storage, but
applications requiring RFC 9520 stateful failure suppression must retain its
BAD/failure history. No hidden native cache compensates for discarded entries.
Optional denial-range hints can be unsupported; full RFC 8198 synthesis remains
separate work.

Database clients belong in the application layer; the
[remote adapter example](examples/adapters/remote/README.md) keeps Redis/PostgreSQL
dependencies outside Donna's core crates.

## Validation

The DNS crate uses `sha2` 0.11.1, whose declared minimum is Rust 1.88.
Linux validation uses Rust 1.99.1.

Reference RFC texts live in [rfcs/](rfcs/). The
[coverage matrix](examples/interop/docs/coverage.md) maps executable checks to
protocol requirements and describes their limits. Library regressions and the
bounded interoperability laboratory provide the current validation evidence.
Performance changes must preserve the tested protocol and security policies.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo clippy --manifest-path examples/interop/Cargo.toml --all-targets -- -D warnings
git diff --check
```

Passing these checks establishes the tested behavior; it does not establish
complete RFC compliance. The [development guide](docs/development.md) also covers
documentation tests, the separate example workspaces, and independent lab checks.

## License

Copyright 2026 ocku. Donna-owned code and documentation are licensed under
[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution and scope.
Vendored Quinn code, RFC reference texts, and other third-party material retain
their original licenses.
