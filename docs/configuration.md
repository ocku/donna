# Daemon configuration and operation

The daemon reads TOML from `/etc/donna/donna.toml` unless `-c FILE` selects
another file. Relative paths resolve from the canonical configuration file's
directory. Unknown keys fail validation. The [commented starter](../config/donna.toml)
and `donna config ROLE` expose the same defaults.

## Root settings

| Key | Default | Meaning |
| --- | --- | --- |
| `role` | `"recursive"` | `recursive`, `forward`, or `authoritative`. |
| `max_inflight` | `1024` | Admission limit for asynchronous handler work, range 1 to 1000000. Immediate answer paths have separate transport admission. |
| `request_timeout_secs` | `30` | Resolution deadline, range 1 to 86400. |
| `log_queries` | `false` | Query logging through tracing; use `RUST_LOG=info`. Enabling logs also bypasses immediate handling paths. |
| `listen` | UDP and TCP `127.0.0.1:53` | Replaced by explicit `[[listen]]` entries. At least one required. |
| `upstream` | empty | Required for forwarding; rejected in other roles. |
| `zones` | empty | Required for authoritative mode; permitted in every mode. |

Duplicate address/socket-kind pairs are rejected by configuration validation.
Wildcard/address overlaps can also fail when sockets bind. UDP and TCP may
share a numeric port. Plain UDP and DNSCrypt UDP listeners need a concrete
local IP; TCP, TLS, HTTPS, QUIC and DNSCrypt TCP listeners can use wildcard
addresses. QUIC listeners and upstreams must not use port 53. Listener
addresses and upstream addresses are socket addresses with explicit ports.

## Resolution settings

| `[resolver]` key | Default | Scope |
| --- | --- | --- |
| `root_servers` | built-in 13 IPv4 root addresses | Bootstrap for iteration; an empty list uses built-in hints. |
| `validate` | `true` | Local iterative DNSSEC validation only. |
| `trust_anchors` | bundled KSK-2017 and KSK-2024 DNSKEYs | Optional replacement master file, DNSKEY records only; requires validation. |
| `timeout_secs` | `5` | Exchange timeout, range 1 to 3600. |
| `edns_udp_payload_size` | `1232` | Iterative EDNS advertisement; minimum 512. |
| `max_steps` | `32` | Bound on iterative transmissions and timeout processing; positive `u16`. |
| `max_attempts_per_server` | `2` | Range 1 to 3. |
| `max_concurrent_queries` | `1` | Positive candidate-server concurrency per iterative round; larger values send redundant work to reduce latency. |
| `max_ttl_secs` | `604800` | Maximum positive/delegation lifetime; also caps negative lifetime. |
| `max_negative_ttl_secs` | `10800` | Negative lifetime ceiling; SOA TTL and SOA.MINIMUM further restrict it. |
| `cache_capacity` | `4096` | Entry capacity of each native iterative cache, not a combined memory or byte limit. Zero disables caching, including failure suppression. |
| `max_bad_ttl_secs` | `30` | Repeated validation-failure lifetime; effective maximum 300 seconds. |
| `failure_ttl_secs` | `1` | Initial terminal failure suppression, effectively 1 to 300 seconds; repeated failures after expiry back off up to 300 seconds. |
| `max_nsec3_iterations` | `150` | Accepted NSEC3 validation work bound. |

Forwarding uses cache capacity, TTL ceilings, exchange timeout, attempt limits
and failure TTL. Iterative root hints, anchors, step/concurrency limits and NSEC3
validation policy do not make forwarding a local DNSSEC validator. A forwarding
response cache retains complete positive responses and SOA-backed negatives
until the shortest retained TTL. Requests carrying EDNS options bypass it.

## Access and authoritative data

`[access].recursion` is a list of CIDRs permitted to use recursion or forwarding;
the default is `["127.0.0.0/8", "::1/128"]`. An empty list denies both to every
client. Local authoritative zones remain queryable outside this list. IPv4-mapped
IPv6 peers are normalized for recursion access checks.

Each `[[zones]]` entry requires `origin` and `file`. Names are compared without
ASCII case sensitivity and duplicate origins are rejected. Master-file parsing
supports `$ORIGIN`, `$TTL`, `$INCLUDE`, relative names, escaped octets, and generic
unknown RDATA. Zone construction performs semantic validation as well as parsing.

`[authority].allow_transfer` lists CIDRs permitted transfer access and defaults to
empty. The daemon retains no IXFR delta history; authorized IXFR requests can
receive the current SOA or an AXFR-format stream fallback. This is a network
grant, not transaction authentication. Daemon configuration does not expose the
library's TSIG/SIG(0) keys, update grants or persistence hooks.

## Working configurations

An authoritative instance on an unprivileged port, using the repository fixture:

```sh
donna check -c examples/authority/donna.toml
donna serve -c examples/authority/donna.toml
# From another terminal:
donna query www.example.test -s 127.0.0.1:5300
```

A complete private forwarding gateway with a local zone:

```toml
role = "forward"

[[listen]]
protocol = "udp"
address = "192.0.2.53:53"
[[listen]]
protocol = "tcp"
address = "192.0.2.53:53"

[access]
recursion = ["192.0.2.0/24"]

[[upstream]]
protocol = "tls"
address = "1.1.1.1:853"
tls_name = "cloudflare-dns.com"

[[zones]]
origin = "example.test."
file = "example.test.zone"
```

Replace the documentation address with an IP assigned to the service host.
Copy [example.test.zone](../config/example.test.zone) beside the configuration.
Upstreams are tried in order, including failover on transport failure, SERVFAIL
and REFUSED. This is one upstream policy for the whole forwarding instance;
there is no per-suffix forwarding table.

An encrypted listener can be added to any role:

```toml
[[listen]]
protocol = "https"
address = "0.0.0.0:443"
certificate = "server-chain.pem"
private_key = "server-key.pem"
https_path = "/dns-query"
```

TLS, HTTPS and QUIC require PEM certificates and private keys. HTTPS alone accepts
`https_path`; it defaults to `/dns-query`. The library has additional certificate
verification and mTLS hooks that are not daemon configuration fields.

DNSCrypt UDP/TCP listeners require these protocol-specific fields:

```toml
[[listen]]
protocol = "dnscrypt-udp"
address = "192.0.2.53:5443"
provider_name = "2.dnscrypt-cert.example.test"
provider_key = "<64 hexadecimal digits of the provider Ed25519 public key>"
dnscrypt_certificate = "certificate.bin"
dnscrypt_secret_key = "resolver-secret.hex"
```

The certificate is signed binary DNSCrypt certificate data. The secret file
contains a hexadecimal X25519 secret, distinct from the provider signing key.
Operators generate and renew these files. Use the same fields with
`protocol = "dnscrypt-tcp"` for the TCP listener.

Each `[[upstream]]` requires `address`. `protocol` defaults to `udp`; TLS-based
protocols require `tls_name`, with optional `ca` for extra PEM roots. HTTPS also
accepts `https_authority`, `https_path`, and `https_get`. DNSCrypt upstreams use
`provider_name` and `provider_key`. Unlike the client command, TOML has no implicit
transport port: write `:853` or `:443` explicitly.

## Lifecycle and deployment

Run `donna check -c FILE` before starting. It loads zones, anchors and credentials
without binding sockets. The daemon stays in the foreground; systemd or OpenRC
owns process restart. See the [installation commands](../README.md#linux-services)
and files in [packaging](../packaging/).

The [Docker images](../packaging/docker/README.md) provide a client and separate
forwarding, recursive and authoritative server targets. The server entrypoint
selects a concrete container address for UDP, validates configuration, and runs
the daemon as PID 1 under an unprivileged account.

On Unix, SIGHUP validates a complete replacement before publication. A rejected
reload retains the active runtime. Successful reloads replace zones, ACLs and
resolver configuration atomically for new requests, resetting caches; in-flight
requests can finish against their prior runtime snapshot. Listener definitions,
including credential paths, must remain unchanged. Replacing certificate file
contents also requires restart to renew active listener credentials. SIGINT and
SIGTERM stop the process.

Trust anchors are operator-maintained. Schedule anchor review independently of
zone reloads; the daemon does not implement RFC 5011 rollover. Pre-signed zones
also need an external signing and renewal process. `check-zone` establishes zone
structure, not continuous signature freshness or automatic signing.

## Diagnosing service behavior

| Symptom | Check |
| --- | --- |
| Configuration rejected | Unknown keys, role requirements, relative paths, duplicate origins and socket overlap; run `check` with the exact file. |
| REFUSED for remote resolution | Client CIDR in `[access].recursion`; authoritative data has independent access semantics. |
| SERVFAIL during iteration | Root reachability over UDP/TCP, clock, trust anchors, signature algorithms, NSEC3/work limits; reproduce with `resolve --trace --stats`. |
| Delayed recovery after upstream repair | Failure/BAD suppression and backoff; waiting for expiry preserves normal recovery behavior, while a successful reload starts cold. |
| TLS handshake failure | Authentication name, certificate chain, custom CA, expiry, protocol port and ALPN. |
| AXFR denied | Transfer CIDR and stream protocol; grants default to empty. |
| High memory usage | Cache capacity is per cache and entry-based; inspect record sizes, connections, in-flight work and custom backend retention. |
| Changed performance with logging | Query logging bypasses immediate reply paths and adds output work. Compare with the same logging configuration. |
