# DNS ad blocker

An application-owned domain policy wrapped around Donna's `Forwarder`. Listed
domains and all their subdomains receive `NXDOMAIN` for every query type, with
EDNS Extended DNS Error 15 (`Blocked`) when the client supports EDNS. Matching
is case insensitive and follows DNS label boundaries. Other queries use the
forwarder's bounded cache and ordered recursive upstreams using DNS over QUIC
(DoQ). By default, it tries Quad9 at `9.9.9.9:853`, then
`149.112.112.112:853` if the first upstream fails. Both use TLS 1.3 and verify
the server certificate for `dns.quad9.net` against bundled Mozilla roots.
Quad9's default service also blocks known malicious domains. See Quad9's
[DoQ announcement](https://quad9.net/news/blog/quad9-enables-dns-over-http-3-and-dns-over-quic/)
and [service addresses](https://docs.quad9.net/services/).

Clients send ordinary DNS over UDP or TCP to this example. Allowed queries
leave over QUIC with the `doq` ALPN protocol; there is no HTTP layer. Upstream
failover stays on DoQ and does not fall back to plaintext DNS. Blocked queries
receive a local answer without contacting either upstream.

The image downloads HaGeZi's [Pop-Up Ads list](https://github.com/hagezi/dns-blocklists/blob/main/dnsmasq/popupads.txt)
in its equivalent [plain domain format](https://github.com/hagezi/dns-blocklists/blob/main/wildcard/popupads-onlydomains.txt)
at build time. It retains the upstream comments and license. Startup needs no
blocklist download. Upstream queries require outbound UDP port 853 for QUIC.
Run these commands from the repository root:

```sh
docker build -f examples/adblock/Dockerfile -t donna-adblock:local .
docker run --rm --name donna-adblock \
  -p 127.0.0.1:5353:5353/udp -p 127.0.0.1:5353:5353/tcp \
  donna-adblock:local
```

In another terminal, choose a domain from the bundled list and query it:

```sh
blocked=$(docker exec donna-adblock sh -c "sed '/^#/d; /^$/d' /etc/donna/blocklist.txt | head -n 1")
dig @127.0.0.1 -p 5353 "$blocked" A +tcp
dig @127.0.0.1 -p 5353 "cdn.$blocked" AAAA +tcp
dig @127.0.0.1 -p 5353 example.com A +tcp
```

The first two return `status: NXDOMAIN` and `EDE: 15 (Blocked)`; `example.com`
resolves normally. Both client protocols are supported. The container runs as
UID/GID 65532 and listens on unprivileged port 5353. To serve standard DNS,
publish host port 53 for both protocols instead.

| Environment variable | Default in Docker | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` | Container IPv4 on port 5353 | Concrete UDP and TCP bind address |
| `UPSTREAM_ADDRS` | `9.9.9.9:853,149.112.112.112:853` | Comma-separated DoQ upstream IP:port addresses, tried in order |
| `UPSTREAM_SERVER_NAME` | `dns.quad9.net` | TLS authentication name shared by all upstream addresses |
| `UPSTREAM_CA_FILE` | Unset | Optional PEM certificates to trust in addition to the bundled roots |
| `BLOCKLIST_FILE` | `/etc/donna/blocklist.txt` | UTF-8 domain list loaded once at startup |

Set variables with
`docker run -e UPSTREAM_ADDRS=9.9.9.9:853,149.112.112.112:853 ...`.
Configure at least two distinct upstream addresses that support DoQ, and set
`UPSTREAM_SERVER_NAME` to their certificate name when changing providers.
Donna connects directly to these IPs without a bootstrap DNS lookup. IPv6 socket
addresses use brackets, such as `[2620:fe::fe]:853`. QUIC upstreams cannot use
port 53. For a private CA, mount a readable PEM file and set
`UPSTREAM_CA_FILE=/certs/ca.pem`; certificate and name verification remain
enabled. All upstreams share the configured authentication name and trust roots.

The native listener defaults to `127.0.0.1:5353`. Donna requires a concrete
local IP for UDP replies; the
container entrypoint detects its IPv4 address with `hostname -i`. Set
`LISTEN_ADDR` explicitly for IPv6 or other network modes.

When updating an existing deployment, rebuild the image and recreate the
container. Remove old `UPSTREAM_ADDRS` values ending in `:53`, or replace them
with DoQ endpoints and the matching `UPSTREAM_SERVER_NAME`. If local blocked
queries work but allowed queries fail, check outbound UDP 853, DoQ support at
both endpoints, and the configured TLS name and trust roots.

A custom list has one domain per line, optionally with a trailing root dot.
Blank lines and `#` comments are accepted, including inline comments. Empty
lists, the root domain, invalid names, and hosts/dnsmasq/adblock syntax fail
startup with an error. For example:

```text
# Block these names and everything beneath them.
ads.example.
tracking.example.
```

Mount a replacement with
`-v "$PWD/my-domains.txt:/etc/donna/blocklist.txt:ro"`. Restart after changing
the file. To refresh the bundled HaGeZi list, rebuild with `--no-cache` and
recreate the container. For reproducible list contents, build with
`--build-arg BLOCKLIST_REF=<hagezi-commit-sha>`.

To run natively:

```sh
curl -fL https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt \
  -o examples/adblock/blocklist.txt
cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-adblock
```

This example filters query names. It trusts the upstream's DNSSEC judgments;
policy answers have AD cleared. It does not inspect CNAME/DNAME targets in
otherwise allowed answers, intercept HTTPS traffic, or block ads served from
the same domains as desired content. Policy answers contain no SOA and are
not admitted to the forwarder's negative cache.

Verify the policy and cache in process, then exercise the built image over
UDP and TCP against controlled upstream endpoints, including failover when the
first endpoint rejects QUIC connections:

```sh
cargo test --locked --manifest-path examples/Cargo.toml -p donna-example-adblock
python3 examples/adblock/smoke.py
```

The smoke test builds an independent `aioquic` upstream on
`python:3.13-slim-bookworm`, generates an ephemeral TLS certificate, and uses a
Python client on an isolated Docker bridge. It removes its temporary
containers, certificate volume, image and network.
It checks authenticated DoQ forwarding, failover after a rejected handshake,
shared A/AAAA caching across the UDP/TCP listeners, and that blocked queries
never reach the upstream.
On Colima, localhost forwarding may support TCP only; use `dig ... +tcp` from
the host or query from another container on the same Docker network for UDP.
