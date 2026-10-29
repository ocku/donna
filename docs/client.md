# Command line reference

Build with `cargo build --locked --release --bin donna`; the executable is
`target/release/donna`. Examples below assume it is on `PATH`. There is no
`cargo install donna` release configured in this workspace.

| Command | Operation |
| --- | --- |
| `donna query NAME [TYPE,...]` | Query a selected server; type defaults to A. |
| `donna NAME [TYPE,...]` | Shorthand for `query`. |
| `donna resolve NAME [TYPE,...]` | Iterative resolution with local validation. |
| `donna serve -c FILE` | Foreground daemon. |
| `donna -c FILE` | Shorthand for `serve`. |
| `donna check -c FILE` | Load and validate configuration, zones, anchors and credentials without listening. |
| `donna check-zone ORIGIN FILE` | Validate a master file, resolving `$INCLUDE`. |
| `donna config [recursive\|forward\|authoritative]` | Print a commented configuration; default role is recursive. |
| `donna completions SHELL` | Generate completion definitions. |

`-c/--config` and `-v/--verbose` are global. `RUST_LOG` overrides the diagnostic
log filter. Help is available for the executable and each command.

## Questions and output

`query` and `resolve` share these options:

| Option | Meaning |
| --- | --- |
| `NAME [TYPE,...]` | One name and one or more comma-separated types, including `TYPE65`. |
| `--class IN` | Query class, also accepting `CLASS<number>`. Iteration supports concrete known classes, not ANY or unknown classes. |
| `-x/--reverse IP` | Construct an IPv4 or IPv6 PTR query. |
| `-f/--batch FILE` | One domain per line; `-` reads stdin. Empty lines and text after `#` are ignored. The current parser accepts the default A type for batch mode; see the limitation below. |
| `--json` | One JSON object per response on stdout. |
| `--short` | Answer RDATA only; mutually exclusive with JSON. |
| `--deadline SECONDS` | Per-question deadline, default 30, accepted range 1 to 86400. |

```sh
donna example.com A,AAAA,MX
donna query -x 2001:db8::80 --short
printf 'example.com\nexample.net\n' | donna query --batch - --json
donna query example.com -s 1.1.1.1 -s 8.8.8.8 --compare --json
```

Batch questions run sequentially and share the transport instance. The current
positional parser assigns a type following `--batch FILE` to the conflicting
`NAME` positional, so explicit batch types cannot be selected through this CLI.
Use separate ordinary queries for non-A batch work. `--compare`
queries each configured server; without it, servers are failover candidates.
Server hostnames require bootstrap name resolution. Use numeric addresses when
the bootstrap path itself is under investigation.

JSON includes `server`, `elapsed_ms`, `id`, `status`, numeric `rcode`, DNS
`flags`, `questions`, `answers`, `authorities`, and `additionals`. Each resource
record has `name`, `ttl`, `class`, `type`, `type_code`, and presentation-format
`data`. Unknown RDATA uses generic hexadecimal notation. For example:

```sh
donna query www.example.test -s 127.0.0.1:5300 --json |
  jq -r '.answers[] | select(.type == "A") | .data'
# 192.0.2.80, when using the shipped authority example
```

Diagnostics, traces and statistics use stderr. NXDOMAIN and NODATA are completed
DNS exchanges and return success. SERVFAIL, REFUSED, transport errors and command
errors return nonzero. Check `rcode` when a script needs existence semantics;
an exit status of zero alone does not mean an A record exists.

## Endpoint and wire controls

| Option | Default or behavior |
| --- | --- |
| `-s/--server` | Repeatable IP, hostname, or socket address; omitted uses `/etc/resolv.conf`. |
| `-p/--port` | Override the endpoint port. |
| `--protocol` | `udp` (default), `tcp`, `tls`, `https`, `quic`, `dnscrypt-udp`, `dnscrypt-tcp`. |
| `--timeout` | Exchange timeout, default 5 seconds, range 1 to 3600. |
| `--attempts` | Attempts per server, default 2, range 1 to 3. |
| `--compare` | Query all servers. |
| `--no-recurse` | Clear RD. |
| `--checking-disabled` | Set CD to request data without upstream validation filtering. |
| `--dnssec` | Request DNSSEC records; already enabled by default. |
| `--no-dnssec` | Clear DO. |
| `--no-edns` | Omit OPT entirely. |
| `--udp-size` | EDNS advertisement, default 1232, minimum 512. |

UDP falls back to TCP for an oversized query or truncated response. This
transition differs from trying another server after an exchange failure.
The overall question deadline can expire before all configured attempts finish.

TLS, HTTPS and QUIC require `--tls-name NAME`. Public CA roots are bundled;
`--ca FILE` adds PEM roots. HTTPS supports `--https-path` (default `/dns-query`),
`--https-authority`, and `--https-get` (POST is the default).

```sh
donna query example.com --protocol tls -s 1.1.1.1 --tls-name cloudflare-dns.com
donna query example.com --protocol https -s 1.1.1.1 --tls-name cloudflare-dns.com --https-get
donna query www.example.test --protocol quic -s 127.0.0.1:8853 --tls-name localhost --ca ca.pem
```

Default ports are UDP/TCP 53, TLS/QUIC 853, HTTPS 443, and DNSCrypt 443.
DNSCrypt requires `--provider-name` with the complete certificate owner name
and `--provider-key` with the 64 hexadecimal digits of the Ed25519 public key.

```sh
donna query example.test --protocol dnscrypt-udp -s 127.0.0.1:5443 \
  --provider-name 2.dnscrypt-cert.example.test --provider-key "$DNSCRYPT_PUBLIC_KEY"
donna query example.test AXFR --protocol tcp -s 127.0.0.1:5300
```

AXFR requires a server grant and a supported transfer transport. This client
does not expose TSIG signing or an IXFR serial/history interface.

## Iterative diagnostics

`resolve` adds `--root IP:PORT` (repeatable), `--trust-anchors FILE`,
`--no-validate`, `--trace`, and `--stats`. A custom anchor file replaces the
bundled root anchors and must contain DNSKEY records only. An unsigned private
hierarchy needs `--no-validate` or a suitable signed chain and custom anchor.

```sh
donna resolve example.com AAAA --trace --stats
donna resolve www.example.test --root 127.0.0.1:5353 --no-validate --trace
```

The root endpoint must implement the root of that hierarchy. Pointing `--root`
at a recursive forwarder or an unrelated leaf authority changes the experiment.
The CLI enables validation by default; `ResolverConfig::default()` in the Rust
library has an empty anchor list and therefore does not enable validation.
