# Donna containers

Donna is vibe coded with AI assistance and is not production ready. These
images support controlled evaluation; they do not change the
[production-readiness notice](../../README.md#ai-notice-and-production-readiness).
Prefer the established DNS implementations named there for production.

For a container that blocks ad domains locally and forwards allowed queries
to Quad9 over DNS over QUIC, use the separate
[ad blocker example](../../examples/adblock/README.md). It bundles a domain
list, serves UDP/TCP on port 5353, and uses authenticated DoQ upstreams on UDP
port 853.

## Build

Run from the repository root:

```sh
docker build -f packaging/docker/Dockerfile.client -t donna-client:local .
docker build -f packaging/docker/Dockerfile.server --target forward -t donna-forward:local .
docker build -f packaging/docker/Dockerfile.server --target recursive -t donna-recursive:local .
docker build -f packaging/docker/Dockerfile.server --target authoritative -t donna-ns:local .
```

Both Dockerfiles compile the shipped `donna` executable using the root lockfile
and release profile. They include no lab binaries, compiler or test credentials
in the runtime image. Both run as UID/GID `10001:10001` on Debian Bookworm.
Donna's Apache-2.0 license and attribution notice are installed under
`/usr/share/licenses/donna/`; image labels identify the license and author.
`RUST_IMAGE` is a build argument, defaulting to `rust:bookworm`; set a compatible
version or digest to pin the builder. The runtime base tag can also change, so
retain built image digests when comparing runs.

The server Dockerfile exposes these targets:

| Target | Default daemon policy |
| --- | --- |
| `forward` | Caching forwarding resolver, using an explicit recursive upstream. |
| `recursive` | Iterative recursive resolver with bundled DNSSEC anchors. This is also the final/default target. |
| `authoritative` | Nameserver serving the included `example.test.` fixture. |
| `server` | Common runtime, defaulting to the recursive role. |

## Client

Arguments go directly to Donna. The default command prints help:

```sh
docker run --rm donna-client:local
docker run --rm donna-client:local query example.com A,AAAA -s 1.1.1.1 --json
docker run --rm donna-client:local resolve example.com --trace --stats
printf 'example.com\nexample.net\n' | docker run --rm -i donna-client:local query --batch - --json
```

External queries require network access. Omitted `--server` uses the container's
`/etc/resolv.conf`, which may point at Docker's embedded DNS service rather than
the host's original resolver. For private CAs, mount a readable PEM file and
pass `--ca`; public roots are compiled into the executable.

## Authoritative nameserver

Create a dedicated example network and publish both DNS transports on host
loopback. The container listens on unprivileged port 5353:

```sh
docker network create --subnet 172.30.95.0/24 donna-example
docker run -d --name donna-ns --network donna-example --ip 172.30.95.10 \
  --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --cap-drop ALL --security-opt no-new-privileges=true \
  -p 127.0.0.1:5300:5353/udp -p 127.0.0.1:5300:5353/tcp \
  donna-ns:local

docker run --rm --network donna-example donna-client:local \
  query www.example.test -s donna-ns:5353 --json
docker run --rm --network donna-example donna-client:local \
  query example.test -s donna-ns:5353 --protocol tcp --short
```

The fixture maps `example.test. A` to `192.0.2.80`; `www` is a CNAME to the apex.
Transfers are denied by default. Supply an operator-owned configuration and
zone directory to serve different zones.

Published ports belong to the Docker daemon's host. In the tested Colima setup,
both UDP and TCP publication worked inside the Linux VM, and TCP was reachable
from macOS, but UDP was not forwarded to macOS loopback. The client examples
above use the Docker bridge directly and avoid that VM forwarding limitation.
Host-side UDP queries require working UDP forwarding from the VM.

## Forwarding resolver

The following instance forwards to the example nameserver. It demonstrates
the forwarding path without requiring Internet access or local DNSSEC validation:

```sh
docker run -d --name donna-forward --network donna-example \
  --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --cap-drop ALL --security-opt no-new-privileges=true \
  -e DONNA_RECURSION_CIDRS=172.30.95.0/24 \
  -e DONNA_UPSTREAM=172.30.95.10:5353 \
  -p 127.0.0.1:5301:5353/udp -p 127.0.0.1:5301:5353/tcp \
  donna-forward:local

docker run --rm --network donna-example donna-client:local \
  query example.test -s donna-forward:5353 --json
```

For ordinary recursive upstream service, set `DONNA_UPSTREAM` to its numeric
socket address. The template uses UDP with required TCP fallback and trusts
upstream validation. Encrypted upstreams require a custom configuration.

## Iterative recursive resolver

```sh
docker run -d --name donna-recursive --network donna-example \
  --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --cap-drop ALL --security-opt no-new-privileges=true \
  -e DONNA_RECURSION_CIDRS=172.30.95.0/24 \
  -p 127.0.0.1:5302:5353/udp -p 127.0.0.1:5302:5353/tcp \
  donna-recursive:local

docker run --rm --network donna-example donna-client:local \
  query example.com -s donna-recursive:5353 --json
```

This role contacts authoritative servers itself over UDP/TCP, using built-in
root hints and bundled DNSKEY anchors. It requires outbound DNS access and a
correct host clock. Maintain anchors as described in the
[configuration guide](../../docs/configuration.md). Private unsigned hierarchies
need their own root settings and validation policy in a custom configuration.

## Server environment and lifecycle

| Variable | Default | Meaning |
| --- | --- | --- |
| `DONNA_ROLE` | Target-dependent | `forward`, `recursive`, or `authoritative`; select the built-in template. |
| `DONNA_LISTEN_IP` | First IPv4 returned by `hostname -i` | Concrete local address for UDP and TCP. Explicit numeric IPv6 addresses are also accepted. |
| `DONNA_PORT` | `5353` | Container listener port; publish UDP and TCP separately. |
| `DONNA_RECURSION_CIDRS` | `127.0.0.0/8,::1/128` | Comma-separated permitted networks, without spaces. Empty denies all. Applies to forwarding/recursion, not authoritative data. |
| `DONNA_UPSTREAM` | `1.1.1.1:53` | Numeric IPv4 or bracketed IPv6 socket address for the forwarding template. |
| `DONNA_CONFIG` | unset | Use an existing TOML file instead of template generation; all other `DONNA_*` template settings are ignored. |
| `RUST_LOG` | `info` | Donna's tracing filter; `log_queries` still defaults to false. |

Recursion is restricted to loopback until an allowed network is explicitly
configured. Container clients and published-port clients usually arrive from
a bridge address, so they need a matching CIDR. Configure the network actually
observed by the service. Docker port publication alone does not grant recursion.

The entrypoint renders a template into an owned temporary directory under
`/tmp`, validates it with `donna check`, and uses `exec` to make the daemon PID 1.
Donna requires a concrete UDP address to preserve reply source addresses; it
rejects a wildcard UDP bind. Automatic address selection assumes a normal
single-network Docker bridge. Set `DONNA_LISTEN_IP` or use a custom file for
multiple interfaces, IPv6-only networks or other network modes.

SIGTERM stops the daemon. SIGHUP reloads the active file, but does not regenerate
templates or reread container environment settings. Recreate the container after
changing those settings. An explicit command bypasses template generation and
runs the CLI directly, for example `docker run --rm donna-ns:local --help`.

## Custom configuration, zones and encrypted transports

Mount a directory containing `donna.toml`, zone files and any credentials:

```sh
docker run -d --name donna-custom --network donna-example --ip 172.30.95.20 \
  --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --cap-drop ALL --security-opt no-new-privileges=true \
  --mount type=bind,src="$(pwd)/container-config",dst=/etc/donna,readonly \
  -e DONNA_CONFIG=/etc/donna/donna.toml \
  -p 127.0.0.1:5303:5353/udp -p 127.0.0.1:5303:5353/tcp \
  donna-recursive:local
```

Create `container-config` first. Its TOML must bind the container's concrete
address, here `172.30.95.20:5353`; no template substitution occurs in a custom
file. Relative paths resolve beside that file. UID 10001 must be able to read
the configuration, zones and private keys. The bundled example zone is only a
fixture and should be replaced for a real experiment.

All compiled transports remain available in both images. Configure TLS, HTTPS,
QUIC or DNSCrypt in TOML and publish the corresponding container ports. TCP
serves TLS/HTTPS; UDP serves QUIC; DNSCrypt can use both. For unprivileged
operation, select ports above 1023 in the file and map host ports as needed.
No certificates or private keys are generated or embedded by these images.

```sh
docker exec donna-custom donna check -c /etc/donna/donna.toml
docker kill --signal HUP donna-custom
docker logs donna-custom
```

Listener or credential changes require restart. The templates retain only
in-memory cache state and load master-file zones; there is no writable volume,
secondary refresh service or durable update store configured by the image.

## Checks and cleanup

The smoke test uses only the client and recursive images, overrides server roles
where needed, and creates its own isolated network. It checks UDP/TCP authority,
forwarding, unsigned private-root iteration, recursion denial, invalid settings,
read-only runtime operation and shutdown without public DNS queries:

```sh
python3 packaging/docker/smoke.py
```

Remove the example resources after use:

```sh
docker rm -f donna-ns donna-forward donna-recursive
docker network rm donna-example
```

Remove `donna-custom` separately if it was created. No external images are
published by these commands.
