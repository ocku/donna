# Language client examples

Generated historical reports have been removed. Use the current [recipe index](recipes.md)
for runnable entry points; historical measurements below describe earlier runs.

`run.py` executes independent Python, Go and Node clients against Donna's
nameserver and recursive daemon. The shipped `donna query` CLI checks BIND,
independent encrypted peers and both Donna roles; `donna resolve` follows the
independent BIND root, TLD and leaf hierarchy. The ordinary recursive role runs
`donna serve` with [explicit configuration](../fixtures/basic/recursive.toml).

| Role | Donna entry point | Python | Go | Node |
| --- | --- | --- | --- | --- |
| Client of authoritative Donna | `donna query`; server: `../../authority/src/listeners.rs` | `python/probe.py` | `go/client.go` | `node/client.mjs` |
| Client of recursive Donna | `donna query`; server: `donna serve` | `python/recursive_probe.py` | `go/recursive.go` | `node/recursive.mjs` |
| Donna client of independent servers | `donna query` | Independent encrypted peers in `python/peers.py` | — | — |
| Iterative resolution | `donna resolve`; cache API check: `../../recursive/src/bin/iterative_client.rs` | — | — | — |

The transport/listener and embedded-resolver examples remain available for
applications using the public APIs. The authority's library listener fixture
also supplies its laboratory TSIG keys; the CLI does not currently configure
TSIG keys. The update example exercises application-owned persistence and
NOTIFY hooks.

Build and execute the laboratory from the repository root:

```sh
python3 examples/interop/run.py --keep
```

To verify a separately built candidate while retaining the historical default
image, pass an explicit image name or immutable image ID. The same candidate
is used for authoritative, recursive, update and signed-zone roles:

```sh
python3 examples/interop/run.py --skip-build --donna-image donna-discovery-current --fuzz 2000
```

Rerun only the recursive language clients against the retained laboratory:

```sh
docker run --rm --network donna-interop-laboratory donna-interop-go recursive-client
docker run --rm --network donna-interop-laboratory donna-interop-node node recursive.mjs
docker exec donna-interop-probe python recursive_probe.py
docker exec donna-interop-donna donna query www.example.test -s 172.29.53.11:5301 --json
docker exec donna-interop-donna donna query www.example.test -s 172.29.53.11:5301 --protocol tcp --json
docker exec donna-interop-donna donna resolve www.example.test --root 172.29.53.22:53 --no-validate --json
docker exec donna-interop-donna iterative_client
```

The full lab parses each CLI JSON response and checks the question, successful
status and fixture A record. To query the authoritative service instead, pass
`172.29.53.10:5300` as the address. Both roles are checked over UDP and TCP.
The other probes cover negative answers and the separate cache laboratory
observes upstream traffic.
The embedded resolver example follows the BIND hierarchy from `ROOT_SERVER`
(default `172.29.53.22:53`) and checks that its repeated answer is supplied by
Donna's positive cache without UDP transmissions. Its unsigned fixture does not
configure DNSSEC trust anchors; applications that validate DNSSEC need to
configure and maintain their own anchors.

The Go and Node recursive clients accept `RECURSIVE_ADDRESS` (default
`172.29.53.11:5301`). They use only their language's standard libraries. Each
checks a positive A lookup, CNAME resolution, NXDOMAIN, NODATA and a complete
96-record A RRset, then repeats the lookups. The Go client counts TCP dials and
requires at least one, verifying automatic fallback for the large response.
Node verifies the complete large response without making a claim about its
internal transport choice. Neither example treats a repeated successful lookup
as proof that upstream traffic stopped; the dedicated cache harness verifies
that separately.

Node exposes NXDOMAIN as `ENOTFOUND` and NODATA as `ENODATA`. Go exposes both as
`net.DNSError.IsNotFound`. The raw Python probe independently checks the distinct
RCODEs, empty answers, SOA owner and bounded negative TTL over UDP and TCP.
These distinctions follow [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html);
TCP fallback follows [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html).
The recursive fixture has no configured trust anchor, so these examples do not
claim DNSSEC authentication. The separate signed-chain laboratory tests that
role.

Cleanup after inspection:

```sh
python3 examples/interop/run.py --cleanup
```

The separate [observable recursive comparison](RECURSIVE-SEMANTICS.md) checks
Donna and BIND against an independently counted authority. It verifies warm
cache traffic, NXDOMAIN/NODATA key scope, CNAME terminal scope and expiration.
For application-owned caches and authoritative catalogs, run the
[public adapter example](../../adapters/README.md).

The optional Hickory peer uses upstream release 0.26.3, source commit
`bd37cafbdd86112a6da32878f8c9bab22e14377e`. The
[Dockerfile](../docker/Hickory.Dockerfile) verifies the source archive checksum and
builds the server and official `dns`/`resolve` clients with the upstream lockfile
and release profile. These dependencies are built and run only inside Docker.

```sh
python3 examples/interop/run.py --with-hickory --keep
# Repeat just the Hickory clients against the retained Donna services:
python3 examples/interop/run.py hickory-clients
```

The official `dns` client checks positive A, CNAME, NXDOMAIN and NODATA over
UDP/TCP against authoritative and recursive Donna. The `resolve` client exercises
the high-level stub resolver API and verifies all 96 addresses of the large
RRset. The harness checks response contents because the resolver utility can
exit successfully even when lookup fails. Donna's CLI also
queries the Hickory authority over UDP/TCP. These unsigned examples establish
neither DNSSEC authentication nor upstream-cache traffic or throughput.
