# Performance measurements

**Donna is vibe coded with AI assistance and is not production ready.** These
measurements do not establish reliability comparable to dig, BIND 9, Knot DNS,
Knot Resolver, Hickory, or Unbound. Prefer those projects over Donna for
production use in their respective roles. See the [AI notice](../README.md#ai-notice-and-production-readiness).

These measurements compare Donna's shipped executable with dig, BIND 9,
Knot DNS, Knot Resolver, Hickory and Unbound in the roles they share. The runs use
a private DNS hierarchy and include correctness gates. They measure command
startup/query cost, unsigned authoritative UDP service, unsigned recursive
cache hits, and the first query through a fresh resolver process.

The retained JSON reports for [CLI/authority](benchmarks/results/2026-10-29.json)
and [recursive/cold queries](benchmarks/results/2026-10-30-recursive.json) contain
individual trials, runtime image identities, the Donna binary hash, source
hashes, complete configurations and response references. The recursive
comparison was rerun with all five resolvers when Unbound was added. The [runner](benchmarks/run.py),
[measurement worker](benchmarks/worker.py), and
[table generator](benchmarks/summarize.py) are checked in. The
[feature comparison](comparison.md) describes operational capabilities that
these throughput tests do not measure.

## Environment and controls

| Parameter | Recorded setting |
| --- | --- |
| Host | Apple M4; Docker through Colima, Linux ARM64 |
| Docker VM, CLI/authority (October 29) | 2 vCPUs, 2053648384 bytes RAM, Linux 6.8.0-117-generic |
| Docker VM, recursive/cold (October 30) | 6 vCPUs, 8306720768 bytes RAM, Linux 6.8.0-117-generic |
| Donna build | 0.1.0, Rust 1.99.1; locked release build, thin LTO, one codegen unit |
| BIND server, CLI/authority | 9.18.49-1~deb12u2-Debian |
| BIND server, recursive/cold | 9.18.49-1~deb12u3-Debian |
| dig client | 9.20.30-1~deb13u1-Debian; distinct from the BIND server package |
| Knot DNS | 3.6.2 |
| Knot Resolver | 6.5.1 |
| Hickory | 0.26.3, revision `bd37cafbdd86112a6da32878f8c9bab22e14377e` |
| Unbound | 1.17.1-2+deb12u4, Debian Bookworm package |
| Server resources, CLI/authority | Each container: 1 CPU quota, 256 MiB, one configured worker |
| Container resources, recursive/cold | Each container: 4 CPU quota, 4 GiB RAM limit; each server: four configured workers |
| Knot DNS worker layout | One UDP worker, one TCP worker, one background worker, within the same container quota |
| Client | Same Docker bridge; unrestricted for CLI/authority, 4 CPU quota and 4 GiB for recursive/cold; no CPU affinity |
| Timed server load | 32 outstanding UDP queries, closed loop, three 3-second trials per workload/server |
| Order | Rotated by repetition; one timed load client at a time |
| Signing/validation | Unsigned zone and hierarchy; recursive validation explicitly disabled for every resolver |
| Logging | Per-query logging disabled; Rust filters at error level |

Donna's server and CLI use the same compiled executable, checked by SHA-256.
The server measurements use `donna serve`, rather than a specialized example
daemon. Hickory's measured build enables recursion and DNSSEC support but does
not enable every optional encrypted transport.

The native load generator is the lab's
[`batched_load.c`](../examples/interop/python/batched_load.c), rebuilt from the
current source. It checks transaction correlation, response flags, completion
counts and loss. An independent dnspython pre/postcheck verifies expected data,
aliases and negative SOA content. Authoritative responses are immutable here,
so every timed packet is also compared byte-for-byte with its independently
checked reference, excluding the transaction ID. Recursive TTLs age; timed
recursive packets have structural/flag checks, with semantic checks before and
after each trial, rather than immutable full-body comparison.

All published timed trials completed with zero loss. A failed gate aborts the
run and leaves `complete = false`. Semantic gate tests deliberately inject
wrong addresses, owners, aliases, extra answers, flags and response codes.

## CLI process-to-result time

Both clients query the same local BIND authority for `www.example.test. A` and
print the same short answer. EDNS is disabled for both, RD and AD are requested,
one attempt is allowed, and the timeout is two seconds. Each command starts a
new process. Timing begins before spawning the executable and ends after its
output is collected; Python process-launch, loader and shutdown costs are
included. Container startup and `docker exec` startup are outside the measured
interval.

The worker alternates order, discards ten warmups per client and retains 60
samples each. p95 uses the nearest-rank definition. Donna uses one Tokio worker.
These are process-to-result measurements, not the exchange duration printed by
either tool and not a server throughput test.

<!-- BEGIN CLI TABLE -->

| Client | Median ms | p95 ms | Min to max ms |
| --- | ---: | ---: | ---: |
| Donna | 1.100 | 1.368 | 0.613 to 3.188 |
| dig | 4.967 | 5.838 | 4.269 to 6.156 |

<!-- END CLI TABLE -->

## Authoritative UDP service

All four authorities load the same small `example.test.` zone. The workloads
are an explicit A record (`www`), NXDOMAIN with SOA (`missing`), and wildcard TXT
synthesis (`m.wild`). Queries use EDNS payload 1232, DO clear and RD clear.
Each timed trial repeatedly asks one question. This deliberately measures
frequently accessed authoritative data and reply construction, not a large
zone distribution or dynamic update throughput.

Tables report the median trial throughput, the full trial range, and the median
of each trial's mean latency. Latency is measured at 32 outstanding queries and
is coupled to throughput in this closed-loop test.

<!-- BEGIN AUTHORITY TABLE -->

| Server | Workload | Median q/s | Min to max q/s | Mean latency, µs |
| --- | --- | ---: | ---: | ---: |
| Donna | positive | 522,351 | 492,683 to 534,585 | 61.0 |
| BIND 9 | positive | 354,441 | 346,279 to 357,078 | 90.0 |
| Knot DNS | positive | 691,971 | 669,794 to 711,576 | 46.1 |
| Hickory | positive | 196,332 | 193,843 to 196,829 | 162.9 |
| Donna | negative | 527,782 | 520,043 to 527,951 | 60.4 |
| BIND 9 | negative | 328,177 | 315,075 to 329,648 | 97.2 |
| Knot DNS | negative | 637,498 | 571,670 to 647,165 | 50.1 |
| Hickory | negative | 120,821 | 116,957 to 121,687 | 264.7 |
| Donna | wildcard | 504,773 | 498,949 to 522,973 | 63.2 |
| BIND 9 | wildcard | 307,288 | 305,288 to 312,230 | 103.9 |
| Knot DNS | wildcard | 621,165 | 616,087 to 621,460 | 51.4 |
| Hickory | wildcard | 136,631 | 135,812 to 140,087 | 234.1 |

<!-- END AUTHORITY TABLE -->

## Recursive warm cache

The resolvers independently iterate through BIND root, `test.`, and
`example.test.` authorities on the private bridge. No resolver forwards to
another resolver. The workloads are a cached A record, cached NXDOMAIN, and a
cached CNAME plus terminal A record. A semantic precheck warms each question
before load. Queries use EDNS payload 1232, DO clear and RD set.

Donna retains its default capacity of 4096 entries per native cache. Knot
Resolver has a 64 MiB cache and minimum TTL zero; Hickory uses 1024 nameserver
and 65536 response entries. BIND retains its default cache sizing within the
container limit. Unbound uses a 4 MiB message cache and a 4 MiB RRset cache,
each with four slabs. These are different cache implementations and retention
budgets. The one-question workload fits every cache; it does not establish
equal memory use, eviction behavior or cache efficiency under churn.

Unbound uses `module-config: "iterator"` to disable validation and
`local-zone: "test." nodefault` to resolve the lab's `test.` hierarchy instead
of serving its built-in local zone. These settings follow the
[Unbound configuration manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

<!-- BEGIN RECURSIVE TABLE -->

| Server | Workload | Median q/s | Min to max q/s | Mean latency, µs |
| --- | --- | ---: | ---: | ---: |
| Donna | positive | 727,141 | 706,415 to 735,810 | 43.8 |
| BIND 9 | positive | 353,208 | 350,263 to 355,003 | 90.4 |
| Knot Resolver | positive | 188,702 | 187,454 to 189,112 | 169.4 |
| Hickory | positive | 306,808 | 301,992 to 308,373 | 104.0 |
| Unbound | positive | 510,502 | 507,773 to 519,720 | 62.6 |
| Donna | negative | 520,032 | 483,562 to 617,105 | 61.3 |
| BIND 9 | negative | 332,131 | 327,197 to 334,238 | 96.2 |
| Knot Resolver | negative | 178,236 | 166,498 to 178,775 | 179.3 |
| Hickory | negative | 269,053 | 211,597 to 269,161 | 118.6 |
| Unbound | negative | 466,322 | 453,489 to 468,775 | 68.6 |
| Donna | cname | 475,866 | 474,196 to 500,398 | 67.0 |
| BIND 9 | cname | 276,680 | 260,893 to 290,142 | 115.5 |
| Knot Resolver | cname | 159,081 | 153,067 to 162,652 | 201.0 |
| Hickory | cname | 272,506 | 222,414 to 283,720 | 117.1 |
| Unbound | cname | 442,916 | 441,445 to 455,742 | 72.2 |

<!-- END RECURSIVE TABLE -->

## Cold iterative query

Each of five observations per resolver starts a fresh resolver process. Readiness
opens TCP without sending a DNS question. The first UDP A query then follows
the private hierarchy. The authorities and host page caches can already be
warm. Process launch, configuration loading and readiness are excluded; query
serialization, socket work and dnspython decoding are included. This is
resolver-process-cold latency on a local network, not Internet DNS latency or
service startup time.

<!-- BEGIN COLD TABLE -->

| Resolver | Cold median ms | Min to max ms |
| --- | ---: | ---: |
| Donna | 1.220 | 1.181 to 1.533 |
| BIND 9 | 1.576 | 1.451 to 1.971 |
| Knot Resolver | 1.123 | 1.097 to 1.226 |
| Hickory | 1.383 | 1.316 to 1.749 |
| Unbound | 1.237 | 1.173 to 1.298 |

<!-- END COLD TABLE -->

Five observations are insufficient for a reliable tail-latency estimate. The
range is included to expose scheduling variation rather than hide it behind a
single median.

## Interpretation and limits

The observed ordering is specific to these execution paths. Knot DNS has the
highest authoritative throughput in this experiment. Donna performs above
BIND and Hickory on the measured authority workloads and above the compared
resolvers on these warm-cache workloads. The CLI measurements favor Donna for
this short local query. These observations describe throughput and command
latency only. They do not demonstrate comparable reliability, security, or
operational experience, and do not justify choosing Donna over the established
projects for production.

Donna has not been validated under sustained, large-scale hostile traffic and
combined failure conditions. Such testing would require substantial distributed
traffic-generation infrastructure beyond this lab. Short runs with one client
and a small set of questions cannot establish behavior under that load or the
long-term reliability of a deployed service.

The throughput client is a single native process with one UDP flow and a fixed
window. A single flow may exercise fewer than four server workers; these results
do not establish scaling across four cores. The client does not sweep offered
load or identify the maximum sustainable rate at an explicit
latency target. The shared VM (two vCPUs for CLI/authority, six for recursive),
container quotas, bridge networking and host scheduling can limit both client
and server. Three trials describe local variation; they are not confidence intervals.

The experiment does not measure cryptographic validation, pre-signed authority
performance, encrypted handshake/session throughput, large-zone lookup, broad
query distributions, cache churn, packet-loss recovery, remote storage, update
durability, forwarder miss latency, or secondary synchronization. In particular,
unsigned cache-hit throughput cannot establish DNSSEC validation performance.
Response sizes and encoding choices may differ between implementations even
when the semantic answer matches; the raw authority rows retain their sizes
and exact reference packets. No memory-efficiency or general production
capacity claim follows from these tables.

## Reproduction

Run from the repository root with Docker available. The Knot Resolver image
recipe installs a pinned ARM64 package; other architectures need a compatible
peer recipe. Build the shared load-client base, the current Donna image, and
independent peers:

```sh
docker build -f examples/interop/docker/Bind.Dockerfile -t donna-interop-bind .
docker build -f examples/interop/docker/Hickory.Dockerfile -t donna-interop-hickory:0.26.3 .
docker build -f examples/interop/docker/KnotResolver.Dockerfile -t donna-interop-knot-resolver:6.5.1 .
docker build -f examples/interop/docker/Unbound.Dockerfile -t donna-interop-unbound .
docker pull cznic/knot:3.6
docker build -f examples/interop/docker/CacheClient.Dockerfile -t donna-interop-cache-client .
docker build -f examples/interop/docker/Donna.Dockerfile -t donna-docs:local .
docker build -f docs/benchmarks/Client.Dockerfile -t donna-docs-client:local .

docker run --rm --network none --entrypoint python donna-docs-client:local \
  -m unittest discover -s /suite -p test_documentation_worker.py
python3 -m unittest discover -s docs/benchmarks -p test_summarize.py
python3 docs/benchmarks/run.py --output examples/interop/.artifacts/documentation.json
python3 docs/benchmarks/summarize.py examples/interop/.artifacts/documentation.json
```

The runner owns containers and network names beginning `donna-documentation-`
and subnet `172.30.93.0/24`. It uses the lab lock, copies configuration through
Docker, and removes its resources in `finally`. Do not allocate that namespace
to another workload. `--phases`, `--seconds`, `--repeats` and `--cold-repeats`
select bounded subsets; an altered run must be labeled with its parameters.
The October 30 recursive report uses `--phases recursive --cpus 4 --memory 4g
--workers 4` with three 3-second trials and five cold observations per resolver.
The resource options apply to every container, including the client and the
private hierarchy. The older CLI/authority report used one server worker,
one CPU quota and 256 MiB per server.

Rebuilding later can select newer distribution packages or mutable image tags.
The recorded image IDs, source hashes and version strings identify the measured
run; the commands reproduce the experiment rather than promise identical
package bytes on a future date. Rebuild both Donna images after changing Donna
source so the server/client identity check remains meaningful. Keep new outputs
in `.artifacts/`; the checked-in reports are the curated evidence for these tables.

For signed workloads, diversity, memory and detailed packet replay, use the
[existing lab recipes](../examples/interop/docs/recipes.md). In-process wire,
signature, signed-RRset and cache profiles live in
[`examples/interop/src/bin`](../examples/interop/src/bin/). Their results describe
different work from the service measurements above.
