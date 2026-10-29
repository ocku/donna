# Redis cache and PostgreSQL catalog example

The `cache-engine` application implements Donna's per-entry `CacheEngine` with
Redis and its authoritative `ZoneStore` with PostgreSQL. The `redis` and
`tokio-postgres` SDKs stay in this standalone locked workspace; Donna's core
libraries contain no database-specific types or clients.

Run from the repository root with Docker available:

```sh
python3 examples/adapters/remote/run_engine.py
```

The driver freezes the current sources, builds the application and independent
signer/checker images, and creates an isolated network and disposable database
volumes. BIND generates a signed root/TLD/leaf fixture. Signing private keys
remain in a separate volume removed after exporting public zones. Database and
cache-sealing secrets are random temporary files, excluded from public evidence.
No database ports are published.

The application exercises seed, database/application restart, Redis outage,
PostgreSQL outage and recovery. A counting in-process transport follows genuine
referrals through PostgreSQL-backed authoritative catalogs. Offline verification
checks 73 signed replies, exact questions and records, authenticated denial,
original TTL bounds and a served bad-DS witness. This is library/provider
integration; it is not a network frontend or throughput benchmark.

Normal runs remove their containers, network, volumes and owned image tags.
`--keep-images` retains this lab's tagged application and helper images.
`--public-fixture` reuses an explicitly
selected signed hierarchy without generating signing keys. See `--help` for
output and evidence options.

## Cache storage and policy

[redis_engine.rs](src/redis_engine.rs) implements targeted read plans and atomic
mutations; [main.rs](src/main.rs) selects `Resolver::with_cache_engine`.
Redis stores sealed entries in individual HASH fields, complete owner-family
indexes and a FIFO ZSET. Exact reads use targeted fields rather than `HGETALL`
or reconstruction of Donna's native stores.

The provider owns FIFO retention with at most 4096 entries and 16 MiB of encoded
entry bodies per namespace, 256 entries per owner family and 1 MiB per entry.
Access callbacks do not change FIFO order. Equal-commit admissions use a
deterministic key tie-break. Declining a replacement leaves that key absent;
mandatory removals still execute. A persistent namespace generation protects
all six categories, absent family members and cross-category changes.

Reads change neither retention nor generation. Server-side checks enforce the
remaining read budget, including zero: an empty complete read can fit zero;
a retained member exceeding the budget fails explicitly. Ancestor queries
expand literal canonical DNS parents. Optional denial-candidate hints are
unsupported. There is no automatic Redis key expiry; core-authenticated
absolute deadlines remain authoritative.

The Lua scripts receive binary-safe arguments through `ARGV`. They preflight
types, sizes, indexes, operations and generation exhaustion before mutating
Redis. Script execution is atomic against other clients; script errors do not
provide rollback. Contract tests verify that rejected preflight operations
leave data and generation unchanged. Revisions stop before Lua's exact-integer
boundary of 2^53 and never wrap.

## Catalog publication

[postgres_zones.rs](src/postgres_zones.rs) stores a complete length-delimited
catalog and revision in one row. A bounded query reads both together; a
conditional atomic `UPDATE` publishes every replacement zone. Independent DNS
wire records are reconstructed and validated through Donna's public APIs.

The application races concurrent catalog writers, rejects stale revisions,
injects empty, truncated, trailing and excessive-zone-count payloads, verifies
SERVFAIL rather than stale/partial answers, then restores a valid catalog.
Redis contract tests cover complete readsets, absent-member conflicts, atomic
invalidations, bounds and malformed storage. Resolver scenarios exercise all
six categories, capacity zero, expiry, sealed-entry corruption, restart,
outage and recovery.

These are disposable application adapters. Their revision contract assumes
storage is not rolled back or deleted; seals cannot prove non-rollback.
A timeout during a write can leave its outcome unknown. Durable applications
must preserve acknowledged writes and revision history, resolve ambiguity and
keep secrets outside the cache. Persistent expiry requires a trusted clock.
Database connections here are unencrypted and opened per operation for clarity;
the example makes no deployment or throughput claim. See the
[adapter contracts](../README.md).

## Offline verifier tests

With the interoperability suite's Python dependencies installed:

```sh
PYTHONPATH=examples/interop/python python3 examples/adapters/remote/engine_verify_test.py
```

They also run through `python3 examples/interop/run.py oracle-tests`. The default
input is a freshly signed synthetic hierarchy and modeled reply/acquisition
records with a fixed clock. Faults cover run metadata, reply multiplicities,
questions, signatures, denial, TTLs and acquisition witnesses. These inputs test
the verifier; they are not captures of Donna or database execution.

To test an explicitly selected current result instead:

```sh
DONNA_ENGINE_CORPUS=/path/to/result.json PYTHONPATH=examples/interop/python \
  python3 examples/adapters/remote/engine_verify_test.py
```

An invalid or missing selected file fails instead of falling back to the model.
Archived evidence records the source and harness that produced it.
