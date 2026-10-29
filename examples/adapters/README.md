# Application-owned cache and authoritative storage

`Resolver::new` uses Donna's native in-memory caches.
`Resolver::with_cache_engine` selects an application-owned `CacheEngine` for
lookup, indexing, admission, retention and eviction. Its six categories are
positive answers, negative answers, delegations, repeated DNSSEC BAD failures,
terminal failures and authenticated DNSKEY material.

`NameServer::with_zone_store` independently selects a caller-owned `ZoneStore`
for coherent authoritative catalogs and atomic publication. Database SDKs and
schemas belong in the application, outside Donna's core crates.

## In-process example

The [memory example](memory/README.md) implements both public interfaces without
database SDKs or network services:

```sh
cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-memory-adapters --bin external_backends
```

Its cache uses indexed owner families and per-entry values. Its zone adapter
stores independent DNS wire records and reconstructs validated catalogs.
The application checks revision conflicts, cache reuse across resolver
reconstruction, unavailable stores, recovery and corrupt-record rejection.
An unknown record type with binary RDATA demonstrates that storage need not
understand every DNS type. The custom transport invokes the authority in process.

The interoperability image also contains the example:

```sh
docker build -f examples/interop/docker/Donna.Dockerfile -t donna-adapter-example .
docker run --rm --network none donna-adapter-example external_backends
docker image rm donna-adapter-example
```

## Remote example

The [Redis and PostgreSQL application](remote/README.md) implements an indexed
FIFO `CacheEngine` and transactional `ZoneStore` in its own locked workspace:

```sh
python3 examples/adapters/remote/run_engine.py
```

It exercises signed DNS data, all six cache categories, concurrent conflicts,
expiry, database/application restart, malformed storage, outages and recovery.
Its library transport follows a private root/TLD/leaf hierarchy. Network
frontend behavior is covered by the separate
[interoperability laboratory](../interop/README.md).

## Adapter contracts

The async interfaces return `transport::BoxFuture<'a, T>`. Implement methods
with `Box::pin(async move { ... })`; no attribute macro is required. Futures
are `Send` and may borrow the provider and request. Providers that spawn tasks
own their task lifecycle. Donna owns update publication once its server commit
task starts, including when the requesting client disconnects.

Cache reads must return complete requested predicates at one consistent
namespace revision, including absent keys and family members. Enforce entry
and byte limits before allocation; fail instead of truncating a readset.
Admission, access accounting and eviction belong in atomic mutation batches.
Mandatory DNS invalidations must execute even when policy declines a put.
Optional denial-candidate hints may be unsupported; the interface does not
provide complete RFC 8198 synthesis by itself.

Every successful cache or catalog commit needs a fresh, non-reusable revision,
even when contents are unchanged. Preserve generations across restarts and
deletion: rollback or restoring an old backup can violate this contract.
Catalog commits must publish all replacement zones together. Never report an
uncommitted operation as successful, and resolve ambiguous write outcomes.

Donna authenticates cache entries using a caller secret kept outside the
provider. Supply a random secret and preserve it when sharing a namespace.
Entry authentication detects modification and policy/namespace substitution,
but cannot prove that storage has not replayed an older authentic value.
Persistent expiry requires a trusted, sufficiently synchronized wall clock.

Native capacity zero disables all cache-engine I/O. A nonzero native capacity
does not impose native cache indexes or retention limits on the provider.
No hidden native cache supplies entries the provider discards. Applications
requiring RFC 9520 suppression must retain BAD and terminal-failure history.

Store each zone apex and resource record as an independent DNS wire value.
Decode with `FromWire` and validate with `Zone::from_master` before returning
a catalog. Compression pointers are meaningful only within the original record
byte sequence. Bound catalog size, database reads and remote operation time.
The memory example rebuilds zone indexes on reads for clarity; it is not a
performance recommendation.

Regression checks:

```sh
cargo test --locked -p resolver external_backend
cargo test --locked -p resolver --test cache_engine
cargo test --locked -p nameserver server::storage::tests
```
