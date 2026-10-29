# In-process cache and zone adapters

Run from the repository root; no network services, certificates or Docker are
needed:

```sh
cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-memory-adapters --bin external_backends
```

[cache.rs](src/cache.rs) implements the public `CacheEngine` with indexed
per-entry values and atomic namespace revisions. [main.rs](src/main.rs) owns the
cache and `ZoneStore`, reconstructs the catalog and invokes the authority in
process. It demonstrates cache reuse across resolver reconstruction, stale
writer rejection, store outage/recovery and corrupt-record rejection.
It enables no socket transport and imports no other example.

For durable remote storage and provider-owned FIFO eviction, see the
[Redis/PostgreSQL application](../remote/README.md).
[Adapter contracts](../README.md) explain revisions, expiry, sealing and durable
storage requirements.
