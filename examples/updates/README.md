# Persistent authenticated updates

[main.rs](src/main.rs) installs its own [zone](zone.db), authorizes TSIG and
SIG(0) updates to specific names, persists wire snapshots through
[snapshot.rs](src/snapshot.rs), and optionally sends NOTIFY. Run from the
repository root:

```sh
UPDATE_LISTEN=127.0.0.1:5301 SNAPSHOT_FILE=/tmp/donna-example-zone.wire \
  cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-updates --bin updates
```

`UPDATE_LISTEN` defaults to `127.0.0.1:5301`; `SNAPSHOT_FILE` defaults to
`zone.wire` in the working directory. Existing snapshots take precedence over
`ZONE_FILE`, which defaults to this directory's fixture. Set `NOTIFY_TARGET`
to an optional `host:port`. Restart with the same snapshot to retain updates.

The fixed public keys authorize `dynamic.example.test. A` (TSIG) and
`sig0-dynamic.example.test. A` (SIG(0)); these are demonstration credentials.
The snapshot format is deliberately bounded to one DNS message. The
[interop lab](../interop/README.md) supplies independent update/NOTIFY clients
and verifies restart persistence. This application needs no encrypted listener,
recursive resolver or certificate service.
