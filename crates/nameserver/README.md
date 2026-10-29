# nameserver

Validated authoritative zones, query/denial indexes, transfer policy,
authenticated updates and atomic publication. Dependencies are `dns` and
`transport`; the daemon supplies master-file loading and listener composition.

`NameServer::new()` uses native storage. `NameServerConfig` defaults deny AXFR
and updates, disable NOTIFY, and retain no IXFR history. `ZoneStore` and
`UpdatePersistence` let an application own durable publication.

See [publication contracts](../../docs/architecture.md#authoritative-publication),
[authority example](../../examples/authority/README.md),
[authenticated update application](../../examples/updates/README.md), and
[storage adapters](../../examples/adapters/README.md).

```sh
cargo doc --locked -p nameserver --no-deps
```
