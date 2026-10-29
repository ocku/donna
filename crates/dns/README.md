# dns

DNS messages and records, master-file loading, wire encoding/decoding, DNSSEC,
transaction authentication and discovery protocol state. This crate has no
runtime workspace dependencies. It does not open sockets or run a resolver.

See the [architecture and embedding guide](../../docs/architecture.md),
[record and cryptographic scope](../../docs/protocols.md), and
[application examples](../../examples/README.md).

Generate the public API reference from the workspace root:

```sh
cargo doc --locked -p dns --no-deps
```
