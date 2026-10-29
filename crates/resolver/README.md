# resolver

Iterative resolution through `Resolver`, inbound recursive service through
`RecursiveServer`, and ordered upstream forwarding through `Forwarder`.
Dependencies on `dns` and `transport` keep data/framing outside resolver policy.

Reuse instances to retain cache state. `ResolverConfig::default()` supplies
root hints but no trust anchors, so library validation requires explicit
anchors. The shipped CLI supplies bundled root anchors by default.

See [embedding and cache ownership](../../docs/architecture.md),
[resolver defaults](../../docs/configuration.md#resolution-settings),
[runnable recursive examples](../../examples/recursive/README.md), and
[cache adapter contracts](../../examples/adapters/README.md).

```sh
cargo doc --locked -p resolver --no-deps
```
