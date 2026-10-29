# Iterative resolution

Use the shipped CLI to resolve with root hints and bundled DNSSEC anchors:

```sh
cargo run --locked -- resolve example.com --stats
```

For an unsigned private hierarchy, supply its root explicitly:

```sh
cargo run --locked -- resolve www.example.test --root 127.0.0.1:5353 --no-validate --trace
```

For a persistent recursive service, generate a configuration with `donna config`,
set its listener addresses and root hints, then run `donna serve -c FILE`.
The examples below demonstrate embedding the resolver API.

[main.rs](src/main.rs) serves recursive DNS over UDP/TCP 5301. Specify an initial
root endpoint; the server follows referrals itself. From the repository root:

```sh
ROOT_SERVER=127.0.0.1:5353 LISTEN_HOST=127.0.0.1 \
  cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-recursive --bin recursive
```

The endpoint must serve the root of the hierarchy you want to resolve; the
small authoritative example alone does not provide a root/TLD hierarchy.
`ROOT_SERVER` is required. `LISTEN_HOST` defaults to `127.0.0.1`.
`CACHE_CAPACITY` optionally overrides native cache capacity, including zero.
`TRUST_ANCHOR_FILE` optionally supplies a nonempty master file containing only
DNSKEY trust anchors; the unsigned lab supplies none.

[iterative_client.rs](src/bin/iterative_client.rs) embeds `Resolver` directly
and checks two referrals and a repeated positive-cache hit for the lab's
`www.example.test.` fixture:

```sh
ROOT_SERVER=172.29.53.22:53 cargo run --locked --manifest-path examples/Cargo.toml \
  -p donna-example-recursive --bin iterative_client
```

That endpoint belongs to the optional [BIND hierarchy lab](../interop/docs/clients.md)
and must be reachable from the client. The full lab runs this same source in
Docker. Neither executable depends on the authority, update or client examples.
