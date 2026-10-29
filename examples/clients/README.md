# DNS transport clients

Use the shipped CLI for ordinary queries:

```sh
cargo run --locked -- query alias.example.test -s 127.0.0.1:5300 --protocol tcp
cargo run --locked -- query example.test MX,TXT -s 127.0.0.1:5300 --json
```

The examples below show how applications use the public transport API.

[query.rs](src/query.rs) sends an A query using Donna's public transport API.
It accepts `udp|tcp`, a server address and a name; defaults are `udp`,
`127.0.0.1:5300` and `www.example.test.`. Start the
[small authority](../authority/README.md), or pass an existing endpoint:

```sh
cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-clients --bin query -- tcp 127.0.0.1:5300 alias.example.test.
```

This package enables UDP/TCP by default. [main.rs](src/main.rs) is the separate
fixture-checking client for encrypted interoperability:

```sh
CERT_DIR=/path/to/certs cargo run --locked --manifest-path examples/Cargo.toml \
  -p donna-example-clients --features encrypted --bin client -- tls 127.0.0.1:8530
```

That client accepts `udp`, `tcp`, `tls`, `doh-get`, `doh-post`, `doq`,
`dnscrypt-udp` and `dnscrypt-tcp`. It verifies the laboratory's fixed
`www.example.test. A 192.0.2.80` answer, authenticates TLS as `localhost`, and
uses public DNSCrypt fixture keys. [The lab](../interop/docs/clients.md) supplies its
certificates and independent peers, plus Python/Go/Node clients.
