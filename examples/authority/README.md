# Authoritative service

Run a UDP/TCP authority with its own small [zone](zone.db), without certificates
or Docker. From the repository root:

```sh
cargo run --locked -- check -c examples/authority/donna.toml
cargo run --locked -- serve -c examples/authority/donna.toml
dig @127.0.0.1 -p 5300 www.example.test A
dig @127.0.0.1 -p 5300 alias.example.test A +tcp
```

For an application-owned authority, run the library example:

```sh
cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-authority --bin authority
```

[main.rs](src/main.rs) loads the zone through `MasterFile`/`Zone` and serves it
through `UdpTransport` and `TcpTransport`. `LISTEN_ADDR` defaults to
`127.0.0.1:5300`; `ZONE_FILE` defaults to this directory's `zone.db`. The zone
apex is `example.test.`. Stop the process with Ctrl-C.

[listeners.rs](src/listeners.rs) demonstrates every supported transport. Enable
its explicit feature and supply DER certificates (`cert.der`, `key.der`):

```sh
LISTEN_HOST=127.0.0.1 CERT_DIR=/path/to/certs \
  cargo run --locked --manifest-path examples/Cargo.toml -p donna-example-authority --features encrypted --bin listeners
```

It serves UDP/TCP 5300, TLS 8530, HTTPS 8443, QUIC 8853 and DNSCrypt UDP/TCP
5443. Its fixed keys and open AXFR policy are laboratory fixtures. For generated
certificates and independent peers, use the [interop lab](../interop/README.md).
