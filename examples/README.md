# Donna examples

Start with the shipped CLI, then choose a library example or a lab when you
need an embedded application or independent peers. All commands below run from the repository root.

The [project documentation](../README.md#documentation) describes every role,
configuration and library boundary. The [benchmark report](../docs/benchmarks.md)
includes runnable comparisons and retained measurements.

| Explore | Entry point | Requirements |
| --- | --- | --- |
| Serve a zone over UDP/TCP | [authority](authority/README.md) | Rust; includes its own zone |
| Query a chosen nameserver | [clients](clients/README.md) | Rust; a running DNS endpoint |
| Run or embed an iterative resolver | [recursive](recursive/README.md) | Rust; an explicit root server |
| Block ad domains and forward allowed queries to Quad9 over DoQ | [ad blocker](adblock/README.md) | Docker, or Rust and a domain list; outbound UDP 853 |
| Persist authenticated updates and send NOTIFY | [updates](updates/README.md) | Rust; optional NOTIFY endpoint |
| Supply application-owned cache/zone storage | [memory adapters](adapters/memory/README.md) | Rust; runs entirely in process |
| Supply Redis/PostgreSQL storage | [remote adapters](adapters/remote/README.md) | Docker |
| Check DNS behaviour learned from BIND | [behaviour corpus](../tests/behaviour/README.md) | Rust tests; optional independent network probe |
| Explore Python, Go and Node clients or encrypted transports | [interop lab](interop/README.md), [language clients](interop/docs/clients.md) | Docker |
| Reproduce comparisons and profiles | [lab recipes](interop/docs/recipes.md) | Varies by experiment |

For a first local session, start the authority in one terminal:

```sh
cargo run --locked -- check -c examples/authority/donna.toml
cargo run --locked -- serve -c examples/authority/donna.toml
```

Query it from another terminal:

```sh
cargo run --locked -- query www.example.test -s 127.0.0.1:5300
cargo run --locked -- query alias.example.test -s 127.0.0.1:5300 --protocol tcp
```

The CLI configuration resolves its zone file relative to the configuration file.
The examples below retain public API hooks for applications embedding Donna.
Each application owns its source, configuration and fixtures. The separate
[examples workspace](Cargo.toml) shares a lockfile and build directory; select a
package with `-p` to build only its dependencies. Plain clients/authorities and
recursive/update examples enable UDP/TCP only. The authority and client
examples require their package's `encrypted` feature for encrypted transports.
The ad blocker enables DoQ upstreams by default, with UDP/TCP client listeners;
it verifies Quad9's `dns.quad9.net` certificate using bundled public roots.
The memory adapter enables no socket transport. No application imports the
interop library or another demo.

`interop/` remains a separate workspace for probes, profilers and integration
checks. Its existing binary names alias the application sources, so Docker binary
commands continue to work. Use `interop/run.py COMMAND` for host-side labs. Its builders
select only the binaries each image needs. `adapters/remote/` also retains its
own workspace and database SDK dependencies.

The lab's Python drivers use `interop/support/` for Docker invocation, locking,
full-lab resource names and evidence output. Importing a utility does not import
an experiment or start services. Drivers extending the full lab say so in the
[recipe index](interop/docs/recipes.md). Generated reports belong in ignored `interop/.artifacts/` or an explicit
output directory; the historical result dumps have been removed.
