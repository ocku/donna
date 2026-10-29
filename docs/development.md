# Building, testing and contributing

Donna is a Rust 2024 workspace. Use the checked-in lockfiles for repeatable
dependency selection. The DNS crate currently depends on `sha2` 0.11.1, which
declares Rust 1.88; this is a dependency minimum, not a verified workspace MSRV.
The documented Linux benchmark build uses Rust 1.99.1. Build and check the
actual target toolchain rather than inferring platform support from edition or
dependency metadata.

```sh
cargo build --locked --release --bin donna
target/release/donna --help
cargo doc --locked --workspace --all-features --no-deps
```

The application has no disabled-by-default transport feature selection. Library
consumers select `transport` features explicitly. Root release settings enable
thin LTO and one codegen unit. The workspace's local `quinn-proto` patch is part
of its dependency identity; see [the patch record](../vendor/quinn-proto/README.donna).

## Repository map

| Path | Responsibility |
| --- | --- |
| `src/main.rs`, `src/app/` | Argument parsing, output, endpoint setup, TOML, trust anchors, daemon composition and reload. |
| `crates/dns/` | Message/record model, master files, wire encoding, DNSSEC and discovery state. |
| `crates/transport/` | Sockets, protocol framing, encrypted sessions, reply ownership and transport limits. |
| `crates/resolver/` | Iteration, forwarding, DNSSEC chain policy, retry/coalescing state and caches. |
| `crates/nameserver/` | Authoritative zones, denial indexes, transfers, authenticated updates and publication. |
| `config/` | Commented daemon configuration and example master file. |
| `packaging/` | systemd, OpenRC, and client/server Docker images with role-specific configurations. |
| `tests/` | CLI, stack and independent behavior checks; certificate fixtures. |
| `examples/` | Separate small-application workspace and its lockfile. |
| `examples/adapters/remote/` | Separate database application workspace and container workflows. |
| `examples/interop/` | Separate lab workspace, Docker peers, protocol oracles and performance experiments. |
| `rfcs/` | Local reference texts; executable coverage is tracked separately. |
| `vendor/quinn-proto/` | Patched transport dependency. |
| `docs/` | Operator, library, comparison and benchmark documentation. |

Do not move database SDKs into core crates to implement an adapter. Shared DNS
data and validation belong in `dns`, framing belongs in `transport`, recursive
policy belongs in `resolver`, and zone policy belongs in `nameserver`.

## Local validation

The [CI workflow](../.github/workflows/ci.yml) runs the root formatting, lint,
test and documentation checks on Linux and macOS. Separate jobs check the
independent example workspaces and host Python harnesses, and build and smoke
test the client/server containers. CI disables incremental compilation and debug
information and shares one target directory within the examples job. Build
outputs are not cached between jobs or runs, keeping runner disk use bounded.
The full independent peer lab remains a separate Docker validation below.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc --all-features
cargo clippy --locked --manifest-path examples/interop/Cargo.toml --all-targets -- -D warnings
git diff --check
```

`--all-targets` does not include Rust documentation tests, so run `--doc`
separately. Library/CLI regressions and the stack tests exercise local behavior;
they do not by themselves establish interoperability with an independent peer.
Platform-specific tests should be interpreted on the platform that ran them.
Linux UDP batching and cgroup process accounting require Linux execution.

The example workspace is independent of the root workspace:

```sh
cargo check --locked --manifest-path examples/Cargo.toml --workspace --all-targets
cargo run --locked --manifest-path examples/Cargo.toml \
  -p donna-example-memory-adapters --bin external_backends
```

Use the package READMEs for optional encrypted features and external services.
The behavior corpus has a bounded, independently specified authority fixture:

```sh
cargo test --locked -p nameserver --test upstream_authority
python3 -m unittest discover -s tests/behaviour
PYTHONPATH=examples/interop python3 -m unittest discover -s examples/interop/tests -p 'test_*.py'
```

Some additional container-side Python checks need dnspython and cryptographic
packages; the [oracle testing guide](../examples/interop/docs/oracle-tests.md)
distinguishes host-only and native/container scopes.

## Independent interoperability

With Docker running:

```sh
python3 examples/interop/run.py --list
python3 examples/interop/run.py full --help
python3 examples/interop/run.py full
```

The full lab builds isolated peers and a private root/TLD/leaf hierarchy, then
checks the shipped CLI, transports, updates, restart persistence, NOTIFY and
signed authority behavior. Optional Hickory checks use `--with-hickory`.
The [recipe index](../examples/interop/docs/recipes.md) specifies which focused
labs own their topology and which extend a retained full lab. Inspect the
command's help before using historical replay or source-archive arguments.

The host harness serializes shared Docker lab work with a lock. Generated
evidence defaults to ignored `.artifacts/`. Drivers may require explicit source
manifests, archives or baseline reports; use the exact candidate's identity,
not metadata copied from a historical control image. A version string such as
`donna 0.1.0` does not uniquely identify a worktree build.

## Performance work

Start from the [published methodology and measurements](benchmarks.md).
Keep semantic, authentication and TTL checks enabled while profiling.
Examples include wire codecs, signatures, signed RRsets, cache behavior and
multi-zone authority selection; these in-process profiles measure a narrower
scope than a network service.

Report runtime/image and source hashes, fixture content, protocol, signing and
validation mode, cache state/population, workers, CPU quota/affinity, client
window, duration, repeats, errors/loss, and correctness gates. Distinguish a
cache hit from a cold iterative request, process startup from network latency,
and client-limited throughput from server capacity. Small repeat counts support
a local comparison, not a statistical guarantee about production workloads.
