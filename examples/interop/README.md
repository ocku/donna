# DNS interoperability labs

Use the [CLI and small Rust examples](../README.md) for a local server/client pair.
These labs add independent BIND, Python, Go, Node and optional Hickory peers.
Run commands from the repository root with a running Docker daemon.

```sh
python3 examples/interop/run.py --list
python3 examples/interop/run.py full --help
python3 examples/interop/run.py full
```

The full lab builds its images, creates an isolated root → TLD → authority
hierarchy, checks transports, shipped CLI clients, updates/restart/NOTIFY and signed NSEC/
NSEC3 responses, then removes its containers, networks and volumes. Docker
Compose is optional. Initial builds need registry/package access; the ordinary
lab needs no public DNS connection or host Python packages.

```sh
python3 examples/interop/run.py full --skip-build --fuzz 1000
python3 examples/interop/run.py full --skip-build --keep
python3 examples/interop/run.py full --cleanup
```

`--donna-image IMAGE` selects a separately built runtime. `--with-hickory` adds
the pinned independent authority and clients. `--keep` retains the full lab even
on failure. Names beginning `donna-interop-` and subnet `172.29.53.0/24` belong
to that lab; the next full run replaces them. Other labs describe their own
resources in `COMMAND --help`. Host-side Docker jobs share a lock.

| Directory | Purpose |
| --- | --- |
| `labs/authority/` | Independent authority semantics, DNAME, NSEC3 and signature checks |
| `labs/recursive/` | Recursive semantics, failure/recovery and peer checks |
| `labs/dname/` | Focused DNAME cache and cross-zone scenarios |
| `labs/dnssec/` | Signed chains, validation, insecure delegations and optional public DNS |
| `labs/transport/` | Framing, malformed ingress, truncation and client interoperability |
| `benchmarks/` | Load, cache, diversity, CPU/memory and histogram experiments |
| `fixtures/` | Static zones and authority configurations, grouped by scenario |
| `python/`, `go/`, `node/` | Container-side protocol peers, clients and independent oracles |
| `support/` | Shared host-side Docker, paths, locking, topology and evidence utilities |
| `tools/` | Dependency provenance audit |
| `tests/` | Rust integration checks and host-side Python harness tests |
| `src/bin/`, `profile/`, `portability/` | Rust profilers, public validation tools and focused transport harnesses |
| `docs/` | [Recipes](docs/recipes.md), [clients](docs/clients.md), [coverage](docs/coverage.md), [upstream semantics](docs/upstream-semantics.md) |

The single `run.py COMMAND` dispatcher loads the chosen module; drivers import
shared helpers explicitly and do not import the full runner. The lab Cargo
manifest aliases application sources in sibling example packages, preserving
specialized binary names such as `listeners`, `recursive` and `updates`.
Ordinary recursive service and client checks in the full lab use the shipped
`donna` binary. The specialized daemons remain library examples for experiments
that inspect internal hooks or supply application-owned fixtures.

Generated results, JSON reports, binary archives and agent handoff logs have
been removed. New experiment outputs default to ignored `.artifacts/`, or use
an explicit `--output` path. Historical replay commands require explicit report
or archive inputs; no bundled report silently selects a runtime or fixture.
Keep reusable inputs in `fixtures/` and generated output outside source control.

Check the host harness without Docker:

```sh
PYTHONPATH=examples/interop python3 -m unittest discover -s examples/interop/tests -p 'test_*.py'
python3 examples/interop/python/authority_expectations_test.py
```

The separate [BIND-derived behaviour corpus](../../tests/behaviour/README.md)
can run through Rust tests or against explicit UDP/TCP endpoints without this
lab. Fixed TSIG, SIG(0) and DNSCrypt keys are public test fixtures; TLS keys are
generated for each lab run.
