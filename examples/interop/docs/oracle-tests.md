# Run the oracle tests

The oracle tests check the harness's own answer, DNSSEC, TTL, correlation,
capture and accounting gates. They inject wrong data into controlled models.
A passing oracle test does not establish that a running Donna process produces
correct answers; use the network labs and Rust regressions for that evidence.

Install the declared Python dependencies in an isolated environment, then run
the host scope from the repository root:

```sh
python3 -m venv /tmp/donna-oracles
/tmp/donna-oracles/bin/pip install -r examples/interop/python/requirements.txt
/tmp/donna-oracles/bin/python examples/interop/run.py oracle-tests
```

`--list` shows the selected modules. This scope starts no services and requires
no generated reports. The signed-chain, NSEC/NSEC3 and signature-source tests
generate small catalogs using test-only keys and dnspython. The oversized-SOA
and memory-accounting inputs are synthetic consistency models. They represent
no historical network capture, memory sample, executable build or performance
measurement. The fixed DNSSEC test clock makes chain expiration tests independent
of the wall clock; signature-source tests sign at their current validation time.
The host scope also runs the [remote cache-provider verifier tests](../../adapters/remote/README.md#offline-verifier-tests)
against a synthetic signed 73-reply model; no Redis or PostgreSQL service is needed.

The memory replay tests can also check an explicit measured capsule:

```sh
PYTHONPATH=examples/interop/python /tmp/donna-oracles/bin/python \
  examples/interop/python/service_memory_replay_test.py /path/to/capsule
```

`DONNA_SERVICE_MEMORY_CAPSULE=/path/to/capsule` selects the same input during
discovery. The test copies it into a temporary directory before injecting
faults and preserves the source capsule. An explicitly selected missing or
invalid capsule fails; it never falls back to the synthetic model.

The native scope requires Linux UDP batching and compiled diagnostic helpers:

```sh
python examples/interop/run.py oracle-tests --scope native
python examples/interop/run.py oracle-tests --scope all
```

Run those commands in a Linux environment with `batched_load`,
`batched_load_clock_delay`, and `clock_snapshot_test` on `PATH`. All three are
built from the current C sources by
[RecursiveClient.Dockerfile](../docker/RecursiveClient.Dockerfile). Captures must
use the current `DNSCAP03` format with explicit capture-budget and coherent
clock metadata. Missing helpers cause an explicit prerequisite error before any
selected tests run. Historical measurement archives retain their original
harness sources; the current decoder does not accept older capture formats.

For raw unittest discovery, add the source layouts to `PYTHONPATH` and provide
the native helpers:

```sh
PYTHONPATH=examples/interop/python:examples/interop/support \
  python -m unittest discover -s examples/interop/python -p '*_test.py'
```

The host driver helpers have a separate suite:

```sh
PYTHONPATH=examples/interop python -m unittest discover -s examples/interop/tests
```
