# Observable resolution failures

The independent recursive comparison has a failure mode:

```sh
python3 examples/interop/run.py recursive-semantics --donna-image IMAGE --failure-cache
```

An isolated Python authority returns SERVFAIL or REFUSED for A while returning
valid AAAA at the same name. Its counters distinguish actual upstream work
from merely receiving the same error twice. For Donna and BIND over UDP/TCP,
the probe checks cold failure, immediate reuse, reuse after half a second,
healthy alternate QTYPE, repeated CD failure reuse and recovered data after the
local suppression interval. Five standard-library fault-injection tests check
the result/flag/data and traffic gates:

```sh
python3 examples/interop/python/resolution_failure_checks_test.py
```

A second gate uses actual independently signed root, test and example.test
zones with only the root KSK configured as the resolver's anchor:

```sh
python3 examples/interop/run.py signed-failure --donna-image IMAGE --mode both
```

Run this gate while the ordinary interoperability laboratory is stopped: it
refuses an existing laboratory network instead of altering its owner's work.
The fixture signs an incorrect child DS with the genuine TLD key. Independent
BIND `dnssec-verify` checks each zone's mathematical signatures. Public signed
zones and hashes are retained in the output; generated private signing keys
are discarded with the temporary volume after the run.

For NSEC and NSEC3, each resolver must acquire root/TLD/leaf DNSKEYs, reject
the incorrect chain with SERVFAIL and AD clear, suppress every authority query
on an immediate repeat, allow CD data with AD clear, and still reject an
ordinary query after the CD bypass. Authority logs count every query from the
resolver's address, including ancestor DS/DNSKEY lookups. Observation windows
must remain below the one-second minimum failure interval; a slower observation
is rejected without a cache verdict. This is a cache correctness observation,
not a performance measurement.


Use each command’s `--help` for runtime and output options. Historical results
have been removed; rerun against the runtime you want to validate. The
[failure-cache implementation](../../../crates/resolver/src/cache/failure/mod.rs) and
[regressions](../../../crates/resolver/src/resolver/tests/failure.rs) describe
the retained state and its boundaries. These tests do not establish exhaustive
failure, backoff or ancestor-throttling compliance.
