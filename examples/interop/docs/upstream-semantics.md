# Authority cases learned from upstream tests

`python/upstream_authority.py` adds a separate deterministic semantic gate for
Donna, BIND, Knot or NSD endpoints serving `fixtures/authority/upstream.zone` as
`example.test.`. It checks 21 cases over UDP and TCP, repeated 40 times by
default to exercise prepared-response paths. It does not start services,
change the existing laboratory, or generate throughput measurements.

The cases were independently derived after reading BIND's
[`tests_wildcard.py`](https://github.com/isc-projects/bind9/blob/main/bin/tests/system/wildcard/tests_wildcard.py).
Its tests exercise wildcard type mismatch, expansion over several labels,
literal asterisk labels, and nested wildcard sources. Its stated omissions
include empty nonterminal blocking, CNAME handling and authority content.
This gate covers those omissions as well. No upstream test code or property
testing dependency is copied into Donna.

| Fixture behavior | Required result | Authority |
| --- | --- | --- |
| Wildcard A queried for A, including a multilabel QNAME | Expanded owner and exact A data | RFC 4592 §§3.3.1–3.3.3 |
| Wildcard A queried for AAAA | NOERROR, empty answer and negative SOA | RFC 4592 §3.3.3; RFC 2308 §2.2/§3 |
| Empty nonterminal `branch` | NOERROR, empty answer; parent wildcard blocked | RFC 4592 §§2.2.2–2.2.3 |
| Missing child below `branch` | NXDOMAIN; no fallback to apex wildcard | RFC 4592 §3.3.1 |
| Missing child below literal `*` owner | NXDOMAIN; wildcard is not recursively reused | RFC 4592 §2.2.1 |
| Wildcard CNAME to a nonexistent child below `branch` | Expanded CNAME plus terminal NXDOMAIN and SOA | RFC 4592 §3.3.3; RFC 2308 §2.1 |
| Same wildcard queried for CNAME | Expanded CNAME and NOERROR; no target chase | RFC 1034 §4.3.2; RFC 4592 §3.3.3 |
| Wildcard CNAME to empty `branch` | Expanded CNAME plus NOERROR and negative SOA | RFC 4592 §3.3.3; RFC 2308 §2.2 |
| Empty wildcard source formed by a descendant | NOERROR, empty answer and SOA | RFC 4592 §4.9 |
| Nested wildcard below two literal asterisks | Expand only from the closest encloser's wildcard | RFC 4592 §§2.2.1/3.3.1 |

[RFC 4592](https://www.rfc-editor.org/rfc/rfc4592.html) is the wildcard source
of truth. In particular, an empty wildcard source differs from an absent
wildcard source: §4.9 requires NOERROR for the former. The fixture includes
`m.*.nested.example.test.` to distinguish these outcomes. Negative SOA TTLs
are checked as `min(SOA TTL, SOA.MINIMUM) = 30` per
[RFC 2308 §3](https://www.rfc-editor.org/rfc/rfc2308.html#section-3).

Load the dedicated fixture into isolated services before running this command;
the ordinary laboratory's fixture does not contain these records. Donna's
existing `listeners` example accepts `ZONE_FILE` for this purpose. The runner
uses the existing laboratory dnspython dependency; no dependencies are added.

```sh
python python/upstream_authority.py \
  --server donna=127.0.0.1:5300 --server bind=127.0.0.1:5353 \
  --server knot=127.0.0.1:5354 --server nsd=127.0.0.1:5355
```

The repository also provides the complete isolated five-authority orchestration
using existing comparison images. BIND's host-name policy is disabled for this
fixture's legal internal-asterisk DNS names:

```sh
python3 examples/interop/run.py similar --upstream-semantics \
  --current-image donna-discovery-current --control-image donna-discovery-current
```

The validation layer can be checked on the host using only Python's standard
library:

```sh
python3 examples/interop/python/authority_expectations_test.py
```

The host-side tests inject wrong terminal RCODEs, aliases, SOA scope/class/TTL,
NS/glue, wildcard data and authority/truncation flags. Historical five-server
result dumps are no longer bundled. The separate
[BIND-derived alias corpus](../../../tests/behaviour/README.md) adds pinned
CNAME/DNAME cases and an endpoint-only network probe.
