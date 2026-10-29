# Observable recursive cache behavior

`recursive_semantics.py` compares Donna and BIND recursive servers against a
separate Python DNS authority. It uses only existing Docker images and the
laboratory's existing dnspython dependency inside Docker. No host DNS library,
new package, forwarding service or public DNS connectivity is needed.

```sh
python3 examples/interop/run.py recursive-semantics --donna-image donna-discovery-current
```

The independent authority serves UDP and TCP, records every received QNAME and
QTYPE, and exposes counters and a generation switch over isolated fixture HTTP.
Each resolver/client-transport combination has separate names. The driver
serializes with existing performance laboratories and removes its containers
and network on success or failure. It neither rebuilds nor removes images.

| Case | Required answer and upstream behavior | Source of truth |
| --- | --- | --- |
| Positive cold/warm | Exact A value; initial upstream request, no request on warm reuse | RFC 1034 §4.3.4 |
| NXDOMAIN A then AAAA | NXDOMAIN with zone SOA; no new upstream request for AAAA | RFC 2308 §5: name/class cache identity |
| NODATA A then AAAA | Repeated A NODATA without upstream; AAAA must query upstream and return its real data | RFC 2308 §5: name/type/class identity |
| CNAME to missing name | CNAME plus terminal NXDOMAIN; CNAME queries still succeed; direct target AAAA uses terminal NXDOMAIN | RFC 2308 §2.1/§5 |
| CNAME to an owner with another type | CNAME plus A NODATA; target AAAA remains available; CNAME owner stays positive | RFC 2308 §2.2/§5 |
| Positive and negative TTL countdown | Both TTLs decrease after an elapsed interval without upstream work | RFC 2308 §5; RFC 1035 §3.2.1 |
| Positive/negative expiration | Authority changes generation; after original TTL expires, both names cause new authority traffic and return changed positive data | RFC 2308 §5; RFC 1035 §3.2.1 |
| Live CNAME with expired negative target | Retain the longer-lived CNAME, reacquire target and return CNAME plus changed A data | RFC 1034 §4.3.2; RFC 2308 §2.1/§5 |

The TTL assertions were independently designed after reviewing BIND's
[`tests_cache_ttl.py`](https://github.com/isc-projects/bind9/blob/main/bin/tests/system/ttl/tests_cache_ttl.py),
which checks TTLs across answer and authority data under configured bounds.
No upstream test code or property-testing library is copied. Negative identity,
terminal scope and expiration requirements come directly from
[RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html#section-5).
The authority supplies a six-second minimized negative SOA TTL and six-second
positive TTL; CNAMEs last thirty seconds. BIND's minimum TTL overrides and
stale-answer serving are explicitly disabled for this comparison.

This is an unsigned deterministic cache fixture. The same authority process
serves root priming and the example.test data, so it provides no new independent
hierarchical traversal, delegation security, DNSSEC, failure-cache or throughput
claim. Counter assertions prove which fixture names reached this authority;
they do not infer cache hits merely from repeated successful responses.

Use `recursive-semantics --help` for image and output options. Generated reports
are written to ignored `.artifacts/` or an explicit output path; historical
measurements are no longer bundled. See [failure cases](resolution-failures.md)
for SERVFAIL/REFUSED and DNSSEC failure suppression.
