# DNS behavioural corpus

These tests use public Donna APIs and an independent network oracle. They do
not need the interoperability lab. [authority.tsv](authority.tsv) is the
readable case table; [authority.zone](authority.zone) is its small unsigned
fixture. Both the Rust regression and Python network probe read that table.

From the repository root:

```sh
cargo test --locked -p nameserver --test upstream_authority
python3 -m unittest discover -s tests/behaviour
python3 tests/behaviour/probe.py --list
```

The Rust test installs the fixture through `Zone`/`NameServer`, checks all 16
cases with RD clear/set and 40 repetitions (1,280 responses), and verifies
answers including TTLs, response flags, question correlation, terminal negative
SOA data and delegation glue. The standard-library Python tests inject wrong
answers, duplicates, TTLs, negative SOAs, flags and referrals into the independent
oracle. They do not substitute for checking real servers.

To check network behaviour, start the small authority in another terminal:

```sh
cargo run --locked -- check -c tests/behaviour/donna.toml
cargo run --locked -- serve -c tests/behaviour/donna.toml
```

Then use an environment with dnspython (the existing interop peers image has it):

```sh
python3 tests/behaviour/probe.py --server donna=127.0.0.1:5300 --repeats 40
```

The probe checks UDP and TCP, RD clear/set, and every repetition independently.
It reports JSON lines and exits nonzero on any failed row. Add more `--server`
arguments to check other authorities serving the identical fixture. It starts
no services and performs no cleanup or benchmark traffic. The full-lab probe
container can run it without installing Python packages on the host:

```sh
docker cp tests/behaviour donna-interop-probe:/corpus
docker exec donna-interop-probe python /corpus/probe.py --server bind=172.29.53.20:53
```

Load `authority.zone` into that BIND instance first; the ordinary lab's zone
contains different records. BIND should have recursion disabled and
`minimal-any no;` for this exact traditional-ANY compatibility corpus.

## Provenance and scope

The new alias cases were independently written after reading BIND's
[`auth/tests.sh` at 917c4f7e](https://github.com/isc-projects/bind9/blob/917c4f7ee9f2c2f25350a6a5bb6be3b207588a51/bin/tests/system/auth/tests.sh).
[sources.json](sources.json) records the full immutable revision, file paths,
SHA-256 hashes and implemented/candidate status. No upstream source or fixture
is vendored; no upstream test framework is required.

| Cases | Source and expected behaviour |
| --- | --- |
| In-zone CNAME, chain and AAAA mismatch | BIND auth in-zone cases; [RFC 1034 §4.3.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.2): follow aliases to terminal data or NODATA |
| Direct CNAME query | BIND auth CNAME case; RFC 1034 §4.3.2: return the alias without chasing |
| External CNAME with RD clear/set | BIND auth RD/RA matrix; authority-only service has RA clear and returns the alias without recursion |
| CNAME to missing name or empty nonterminal | Extension of the alias cases; [RFC 2308 §§2–3](https://www.rfc-editor.org/rfc/rfc2308.html#section-2): preserve aliases, terminal NXDOMAIN/NODATA and negative SOA TTL |
| DNAME owner versus descendant, chain, terminal negative | [RFC 6672 §§2.2–2.3, 3.1–3.2](https://www.rfc-editor.org/rfc/rfc6672.html#section-2.2): substitute only descendants; synthesized CNAME inherits DNAME TTL |
| DNAME followed by QTYPE=CNAME | BIND auth DNAME case; RFC 6672 §3.1: return the DNAME and synthesized CNAME |
| CNAME/DNAME QTYPE=ANY | BIND auth compatibility cases: return aliases at the queried name and stop; these pin Donna's traditional ANY policy |
| Below-cut ANY | BIND auth delegation case; referral NS, available in-domain glue, no AA or negative SOA; [RFC 9471 §3.1](https://www.rfc-editor.org/rfc/rfc9471.html#section-3.1) |

ANY is an explicit compatibility choice here. [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482.html)
allows other response policies; differences from this fixture are not by
themselves proof of noncompliance. The tests make no DNSSEC, recursive-service,
exhaustive RFC or performance claim. The existing
[wildcard/empty-node corpus](../../examples/interop/docs/upstream-semantics.md) remains
separate and runnable through its established comparison lab.

The first run exposed an extra target CNAME in Donna's DNAME/ANY answer. BIND
9.18.49 passed the expected two-record shape over UDP/TCP with both RD settings;
Donna now stops after the synthesized CNAME for ANY as it already did for CNAME.

## Next upstream material

The pinned BIND files in `sources.json` provide concrete follow-up work:

- `cname_recursion/tests_cname_recursion.py`: hosted-zone CNAMEs whose targets
  need recursive resolution, including dynamically added and catalog zones.
  Adapt the recursive behaviour independently; Donna has no BIND catalog-zone API.
- `formerr/tests_formerr.py`: malformed section contents, forbidden name
  compression, pointer-hop and whole-message decompression budgets. Translate
  wire cases to `dns`/`transport` tests without importing BIND's `isctest` helpers.
- `masterfile/tests_masterfile.py`: owner inheritance, RFC 1035 lexical semantics
  and include/origin restoration. Separate supported parser behaviour from
  BIND-specific file/template/include policy.

These are reviewed source candidates, not newly passing Donna coverage. Keep
upstream implementation choices distinct from RFC requirements when importing
more cases.

Unbound also has a substantial declarative replay collection. Three reviewed,
pinned candidates in `sources.json` are
[`iter_dname_ttl0.rpl`](https://github.com/NLnetLabs/unbound/blob/e78d0a1c03e40602e81d0c440190134106cf6ffc/testdata/iter_dname_ttl0.rpl)
(zero-TTL DNAME and a cache grace policy),
[`iter_scrub_dname_out_of_zone.rpl`](https://github.com/NLnetLabs/unbound/blob/e78d0a1c03e40602e81d0c440190134106cf6ffc/testdata/iter_scrub_dname_out_of_zone.rpl)
(reject out-of-zone answer DNAMEs), and
[`val_cnametonodata.rpl`](https://github.com/NLnetLabs/unbound/blob/e78d0a1c03e40602e81d0c440190134106cf6ffc/testdata/val_cnametonodata.rpl)
(authenticated CNAME-to-NODATA). Their `QUERY`, `CHECK_OUT_QUERY`, `REPLY` and
`CHECK_ANSWER` steps are useful models for Donna's fake-upstream resolver tests.
The historical DNSSEC fixtures use overridden dates and test-only SHA-1 handling;
recreate those scenarios with modern test keys. Unbound's cache grace period is
an implementation policy to assess separately, not an expiry requirement.
