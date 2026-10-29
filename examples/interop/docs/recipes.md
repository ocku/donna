# Choose a lab

From the repository root, use `python3 examples/interop/run.py COMMAND --help`.
`--list` shows every command and its source module.

| Goal | Command | Setup |
| --- | --- | --- |
| Every transport and language client, updates and DNSSEC | `full` | Builds and owns the complete isolated lab |
| Signed authority/denial captures | `signed` | Extends a full lab retained with `full --keep` |
| Wildcards, empty nodes, referrals and glue | `similar --upstream-semantics` | Own comparison lab; requires comparison images |
| DNAME authority semantics | `dname-authority` | Own comparison lab |
| Recursive negative/cache key semantics | `recursive-semantics` | Own isolated hierarchy |
| Recursive failures and ancestor recovery | `ancestor-failures`, `recursive-peer-smoke` | Own isolated peer fixtures |
| Signed root/TLD/leaf hierarchy | `chain` | Extends a running full lab |
| DNAME recursive/cache/cross-zone behaviour | `dname-recursive`, `dname-cache`, `dname-cross-zone`, `dname-mixed`, `dname-edns` | Most use the retained full lab; inspect command help |
| Independent transport/framing checks | `transport-compare`, `doh-codec`, `hickory-clients` | Comparison images or retained full lab |
| Public Internet DNSSEC | `public` | Separate CLI image and outbound UDP/TCP 53 |
| Authority/resolver load | `authority`, `similar`, `recursive-performance` | Prebuilt service/load-client images |
| Cache and signed validation load | `cache`, `cold`, `validating` | Retained full lab |
| Diversity and wire ingress comparisons | `diversity-compare`, `ingress-wire-compare` | Dedicated comparison images; explicit source/report inputs where required |
| Signed negative-cache replay | `negative-discovery`, `negative-compare`, `recursive-compare` | Explicit manifests, archives and baseline reports |
| Process memory and UDP batch counters | `service-memory-compare`, `batch-histogram` | Dedicated runtime/client images; explicit build report for memory comparison |
| Declared dependency provenance | `audit-dependencies` | Host-side lockfile/package metadata only |
| Fault injection into independent harness oracles | `oracle-tests` | Declared Python dependencies; [host/native scopes](oracle-tests.md) |

Benchmarks are opt-in. Their configured worker counts, offered load, loss gates
and independent pre/postchecks determine the scope of their results. A passing
behaviour gate is not a throughput measurement or blanket RFC-conformance
claim. Keep generated reports in `.artifacts/` or another explicit output path.

The [standalone behaviour probe](../../../tests/behaviour/README.md) takes
explicit authority endpoints and performs no container lifecycle or load test.

Live recursive candidates use the shipped CLI image, `donna-interop-donna`,
built by `docker/Donna.Dockerfile`. The signed evidence drivers
`negative-discovery`, `negative-compare`, and `recursive-compare` require the
exact candidate's `--donna-source-manifest` and `--donna-source-archive`, even
when using the default image. A historical baseline report supplies offline
comparison metadata; its source identity is never reused as the live candidate's
identity. These drivers check the CLI before allocating lab resources.

The DNAME cache/mixed/performance comparisons now require an explicit
`--baseline` CLI-capable control image alongside `--candidate`. The established
`recursive-performance --baseline-image` path retains its explicitly named
legacy example launcher. Ordinary candidate runs use the CLI throughout.

Evidence source hashes include static local Python imports as well as each
driver's explicit fixture and native-source inputs. The expanded source set is
also retained in archived harnesses. Dynamic inputs still need explicit entries;
third-party Python packages are bound through the recorded environment/images.
