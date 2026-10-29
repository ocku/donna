# Behaviour covered by the labs

The [recipe index](recipes.md) identifies each runnable driver and its setup.
Passing a bounded lab checks those scenarios, not every requirement of every
referenced RFC. Optional comparison/benchmark commands are separate from `full`.

| Area | Checks | Entry point |
| --- | --- | --- |
| Transport interoperability | UDP, TCP, TLS, HTTPS GET/POST, QUIC and DNSCrypt against independent peers | `full` |
| Client implementations | Shipped Donna CLI, embedded cache API and independent Python, Go and Node clients | `full`; [client guide](clients.md) |
| Query flags and errors | RD/CD/AD/DO combinations, negative answers, EDNS errors, malformed packets and stream abuse | `full`; `transport-compare` |
| Authoritative operations | AXFR, authorized TSIG/SIG(0) updates, prerequisites, deletion, durable restart and NOTIFY | `full` |
| DNSSEC authority | Independently generated NSEC/NSEC3 zones, signatures and required denial witnesses over each transport | `signed`, invoked by `full` |
| Root trust and recursive validation | Independently signed root/TLD/leaf chain, positive/negative results, incorrect DS rejection and CD bypass | `chain`, `signed-failure` |
| Authority selection | Wildcards, empty nonterminals, literal asterisks, CNAME terminal scope, cuts, parent DS and glue | `similar --upstream-semantics`; [oracle](upstream-semantics.md) |
| Alias boundaries | CNAME/DNAME chase/stop behaviour, ANY compatibility, negative targets and referrals | [Standalone BIND-derived corpus](../../../tests/behaviour/README.md) |
| Recursive caches | Counted upstream traffic, NXDOMAIN/NODATA key scope, alias scope and original expiry | `recursive-semantics`; [guide](recursive-semantics.md) |
| Resolution failures | Counted SERVFAIL/REFUSED reuse, healthy alternate type, DNSSEC BAD suppression and recovery | [Failure guide](resolution-failures.md) |
| Application storage | Public memory adapter and separate Redis/PostgreSQL cache/zone-store examples | [Adapters](../../adapters/README.md) |

The ordinary lab uses an unsigned isolated hierarchy; signed chain tests supply
explicit local anchors. `public` separately requires Internet access and uses
changing public DNS data. Encrypted protocol peers are deliberately small test
servers forwarding to BIND, not production resolver implementations.

The Python harness tests exercise its oracles independently, including injected
wrong flags, data, TTLs, negative SOAs, referrals and traffic counts. Rust tests
check the library state machines and public APIs. A network run is needed to
validate a particular built runtime; old generated reports are no longer bundled.

Reference texts are maintained in [rfcs/](../../../rfcs/). The individual
guides describe executable coverage and remaining protocol boundaries. Benchmarks report their configured workload and observation
limits; they do not expand the semantic coverage described here.
