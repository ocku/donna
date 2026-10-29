#!/usr/bin/env python3
"""Explore and run the isolated DNS labs and benchmarks.

Use --list to browse commands; COMMAND --help describes its own setup/options.
With no command, options are passed to the full interoperability laboratory.
"""

from pathlib import Path
import runpy
import sys

COMMANDS = {
    "ancestor-failures": "labs.recursive.ancestor_failures",
    "audit-dependencies": "tools.audit_dependencies",
    "authority": "benchmarks.authority",
    "batch-histogram": "benchmarks.batch_histogram",
    "cache": "benchmarks.cache",
    "chain": "labs.dnssec.chain",
    "cold": "benchmarks.cold",
    "similar": "labs.authority.similar",
    "diversity-candidate": "benchmarks.diversity_candidate",
    "diversity-compare": "benchmarks.diversity_compare",
    "dname-authority": "labs.authority.dname_authority",
    "dname-cache": "labs.dname.dname_cache",
    "dname-cache-performance": "benchmarks.dname_cache_performance",
    "dname-cross-zone": "labs.dname.dname_cross_zone",
    "dname-edns": "labs.dname.dname_edns",
    "dname-mixed": "labs.dname.dname_mixed",
    "dname-recursive": "labs.dname.dname_recursive",
    "doh-codec": "labs.transport.doh_codec",
    "full": "labs.full",
    "hickory-clients": "labs.transport.hickory_clients",
    "ingress-wire-compare": "labs.transport.ingress_wire_compare",
    "insecure-delegation": "labs.dnssec.insecure_delegation",
    "negative-compare": "benchmarks.negative_compare",
    "negative-discovery": "benchmarks.negative_discovery",
    "nsec3-owners": "labs.authority.nsec3_owners",
    "oracle-tests": "tools.test_oracles",
    "public": "labs.dnssec.public",
    "qcount-recheck": "labs.transport.qcount_recheck",
    "recursive-compare": "benchmarks.recursive_compare",
    "recursive-peer-smoke": "labs.recursive.recursive_peer_smoke",
    "recursive-performance": "benchmarks.recursive_performance",
    "recursive-semantics": "labs.recursive.recursive_semantics",
    "service-memory-compare": "benchmarks.service_memory_compare",
    "signature-sources": "labs.authority.signature_sources",
    "signed": "labs.dnssec.signed",
    "signed-failure": "labs.dnssec.signed_failure",
    "transport-compare": "labs.transport.transport_compare",
    "truncated-client-audit": "labs.transport.truncated_client_audit",
    "validating": "labs.dnssec.validating",
}


def main():
    arguments = sys.argv[1:]
    if arguments and arguments[0] in ("--list", "--help", "-h"):
        print(__doc__)
        for command, module in COMMANDS.items():
            print(f"  {command:26} {module.replace('.', '/')}.py")
        return
    command = (
        arguments.pop(0) if arguments and not arguments[0].startswith("-") else "full"
    )
    if command not in COMMANDS:
        raise SystemExit(
            f"Unknown command: {command}. Use --list to explore available labs."
        )
    sys.argv = [f"{Path(__file__).name} {command}", *arguments]
    runpy.run_module(COMMANDS[command], run_name="__main__")


if __name__ == "__main__":
    main()
