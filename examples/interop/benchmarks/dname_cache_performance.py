#!/usr/bin/env python3
"""Measure signed DNAME synthesis for distinct owners with cached target A data."""

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path

from labs.dname.dname_cache import wait_ready
from labs.dnssec import chain
from support.lock import exclusive_laboratory
from support.paths import ROOT, SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from benchmarks.cache import cpu_usage

PROBE = PREFIX + "probe"
CLIENT = chain.CLIENT


def row(output):
    values = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    if len(values) != 1:
        raise RuntimeError("expected one result: " + output)
    return values[0]


def invoke(container, role, phase, repeat, population, dnames):
    host, port = ("172.29.53.73", 53) if role == "bind" else ("172.29.53.74", 5301)
    return row(
        docker(
            "exec",
            container,
            "python",
            "/suite/dname_cache_load.py",
            "--host",
            host,
            "--port",
            str(port),
            "--role",
            role,
            "--phase",
            phase,
            "--repeat",
            str(repeat),
            "--population",
            str(population),
            "--dnames",
            str(dnames),
            capture=True,
        )
    )


def old_query_count(log, source):
    pattern = re.compile(r"query: p[0-9]{4}\.old(?:[0-9]{2})?\.example\.test\.? IN A\b")
    return sum(
        source in line and bool(pattern.search(line)) for line in log.splitlines()
    )


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--baseline",
        required=True,
        help="explicit CLI-capable comparison control image",
    )
    parser.add_argument(
        "--baseline-caches-dname",
        action="store_true",
        help="the baseline already implements DNAME caching",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("nsec", "nsec3"), default="nsec")
    parser.add_argument("--population", type=int, default=256)
    parser.add_argument("--dnames", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if (
        args.repeats < 1
        or not 1 <= args.population <= 2048
        or not 1 <= args.dnames <= min(64, args.population)
    ):
        parser.error(
            "positive repeats, population 1..2048 and dnames 1..min(population, 64) required"
        )
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError("ordinary laboratory network exists")
    files = [
        Path(__file__),
        SUITE / "labs/dnssec/chain.py",
        SUITE / "labs/dnssec/chain_fixture.py",
        SUITE / "labs/dname/dname_cache.py",
        SUITE / "python/dname_cache_load.py",
        SUITE / "python/dname_cache_probe.py",
        SUITE / "python/dname_recursive_probe.py",
        SUITE / "python/cache_load.py",
    ]
    images = (
        ("baseline", args.baseline),
        ("candidate", args.candidate),
        ("bind", PREFIX + "bind"),
        ("probe", PREFIX + "peers"),
        ("client", PREFIX + "cache-client"),
    )
    result = {
        "scope": "finite distinct signed DNAME owners, warmed destination A and validated DNSSEC chain; "
        "not steady-state cache-hit throughput or production-network latency",
        "configuration": vars(args),
        "images": {
            name: docker("image", "inspect", image, "--format", "{{.Id}}", capture=True)
            for name, image in images
        },
        "harness_sha256": harness_hashes(ROOT, files),
        "rows": [],
    }
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        docker("volume", "create", chain.VOLUME, capture=True)
        docker(
            "run",
            "-d",
            "--name",
            PROBE,
            "--network",
            NETWORK,
            "-v",
            chain.VOLUME + ":/work:ro",
            PREFIX + "peers",
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            CLIENT,
            "--network",
            NETWORK,
            "-v",
            chain.VOLUME + ":/work:ro",
            "--entrypoint",
            "sleep",
            PREFIX + "cache-client",
            "infinity",
            capture=True,
        )
        for filename in (
            "dname_cache_load.py",
            "dname_cache_probe.py",
            "dname_recursive_probe.py",
            "cache_load.py",
        ):
            for container in (PROBE, CLIENT):
                docker(
                    "cp",
                    str(SUITE / "python" / filename),
                    container + ":/suite/" + filename,
                )
        with tempfile.TemporaryDirectory(prefix="donna-dname-perf-") as temporary:
            directory = Path(temporary)
            chain.prepare(directory, 1, args.mode)
            leaf = docker(
                "exec", chain.SIGNER, "cat", "/work/leaf/zone.db", capture=True
            )

            def suffix(index):
                return "" if args.dnames == 1 else f"{index % args.dnames:02d}"

            additions = "\n" + "".join(
                f"old{suffix(i)} 300 IN DNAME dest{suffix(i)}.example.test.\n"
                f"prime.dest{suffix(i)} 300 IN A 192.0.2.80\n"
                for i in range(args.dnames)
            )
            additions += "".join(
                f"p{i:04d}.dest{suffix(i)} 300 IN A 192.0.2.80\n"
                for i in range(args.population)
            )
            chain.put(directory, "leaf/zone.db", leaf + additions)
            chain.sign("leaf", args.mode)
            docker(
                "exec",
                chain.SIGNER,
                "cp",
                "/work/leaf/signed.db",
                "/work/leaf/active.db",
            )
            result["zone_verification"] = docker(
                "exec",
                "-w",
                "/work/leaf",
                chain.SIGNER,
                "dnssec-verify",
                "-o",
                "example.test.",
                "signed.db",
                capture=True,
            )
            result["fixtures"] = {}
            for zone, origin in chain.ORIGINS.items():
                text = docker(
                    "exec", chain.SIGNER, "cat", f"/work/{zone}/active.db", capture=True
                )
                result["fixtures"][zone] = {
                    "origin": origin,
                    "zone": text,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
            result["anchors"] = docker(
                "exec", chain.SIGNER, "cat", "/work/anchors.zone", capture=True
            )
            chain.start_authorities()
            roles = (
                ("baseline", args.baseline),
                ("candidate", args.candidate),
                ("bind", PREFIX + "bind"),
            )
            for repeat in range(args.repeats):
                order = roles[repeat % 3 :] + roles[: repeat % 3]
                for role, image in order:
                    service = "bind" if role == "bind" else "donna"
                    chain.start_resolver(service, image)
                    try:
                        wait_ready(role)
                        prepared = invoke(
                            PROBE, role, "prepare", repeat, args.population, args.dnames
                        )
                        source = "172.29.53.73" if role == "bind" else "172.29.53.74"
                        before_queries = old_query_count(
                            docker("logs", PREFIX + "chain-leaf", capture=True), source
                        )
                        container = PREFIX + "chain-" + service
                        before_cpu = cpu_usage(container)
                        measured = invoke(
                            CLIENT,
                            role,
                            "measure",
                            repeat,
                            args.population,
                            args.dnames,
                        )
                        elapsed_cpu = cpu_usage(container) - before_cpu
                        after_queries = old_query_count(
                            docker("logs", PREFIX + "chain-leaf", capture=True), source
                        )
                        verified = invoke(
                            PROBE, role, "verify", repeat, args.population, args.dnames
                        )
                        queries = after_queries - before_queries
                        if role == "candidate" and queries != 0:
                            raise RuntimeError(
                                f"candidate queried cached DNAME owners upstream {queries} times"
                            )
                        if role == "baseline":
                            if args.baseline_caches_dname and queries != 0:
                                raise RuntimeError(
                                    f"baseline did not reuse cached DNAME: {queries}"
                                )
                            if (
                                not args.baseline_caches_dname
                                and queries < args.population
                            ):
                                raise RuntimeError(
                                    f"baseline did not request each DNAME owner: {queries}"
                                )
                        item = {
                            "role": role,
                            "repeat": repeat,
                            "prepared": prepared,
                            "measurement": measured,
                            "server_cgroup_cpu_seconds": elapsed_cpu,
                            "old_owner_upstream_queries": queries,
                            "verification": verified,
                        }
                        result["rows"].append(item)
                        print(json.dumps(item), flush=True)
                    finally:
                        chain.stop_resolvers()
        result["result"] = "PASS"
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    finally:
        docker("rm", "-f", PROBE, check=False, capture=True)
        chain.cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)


if __name__ == "__main__":
    main()
