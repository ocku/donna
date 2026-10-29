#!/usr/bin/env python3
"""Compare validating recursion through independently signed root/test/leaf zones."""

import argparse
from collections import Counter
import json
from support.paths import SUITE
from pathlib import Path
import re
import tempfile

from support.lock import exclusive_laboratory
from support.daemon import create_recursive
from support.topology import NETWORK, PREFIX, docker
from .chain_fixture import (
    ORIGINS as ORIGINS,
    SIGNER as SIGNER,
    VOLUME as VOLUME,
    prepare as prepare,
    put as put,
    sign as sign,
)

CLIENT = PREFIX + "chain-client"
AUTHORITIES = ("root", "tld", "leaf")
RESOLVERS = ("donna", "bind")


def stop_resolvers():
    docker(
        "rm",
        "-f",
        *(PREFIX + "chain-" + name for name in RESOLVERS),
        check=False,
        capture=True,
    )


def cleanup():
    stop_resolvers()
    docker(
        "rm",
        "-f",
        CLIENT,
        SIGNER,
        *(PREFIX + "chain-" + name for name in AUTHORITIES),
        check=False,
        capture=True,
    )
    docker("volume", "rm", VOLUME, check=False, capture=True)


def start_authorities():
    for index, name in enumerate(AUTHORITIES):
        docker(
            "run",
            "-d",
            "--name",
            PREFIX + "chain-" + name,
            "--network",
            NETWORK,
            "--ip",
            f"172.29.53.{70 + index}",
            "-v",
            VOLUME + ":/work:ro",
            PREFIX + "bind",
            "named",
            "-g",
            "-n",
            "2",
            "-c",
            "/work/" + name + ".conf",
            "-u",
            "root",
            capture=True,
        )


def start_resolver(server, image):
    stop_resolvers()
    name = PREFIX + "chain-" + server
    if server == "bind":
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--network",
            NETWORK,
            "--ip",
            "172.29.53.73",
            "-v",
            VOLUME + ":/work:ro",
            PREFIX + "bind",
            "named",
            "-g",
            "-n",
            "2",
            "-c",
            "/work/recursive.conf",
            "-u",
            "root",
            capture=True,
        )
    else:
        create_recursive(
            name,
            image,
            NETWORK,
            "172.29.53.74",
            "172.29.53.70:53",
            "172.29.53.0/24",
            anchors="/work/anchors.zone",
            options=("-v", VOLUME + ":/work:ro"),
        )


def client(*args, diagnostic=False):
    output = docker(
        "exec", CLIENT, "python", "/suite/chain_load.py", *args, capture=True
    )
    mode = args[args.index("--mode") + 1]
    rows = []
    cold_chain = "--cold-chain-batch" in args
    for line in output.splitlines():
        row = json.loads(line)
        row.setdefault("mode", mode)
        row["diagnostic"] = diagnostic
        if "qps" in row:
            row["phase"] = (
                "cold_owners_fresh_chain" if cold_chain else "cold_owners_warm_chain"
            )
            row["scope"] = (
                "fresh resolver finite batch; no DNS control query; normal startup/root priming retained"
                if cold_chain
                else "cold client owners; delegation/DNSKEY caches warmed separately; denial proof reuse allowed"
            )
        rows.append(row)
        print(json.dumps(row), flush=True)
    return rows


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=PREFIX + "donna")
    parser.add_argument("--mode", choices=("nsec", "nsec3", "both"), default="both")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument(
        "--cold-chain-batch",
        action="store_true",
        help="measure a finite batch on each fresh resolver before any control DNS query",
    )
    parser.add_argument(
        "--compare-chain-state",
        action="store_true",
        help="alternate fresh-chain and warmed-chain batches with identical signed fixtures",
    )
    parser.add_argument(
        "--workload", choices=("all", "positive", "negative", "nodata"), default="all"
    )
    parser.add_argument(
        "--diagnostic-query-logs",
        action="store_true",
        help="retain authority query logging for acquisition counts; exclude these timings from performance comparisons",
    )
    args = parser.parse_args()
    if args.repeats < 1 or not 1 <= args.population <= 2048:
        parser.error("positive repeats and population 1..2048 required")
    if args.cold_chain_batch and args.compare_chain_state:
        parser.error("choose cold-chain-batch or compare-chain-state")
    cleanup()
    try:
        print(
            json.dumps(
                {
                    "images": {
                        "donna": docker(
                            "image",
                            "inspect",
                            args.donna_image,
                            "--format",
                            "{{.Id}}",
                            capture=True,
                        ),
                        "bind": docker(
                            "image",
                            "inspect",
                            PREFIX + "bind",
                            "--format",
                            "{{.Id}}",
                            capture=True,
                        ),
                    }
                }
            ),
            flush=True,
        )
        for mode in ("nsec", "nsec3") if args.mode == "both" else (args.mode,):
            with tempfile.TemporaryDirectory(prefix="donna-chain-") as temporary:
                prepare(Path(temporary), args.population, mode)
                docker(
                    "run",
                    "-d",
                    "--name",
                    CLIENT,
                    "--network",
                    NETWORK,
                    "--entrypoint",
                    "sleep",
                    PREFIX + "cache-client",
                    "infinity",
                    capture=True,
                )
                docker(
                    "cp",
                    str(SUITE / "python/chain_load.py"),
                    CLIENT + ":/suite/chain_load.py",
                )
                docker(
                    "exec", SIGNER, "cp", "/work/tld/bad-ds.db", "/work/tld/active.db"
                )
                start_authorities()
                for server in RESOLVERS:
                    start_resolver(server, args.donna_image)
                    client("--server", server, "--mode", mode, "--verify-bad-ds")
                stop_resolvers()
                docker(
                    "exec", SIGNER, "cp", "/work/tld/signed.db", "/work/tld/active.db"
                )
                docker("restart", PREFIX + "chain-tld", capture=True)
                control_flags = {}
                for server in RESOLVERS:
                    start_resolver(server, args.donna_image)
                    rows = client("--server", server, "--mode", mode, "--verify-chain")
                    control_flags[server] = next(
                        row["response_flags"] for row in rows if "response_flags" in row
                    )
                stop_resolvers()
                logs = {
                    name: docker("logs", PREFIX + "chain-" + name, capture=True)
                    for name in AUTHORITIES
                }
                witnesses = {}
                for address in ("172.29.53.73", "172.29.53.74"):
                    for zone, origin in ORIGINS.items():
                        owner = origin.rstrip(".") if origin != "." else "."
                        match = re.search(
                            re.escape(address)
                            + r"#.*query: "
                            + re.escape(owner)
                            + r"\.? IN DNSKEY\b",
                            logs[zone],
                        )
                        assert match, (address, zone, "missing chain DNSKEY query")
                        witnesses[address + "/" + zone] = match[0]
                print(
                    json.dumps(
                        {
                            "verification": "both resolvers fetched root/TLD/leaf DNSKEY sets",
                            "mode": mode,
                            "witnesses": witnesses,
                        }
                    ),
                    flush=True,
                )
                # Query logging is useful for the chain security gate, but
                # would add per-query I/O to timed cold-owner comparisons.
                if not args.diagnostic_query_logs:
                    for name in AUTHORITIES:
                        docker(
                            "exec",
                            SIGNER,
                            "sed",
                            "-i",
                            "s/querylog yes/querylog no/",
                            "/work/" + name + ".conf",
                        )
                        docker("restart", PREFIX + "chain-" + name, capture=True)
                for kind in ("positive", "negative", "nodata"):
                    if args.workload != "all" and kind != args.workload:
                        continue
                    for repeat in range(args.repeats):
                        states = (
                            ((True, False) if repeat % 2 == 0 else (False, True))
                            if args.compare_chain_state
                            else (args.cold_chain_batch,)
                        )
                        for cold in states:
                            for server in (
                                RESOLVERS
                                if repeat % 2 == 0
                                else tuple(reversed(RESOLVERS))
                            ):
                                start_resolver(server, args.donna_image)
                                cold_arguments = (
                                    (
                                        "--cold-chain-batch",
                                        "--expected-response-flags",
                                        str(control_flags[server]),
                                    )
                                    if cold
                                    else ()
                                )
                                client(
                                    "--server",
                                    server,
                                    "--mode",
                                    mode,
                                    "--workload",
                                    kind,
                                    "--repeat",
                                    str(repeat),
                                    "--population",
                                    str(args.population),
                                    "--load-client",
                                    args.load_client,
                                    *cold_arguments,
                                    diagnostic=args.diagnostic_query_logs,
                                )
                                stop_resolvers()
                if args.diagnostic_query_logs:
                    counts = {}
                    for zone in AUTHORITIES:
                        after = docker("logs", PREFIX + "chain-" + zone, capture=True)
                        pattern = r"(172\.29\.53\.(?:73|74))#.*query: \S+ IN (\S+)"
                        delta = Counter(re.findall(pattern, after)) - Counter(
                            re.findall(pattern, logs[zone])
                        )
                        counts[zone] = {
                            address + "/" + rtype: count
                            for (address, rtype), count in sorted(delta.items())
                        }
                    print(
                        json.dumps(
                            {
                                "diagnostic": "query counts after security gates, including separate first client queries",
                                "mode": mode,
                                "authority_query_counts": counts,
                            }
                        ),
                        flush=True,
                    )
                print(
                    json.dumps(
                        {
                            "query_logging_during_timing": args.diagnostic_query_logs,
                            "security_gate_query_counts": {
                                zone: dict(
                                    Counter(re.findall(r"query: \S+ IN (\S+)", log))
                                )
                                for zone, log in logs.items()
                            },
                            "mode": mode,
                            "donna_image": docker(
                                "image",
                                "inspect",
                                args.donna_image,
                                "--format",
                                "{{.Id}}",
                                capture=True,
                            ),
                        }
                    ),
                    flush=True,
                )
            cleanup()
    finally:
        cleanup()


if __name__ == "__main__":
    main()
