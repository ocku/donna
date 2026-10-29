#!/usr/bin/env python3
"""Restart each resolver for every cold comparison; never warm measured owners."""

from support.lock import exclusive_laboratory
from support.daemon import create_recursive

import argparse
import json

from support.topology import NETWORK, PREFIX, docker


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--population", type=int, default=1024)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument("--donna-image", default=PREFIX + "donna")
    args = parser.parse_args()
    if args.repeats < 1 or not 1 <= args.population <= 2048:
        parser.error("positive repeats and population 1..2048 required")
    for kind in ("positive", "negative", "cname"):
        for repeat in range(args.repeats):
            for server in ("donna", "bind") if repeat % 2 == 0 else ("bind", "donna"):
                container = PREFIX + "cold-" + server
                docker("rm", "-f", container, check=False, capture=True)
                try:
                    if server == "donna":
                        create_recursive(
                            container,
                            args.donna_image,
                            NETWORK,
                            "172.29.53.51",
                            "172.29.53.22:53",
                            "172.29.53.0/24",
                        )
                    else:
                        docker(
                            "run",
                            "-d",
                            "--name",
                            container,
                            "--network",
                            NETWORK,
                            "--ip",
                            "172.29.53.50",
                            PREFIX + "cache-peer",
                            capture=True,
                        )
                    output = docker(
                        "run",
                        "--rm",
                        "--network",
                        NETWORK,
                        "--entrypoint",
                        "python",
                        PREFIX + "cache-client",
                        "/suite/cold_load.py",
                        "--server",
                        server,
                        "--workload",
                        kind,
                        "--repeat",
                        str(repeat),
                        "--population",
                        str(args.population),
                        "--load-client",
                        args.load_client,
                        capture=True,
                    )
                    for line in output.splitlines():
                        if line.startswith("{"):
                            row = json.loads(line)
                            row.update(
                                donna_image=args.donna_image,
                                load_client=args.load_client,
                                scope="unsigned local hierarchy; no recursive DNSSEC validation",
                            )
                            print(json.dumps(row), flush=True)
                finally:
                    docker("rm", "-f", container, check=False, capture=True)


if __name__ == "__main__":
    main()
