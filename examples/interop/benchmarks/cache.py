#!/usr/bin/env python3
"""Run optional cache CPU and independent BIND network comparisons."""

from support.lock import exclusive_laboratory
from support.daemon import create_recursive

import argparse
import json
import time

from support.topology import NETWORK, PREFIX, docker


def cpu_usage(container):
    values = dict(
        line.split()
        for line in docker(
            "exec", container, "cat", "/sys/fs/cgroup/cpu.stat", capture=True
        ).splitlines()
    )
    return int(values["usage_usec"]) / 1_000_000


def measure_with_cpu(args, donna, peer):
    containers = {"donna": donna, "bind": peer}
    for kind in ("positive", "negative", "cname"):
        for repeat in range(args.repeats):
            order = ("donna", "bind") if repeat % 2 == 0 else ("bind", "donna")
            for name in order:
                before = cpu_usage(containers[name])
                command = [
                    "run",
                    "--rm",
                    "--network",
                    NETWORK,
                    PREFIX + "cache-client",
                    "--queries",
                    str(args.queries),
                    "--repeats",
                    "1",
                    "--load-seconds",
                    str(args.load_seconds),
                    "--server",
                    name,
                    "--workload",
                    kind,
                    "--repeat-offset",
                    str(repeat),
                    "--query-format",
                    args.query_format,
                    "--load-client",
                    args.load_client,
                ]
                if args.source_port is not None:
                    command += ["--source-port", str(args.source_port)]
                output = docker(*command, capture=True)
                cpu_seconds = cpu_usage(containers[name]) - before
                rows = [
                    json.loads(line)
                    for line in output.splitlines()
                    if line.startswith("{")
                ]
                if len(rows) != 1:
                    raise RuntimeError(
                        "expected one native load measurement\n" + output
                    )
                row = rows[0]
                # Cgroup usage includes correctness passes outside native
                # timing and the short counter-reading process.
                row["server_cpu_seconds_with_warmup"] = cpu_seconds
                row["server_cpu_percent_with_warmup"] = (
                    100 * cpu_seconds / row["client_wall_seconds"]
                )
                print(json.dumps(row), flush=True)


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--cpu-only", action="store_true")
    parser.add_argument("--network-only", action="store_true")
    parser.add_argument("--queries", type=int, default=10000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--load-seconds", type=int, default=0)
    parser.add_argument(
        "--cpu-stats",
        action="store_true",
        help="record per-run cgroup-v2 server and native-client CPU use",
    )
    parser.add_argument("--source-port", type=int)
    parser.add_argument(
        "--load-client", choices=("dnsperf", "batched"), default="dnsperf"
    )
    parser.add_argument(
        "--query-format", choices=("classic", "edns", "edns-do"), default="classic"
    )
    parser.add_argument(
        "--donna-image",
        default=PREFIX + "donna",
        help="Donna laboratory image used for network measurements",
    )
    args = parser.parse_args()
    if args.cpu_only and args.network_only:
        parser.error("choose at most one of --cpu-only and --network-only")
    if args.cpu_stats and (args.cpu_only or args.load_seconds <= 0):
        parser.error("CPU statistics require native network load")
    if args.load_client == "batched" and (
        args.load_seconds <= 0 or args.source_port is not None
    ):
        parser.error(
            "batched load needs positive --load-seconds and no fixed source port"
        )
    if args.source_port is not None and not 1024 <= args.source_port <= 65535:
        parser.error("source port must be 1024..65535")
    images = []
    if not args.network_only:
        images.append(("cache", "Cache"))
    if not args.cpu_only:
        images += [("cache-peer", "CachePeer"), ("cache-client", "CacheClient")]
        docker("inspect", PREFIX + "root", capture=True)
        docker("network", "inspect", NETWORK, capture=True)
    if not args.skip_build:
        for image, filename in images:
            docker(
                "build",
                "-t",
                PREFIX + image,
                "-f",
                f"examples/interop/docker/{filename}.Dockerfile",
                ".",
            )
    if not args.network_only:
        docker("run", "--rm", PREFIX + "cache")
    if args.cpu_only:
        return
    peer = PREFIX + "cache-reference"
    donna = PREFIX + "cache-donna"
    docker("rm", "-f", peer, donna, check=False, capture=True)
    try:
        docker(
            "run",
            "-d",
            "--name",
            peer,
            "--network",
            NETWORK,
            "--ip",
            "172.29.53.50",
            PREFIX + "cache-peer",
            capture=True,
        )
        create_recursive(
            donna,
            args.donna_image,
            NETWORK,
            "172.29.53.51",
            "172.29.53.22:53",
            "172.29.53.0/24",
        )
        for _ in range(30):
            logs = docker("logs", peer, capture=True)
            if "running" in logs:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("reference BIND did not become ready\n" + logs)
        if args.cpu_stats:
            measure_with_cpu(args, donna, peer)
        else:
            command = [
                "run",
                "--rm",
                "--network",
                NETWORK,
                PREFIX + "cache-client",
                "--queries",
                str(args.queries),
                "--repeats",
                str(args.repeats),
                "--load-seconds",
                str(args.load_seconds),
                "--query-format",
                args.query_format,
                "--load-client",
                args.load_client,
            ]
            if args.source_port is not None:
                command += ["--source-port", str(args.source_port)]
            docker(*command)
    finally:
        docker("rm", "-f", peer, donna, check=False, capture=True)


if __name__ == "__main__":
    main()
