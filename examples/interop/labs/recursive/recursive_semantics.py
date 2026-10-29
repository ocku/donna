#!/usr/bin/env python3
"""Compare recursive cache semantics with an independent observable authority.

Uses existing Docker images only; never builds or installs dependencies.
The shared lock avoids perturbing throughput jobs despite separate resources.
"""

import argparse
import json
import tempfile
import time
from pathlib import Path

from support.daemon import CLI_IMAGE, create_recursive
from support.docker import docker
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes

PREFIX = "donna-recursive-semantics-"
NETWORK = PREFIX + "network"
SERVICES = ("authority", "donna", "bind", "probe")


def cleanup():
    docker("rm", "-f", *(PREFIX + role for role in SERVICES), check=False, capture=True)
    docker("network", "rm", NETWORK, check=False, capture=True)


def create(role, image, address, *command, environment=()):
    args = ["create", "--name", PREFIX + role, "--network", NETWORK, "--ip", address]
    for value in environment:
        args += ["-e", value]
    docker(*args, image, *command, capture=True)


@exclusive_laboratory
def execute(args):
    cleanup()
    suite = SUITE
    images = {
        "donna": args.donna_image,
        "bind": "donna-interop-bind",
        "authority": "donna-interop-peers",
    }
    print(
        json.dumps(
            {
                "images": {
                    key: json.loads(docker("image", "inspect", image, capture=True))[0][
                        "Id"
                    ]
                    for key, image in images.items()
                },
                "harness_sha256": harness_hashes(
                    suite,
                    (
                        Path(__file__).resolve(),
                        suite / "python/cache_authority.py",
                        suite / "python/rrset_ttl_probe.py",
                        suite / "python/recursive_cache_probe.py",
                        suite / "python/recursive_cache_checks.py",
                        suite / "python/recursive_cache_checks_test.py",
                        suite / "python/oversized_soa_probe.py",
                        suite / "python/short_cname_probe.py",
                        suite / "python/short_cname_checks.py",
                        suite / "python/short_cname_checks_test.py",
                        suite / "python/resolution_failure_probe.py",
                        suite / "python/persistent_failure_probe.py",
                        suite / "python/retry_transport_probe.py",
                        suite / "python/resolution_failure_checks.py",
                        suite / "python/resolution_failure_checks_test.py",
                    ),
                ),
                "scope": (
                    "RFC2181 inbound RRset TTLs"
                    if args.rrset_ttl
                    else "expired CNAME with live terminal NXDOMAIN"
                    if args.short_cname
                    else "malformed negative SOA TTL handling"
                    if args.oversized_soa
                    else "unsigned cache identity, CNAME terminal scope, TTL countdown and expiry"
                )
                + "; no throughput or signed-proof claim",
            }
        ),
        flush=True,
    )
    if args.rrset_ttl:
        print(
            json.dumps(
                {
                    "bind_version": docker(
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        images["bind"],
                        "named",
                        "-V",
                        capture=True,
                    ),
                    "donna_recursive_sha256": docker(
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        images["donna"],
                        "sha256sum",
                        "/usr/local/bin/donna",
                        capture=True,
                    ),
                }
            ),
            flush=True,
        )
    try:
        docker("network", "create", "--subnet", "172.29.55.0/24", NETWORK, capture=True)
        create(
            "authority",
            images["authority"],
            "172.29.55.20",
            "python",
            "/suite/cache_authority.py",
        )
        docker(
            "cp",
            str(suite / "python/cache_authority.py"),
            PREFIX + "authority:/suite/cache_authority.py",
        )
        docker("start", PREFIX + "authority", capture=True)
        deadline = time.monotonic() + 15
        while "READY" not in docker("logs", PREFIX + "authority", capture=True):
            if time.monotonic() > deadline:
                raise RuntimeError("independent authority not ready")
            time.sleep(0.1)
        create_recursive(
            PREFIX + "donna",
            images["donna"],
            NETWORK,
            "172.29.55.10",
            "172.29.55.20:53",
            "172.29.55.0/24",
            start=False,
        )
        create(
            "bind",
            images["bind"],
            "172.29.55.11",
            "named",
            "-g",
            "-n",
            "2",
            "-u",
            "root",
            "-c",
            "/suite/recursive.conf",
        )
        with tempfile.TemporaryDirectory(prefix=PREFIX) as directory:
            config = Path(directory) / "recursive.conf"
            config.write_text(
                'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
                "recursion yes; allow-recursion { any; }; dnssec-validation no; empty-zones-enable no; "
                "min-cache-ttl 0; min-ncache-ttl 0; stale-answer-enable no; }; controls {}; "
                'zone "." { type hint; file "/suite/recursive.hints"; };\n'
            )
            hints = Path(directory) / "recursive.hints"
            hints.write_text(". 300 IN NS ns.root.\nns.root. 300 IN A 172.29.55.20\n")
            if args.rrset_ttl:
                print(
                    json.dumps(
                        {
                            "bind_configuration": config.read_text(),
                            "bind_root_hints": hints.read_text(),
                            "max_cache_ttl": "default: 604800 seconds (BIND 9.18.49 ARM)",
                        }
                    ),
                    flush=True,
                )
            docker("cp", str(config), PREFIX + "bind:/suite/recursive.conf")
            docker("cp", str(hints), PREFIX + "bind:/suite/recursive.hints")
        docker("start", PREFIX + "donna", PREFIX + "bind", capture=True)
        create("probe", images["authority"], "172.29.55.30", "sleep", "infinity")
        docker(
            "cp",
            str(suite / "python/recursive_cache_probe.py"),
            PREFIX + "probe:/suite/recursive_cache_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/recursive_cache_checks.py"),
            PREFIX + "probe:/suite/recursive_cache_checks.py",
        )
        docker(
            "cp",
            str(suite / "python/oversized_soa_probe.py"),
            PREFIX + "probe:/suite/oversized_soa_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/short_cname_probe.py"),
            PREFIX + "probe:/suite/short_cname_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/short_cname_checks.py"),
            PREFIX + "probe:/suite/short_cname_checks.py",
        )
        docker(
            "cp",
            str(suite / "python/resolution_failure_probe.py"),
            PREFIX + "probe:/suite/resolution_failure_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/resolution_failure_checks.py"),
            PREFIX + "probe:/suite/resolution_failure_checks.py",
        )
        docker(
            "cp",
            str(suite / "python/persistent_failure_probe.py"),
            PREFIX + "probe:/suite/persistent_failure_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/retry_transport_probe.py"),
            PREFIX + "probe:/suite/retry_transport_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/rrset_ttl_probe.py"),
            PREFIX + "probe:/suite/rrset_ttl_probe.py",
        )
        docker("start", PREFIX + "probe", capture=True)
        deadline = time.monotonic() + 15
        while True:
            output = docker(
                "exec",
                PREFIX + "probe",
                "python",
                "-c",
                "import socket; socket.create_connection(('172.29.55.10',5301),.3).close(); "
                "socket.create_connection(('172.29.55.11',53),.3).close(); print('READY')",
                capture=True,
                check=False,
            )
            if output.strip() == "READY":
                break
            if time.monotonic() > deadline:
                raise RuntimeError("recursive peers not ready\n" + output)
            time.sleep(0.1)
        script = (
            "rrset_ttl_probe.py"
            if args.rrset_ttl
            else "short_cname_probe.py"
            if args.short_cname
            else "oversized_soa_probe.py"
            if args.oversized_soa
            else "retry_transport_probe.py"
            if args.retry_transports
            else "persistent_failure_probe.py"
            if args.persistent_failure
            else "resolution_failure_probe.py"
            if args.failure_cache
            else "recursive_cache_probe.py"
        )
        print(
            docker(
                "exec", PREFIX + "probe", "python", "/suite/" + script, capture=True
            ),
            flush=True,
        )
    except Exception:
        for role in SERVICES:
            print(
                docker(
                    "logs", "--tail", "30", PREFIX + role, check=False, capture=True
                ),
                flush=True,
            )
        raise
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=CLI_IMAGE)
    parser.add_argument(
        "--failure-cache",
        action="store_true",
        help="compare RFC 9520 resolution-failure caching instead of ordinary cache semantics",
    )
    parser.add_argument(
        "--persistent-failure",
        action="store_true",
        help="observe persistent failure retry intervals and recovery",
    )
    parser.add_argument(
        "--retry-transports",
        action="store_true",
        help="count UDP truncation and closed-TCP retry transmissions",
    )
    parser.add_argument(
        "--oversized-soa",
        action="store_true",
        help="compare handling of a malformed negative SOA TTL exceeding MINIMUM",
    )
    parser.add_argument(
        "--rrset-ttl",
        action="store_true",
        help="compare raw inbound TTL high bits, mixed TTLs and duplicate suppression",
    )
    parser.add_argument(
        "--short-cname",
        action="store_true",
        help="compare changed CNAME after expiry while its old terminal NXDOMAIN is live",
    )
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
