#!/usr/bin/env python3
"""Compare cross-name failed-zone ancestor refresh using existing Docker images."""

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

PREFIX = "donna-ancestor-failures-"
NETWORK = PREFIX + "network"
ROLES = ("root", "tld", "leaf", "donna", "bind", "probe")


@exclusive_laboratory
def execute(image, ns_failure_cache=False):
    suite = SUITE
    try:
        print(
            json.dumps(
                {
                    "images": {
                        role: docker(
                            "image", "inspect", ref, "--format", "{{.Id}}", capture=True
                        )
                        for role, ref in (
                            ("donna", image),
                            ("bind", "donna-interop-bind"),
                            ("authority", "donna-interop-peers"),
                        )
                    },
                    "harness_sha256": harness_hashes(
                        suite,
                        (
                            Path(__file__),
                            suite / "python/ancestor_authority.py",
                            suite / "python/ancestor_probe.py",
                        ),
                    ),
                }
            ),
            flush=True,
        )
        docker("network", "create", "--subnet", "172.29.56.0/24", NETWORK, capture=True)
        for role, address in (("root", 20), ("tld", 21), ("leaf", 22)):
            docker(
                "create",
                "--name",
                PREFIX + role,
                "--network",
                NETWORK,
                "--ip",
                f"172.29.56.{address}",
                "-e",
                "AUTHORITY_ROLE=" + role,
                "donna-interop-peers",
                "python",
                "/suite/ancestor_authority.py",
                capture=True,
            )
            docker(
                "cp",
                str(suite / "python/ancestor_authority.py"),
                PREFIX + role + ":/suite/ancestor_authority.py",
            )
            docker("start", PREFIX + role, capture=True)
        deadline = time.monotonic() + 15
        while not all(
            "READY" in docker("logs", PREFIX + role, capture=True)
            for role in ("root", "tld", "leaf")
        ):
            if time.monotonic() >= deadline:
                raise RuntimeError("hierarchy authority not ready")
            time.sleep(0.1)
        create_recursive(
            PREFIX + "donna",
            image,
            NETWORK,
            "172.29.56.10",
            "172.29.56.20:53",
            "172.29.56.0/24",
        )
        docker(
            "create",
            "--name",
            PREFIX + "bind",
            "--network",
            NETWORK,
            "--ip",
            "172.29.56.11",
            "donna-interop-bind",
            "named",
            "-g",
            "-n",
            "2",
            "-u",
            "root",
            "-c",
            "/suite/ancestor.conf",
            capture=True,
        )
        with tempfile.TemporaryDirectory(prefix=PREFIX) as temporary:
            config = Path(temporary) / "ancestor.conf"
            config.write_text(
                'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; recursion yes; '
                "allow-recursion { any; }; dnssec-validation no; empty-zones-enable no; "
                "stale-answer-enable no; }; controls {}; "
                'zone "." { type hint; file "/suite/ancestor.hints"; };\n'
            )
            hints = Path(temporary) / "ancestor.hints"
            hints.write_text(". 300 IN NS ns.root.\nns.root. 300 IN A 172.29.56.20\n")
            for p in (config, hints):
                docker("cp", str(p), PREFIX + "bind:/suite/" + p.name)
        docker("start", PREFIX + "bind", capture=True)
        docker(
            "run",
            "-d",
            "--name",
            PREFIX + "probe",
            "--network",
            NETWORK,
            "donna-interop-peers",
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "cp",
            str(suite / "python/ancestor_probe.py"),
            PREFIX + "probe:/suite/ancestor_probe.py",
        )
        deadline = time.monotonic() + 15
        while (
            docker(
                "exec",
                PREFIX + "probe",
                "python",
                "-c",
                "import socket; socket.create_connection(('172.29.56.10',5301),.3).close(); "
                "socket.create_connection(('172.29.56.11',53),.3).close(); print('READY')",
                capture=True,
                check=False,
            ).strip()
            != "READY"
        ):
            if time.monotonic() >= deadline:
                raise RuntimeError("recursive peers not ready")
            time.sleep(0.1)
        print(
            docker(
                "exec",
                PREFIX + "probe",
                "python",
                "/suite/ancestor_probe.py",
                *(("--ns-failure-cache",) if ns_failure_cache else ()),
                capture=True,
            ),
            flush=True,
        )
    except Exception:
        for role in ROLES:
            print(
                docker(
                    "logs", "--tail", "30", PREFIX + role, capture=True, check=False
                ),
                flush=True,
            )
        raise
    finally:
        docker(
            "rm", "-f", *(PREFIX + role for role in ROLES), capture=True, check=False
        )
        docker("network", "rm", NETWORK, capture=True, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=CLI_IMAGE)
    parser.add_argument(
        "--ns-failure-cache",
        action="store_true",
        help="require exact NS-address failure reuse (one leaf request per fresh name)",
    )
    args = parser.parse_args()
    execute(args.donna_image, args.ns_failure_cache)
