#!/usr/bin/env python3
"""Compare overflow responses with a deliberately invalid extended RCODE."""

import argparse
import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import tempfile
import time

from support.lock import exclusive_laboratory
from support.daemon import create_recursive
from support.docker import docker


PREFIX = "donna-dname-edns-"
NETWORK = PREFIX + "network"
ROLES = ("authority", "donna", "bind", "probe")


def cleanup():
    docker("rm", "-f", *(PREFIX + role for role in ROLES), check=False, capture=True)
    docker("network", "rm", NETWORK, check=False, capture=True)


def create(role, image, address, *command, environment=()):
    args = ["create", "--name", PREFIX + role, "--network", NETWORK, "--ip", address]
    for value in environment:
        args += ["-e", value]
    docker(*args, image, *command, capture=True)


@exclusive_laboratory
def execute(args):
    suite = SUITE
    sources = (
        Path(__file__),
        suite / "python/dname_edns_authority.py",
        suite / "python/dname_edns_probe.py",
    )
    images = {
        "donna": args.donna_image,
        "bind": "donna-interop-bind",
        "probe": "donna-interop-peers",
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
                "source_sha256": {
                    str(path.relative_to(suite)): hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                    for path in sources
                },
                "scope": "DNAME overflow; deliberately malformed 12-bit upstream RCODE",
            }
        ),
        flush=True,
    )
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError("DNAME EDNS laboratory network already exists")
    try:
        docker("network", "create", "--subnet", "172.29.56.0/24", NETWORK, capture=True)
        create(
            "authority",
            images["probe"],
            "172.29.56.20",
            "python",
            "/suite/dname_edns_authority.py",
        )
        docker(
            "cp", str(sources[1]), PREFIX + "authority:/suite/dname_edns_authority.py"
        )
        docker("start", PREFIX + "authority", capture=True)
        deadline = time.monotonic() + 15
        while "READY" not in docker("logs", PREFIX + "authority", capture=True):
            if time.monotonic() >= deadline:
                raise RuntimeError("authority did not start")
            time.sleep(0.1)
        create_recursive(
            PREFIX + "donna",
            images["donna"],
            NETWORK,
            "172.29.56.10",
            "172.29.56.20:53",
            "172.29.56.0/24",
            start=False,
        )
        create(
            "bind",
            images["bind"],
            "172.29.56.11",
            "named",
            "-g",
            "-n",
            "2",
            "-u",
            "root",
            "-c",
            "/suite/dname-edns.conf",
        )
        with tempfile.TemporaryDirectory(prefix=PREFIX) as directory:
            config = Path(directory) / "named.conf"
            hints = Path(directory) / "root.hints"
            config.write_text(
                'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
                "recursion yes; allow-recursion { any; }; dnssec-validation no; empty-zones-enable no; }; "
                'controls {}; zone "." { type hint; file "/suite/dname-edns.hints"; };\n'
            )
            hints.write_text(". 300 IN NS ns.root.\nns.root. 300 IN A 172.29.56.20\n")
            docker("cp", str(config), PREFIX + "bind:/suite/dname-edns.conf")
            docker("cp", str(hints), PREFIX + "bind:/suite/dname-edns.hints")
        docker("start", PREFIX + "donna", PREFIX + "bind", capture=True)
        create("probe", images["probe"], "172.29.56.30", "sleep", "infinity")
        docker("cp", str(sources[2]), PREFIX + "probe:/suite/dname_edns_probe.py")
        docker("start", PREFIX + "probe", capture=True)
        deadline = time.monotonic() + 15
        while True:
            ready = docker(
                "exec",
                PREFIX + "probe",
                "python",
                "-c",
                "import socket; socket.create_connection(('172.29.56.10',5301),.3).close(); "
                "socket.create_connection(('172.29.56.11',53),.3).close(); print('READY')",
                capture=True,
                check=False,
            )
            if ready.strip() == "READY":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("resolvers did not start: " + ready)
            time.sleep(0.1)
        output = docker(
            "exec",
            PREFIX + "probe",
            "python",
            "/suite/dname_edns_probe.py",
            capture=True,
            check=False,
        )
        print(output, flush=True)
        authority = docker("logs", PREFIX + "authority", capture=True)
        print(authority, flush=True)
        rows = [
            json.loads(line) for line in output.splitlines() if line.startswith("{")
        ]
        observations = [
            json.loads(line) for line in authority.splitlines() if line.startswith("{")
        ]
        for case in ("valid", "bad"):
            for protocol in ("udp", "tcp"):
                name = f"{case}-{protocol}.{case}-{protocol}.example.test."
                matched = [row for row in observations if row["authority"] == name]
                expected = 6 if case == "valid" else 22
                if len(matched) < 2 or any(
                    row["response_rcode"] != expected or row["query_edns"] != 0
                    for row in matched
                ):
                    raise RuntimeError(f"missing EDNS upstream observations for {name}")
        cases = [
            (row.get("server"), row.get("transport"), row.get("case"))
            for row in rows
            if "case" in row
        ]
        if len(cases) != 12 or len(set(cases)) != 12:
            raise RuntimeError("incomplete or duplicated client matrix")
        if not rows or rows[-1].get("result") != "PASS":
            raise RuntimeError("DNAME EDNS gate failed")
    finally:
        cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    execute(parser.parse_args())
