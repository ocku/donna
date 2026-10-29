#!/usr/bin/env python3
"""Compare validating recursion beneath an independently proved insecure cut."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import time
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain


def prepare(directory, mode):
    chain.prepare(directory, 1, "nsec" if mode == "nsec" else "nsec3")
    tld = docker("exec", chain.SIGNER, "cat", "/work/tld/zone.db", capture=True)
    lines = [line for line in tld.splitlines() if " IN DS " not in line]
    assert len(lines) < len(tld.splitlines()), "fixture did not remove the child DS"
    chain.put(directory, "tld/zone.db", "\n".join(lines) + "\n")
    if mode == "optout":
        docker(
            "exec",
            "-w",
            "/work/tld",
            chain.SIGNER,
            "dnssec-signzone",
            "-q",
            "-S",
            "-n",
            "1",
            "-s",
            "now-3600",
            "-e",
            "now+86400",
            "-N",
            "keep",
            "-o",
            "test.",
            "-f",
            "signed.db",
            "-3",
            "A1B2",
            "-A",
            "zone.db",
            capture=True,
        )
    else:
        chain.sign("tld", mode)
    docker("exec", chain.SIGNER, "cp", "/work/tld/signed.db", "/work/tld/active.db")
    leaf = docker("exec", chain.SIGNER, "cat", "/work/leaf/zone.db", capture=True)
    leaf += "\nalias IN CNAME www.example.test.\n"
    chain.put(directory, "leaf/active.db", leaf)


def run_probe(server, protocol, mode, image, bad_proof=False):
    chain.start_resolver(server, image)
    host, port = ("172.29.53.74", 5301) if server == "donna" else ("172.29.53.73", 53)
    deadline = time.monotonic() + 15
    while (
        docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            f"import socket; socket.create_connection(('{host}',{port}),.3).close(); print('READY')",
            check=False,
            capture=True,
        ).strip()
        != "READY"
    ):
        if time.monotonic() >= deadline:
            raise RuntimeError("resolver did not start: " + server)
        time.sleep(0.1)
    command = [
        "docker",
        "exec",
        PREFIX + "probe",
        "python",
        "/suite/insecure_probe.py",
        "--server",
        server,
        "--host",
        host,
        "--port",
        str(port),
        "--protocol",
        protocol,
        "--mode",
        mode,
    ]
    if bad_proof:
        command.append("--bad-proof")
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, result.stderr, flush=True)
        raise RuntimeError("insecure-delegation gate failed")
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len([row for row in rows if "case" in row]) == (4 if bad_proof else 16), (
        "incomplete cache/CD matrix"
    )
    for row in rows:
        row["mode"] = mode
        print(json.dumps(row), flush=True)


@exclusive_laboratory
def execute(args):
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError(
            "ordinary laboratory network exists; finish its owning job first"
        )
    suite = SUITE
    paths = (
        Path(__file__).resolve(),
        suite / "labs/dnssec/chain.py",
        suite / "labs/dnssec/chain_fixture.py",
        suite / "python/insecure_probe.py",
        suite / "python/dname_recursive_probe.py",
        suite / "python/insecure_tamper.py",
    )
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
                    "probe": docker(
                        "image",
                        "inspect",
                        PREFIX + "peers",
                        "--format",
                        "{{.Id}}",
                        capture=True,
                    ),
                },
                "harness_sha256": harness_hashes(suite, paths),
                "scope": "signed parent DS denial and unsigned child over recursive UDP/TCP; no timing claim",
            }
        ),
        flush=True,
    )
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        modes = ("nsec", "nsec3", "optout") if args.mode == "all" else (args.mode,)
        for mode in modes:
            docker("volume", "create", chain.VOLUME, capture=True)
            docker(
                "run",
                "-d",
                "--name",
                PREFIX + "probe",
                "--network",
                NETWORK,
                "-v",
                chain.VOLUME + ":/work:ro",
                PREFIX + "peers",
                "sleep",
                "infinity",
                capture=True,
            )
            for name in (
                "insecure_probe.py",
                "dname_recursive_probe.py",
                "insecure_tamper.py",
            ):
                docker(
                    "cp", str(suite / "python" / name), PREFIX + "probe:/suite/" + name
                )
            with tempfile.TemporaryDirectory(prefix="donna-insecure-") as tmp:
                prepare(Path(tmp), mode)
                public = {}
                for name, origin in chain.ORIGINS.items():
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{name}/active.db",
                        capture=True,
                    )
                    verification = (
                        None
                        if name == "leaf"
                        else docker(
                            "exec",
                            "-w",
                            "/work/" + name,
                            chain.SIGNER,
                            "dnssec-verify",
                            "-o",
                            origin,
                            "active.db",
                            capture=True,
                        )
                    )
                    public[name] = {
                        "zone": text,
                        "sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "verification": verification,
                    }
                print(json.dumps({"mode": mode, "public_zones": public}), flush=True)
                chain.start_authorities()
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        run_probe(server, protocol, mode, args.donna_image)
                chain.stop_resolvers()
                count = docker(
                    "exec",
                    PREFIX + "probe",
                    "python",
                    "/suite/insecure_tamper.py",
                    capture=True,
                )
                bad_file = Path(tmp) / "tld-bad-denial.db"
                docker("cp", PREFIX + "probe:/tmp/tld-bad-denial.db", str(bad_file))
                docker("cp", str(bad_file), chain.SIGNER + ":/work/tld/active.db")
                docker("restart", PREFIX + "chain-tld", capture=True)
                print(
                    json.dumps(
                        {
                            "mode": mode,
                            "tampered_signatures": int(count),
                            "bad_parent_zone": bad_file.read_text(),
                            "sha256": hashlib.sha256(bad_file.read_bytes()).hexdigest(),
                        }
                    ),
                    flush=True,
                )
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        run_probe(
                            server, protocol, mode, args.donna_image, bad_proof=True
                        )
            docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
            chain.cleanup()
    finally:
        docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
        chain.cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)
    print(json.dumps({"result": "PASS"}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    parser.add_argument(
        "--mode", choices=("nsec", "nsec3", "optout", "all"), default="all"
    )
    execute(parser.parse_args())
