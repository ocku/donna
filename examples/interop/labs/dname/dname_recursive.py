#!/usr/bin/env python3
"""Compare DNSSEC-validating recursion over a signed DNAME hierarchy."""

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


def run_peer(server, protocol, mode, image, bad_chain=False):
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
        "/suite/dname_recursive_probe.py",
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
    if bad_chain:
        command.append("--bad-chain")
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, result.stderr, flush=True)
        raise RuntimeError("recursive DNAME probe failed")
    objects = [
        json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")
    ]
    rows = [row for row in objects if "case" in row]
    if len(rows) != (2 if bad_chain else 6):
        raise RuntimeError("incomplete recursive DNAME matrix")
    failures = []
    for row in rows:
        row["mode"] = mode
        print(json.dumps(row), flush=True)
        if not row["passed"]:
            failures.append(row)
    if not bad_chain:
        faults = [row for row in objects if "fault_tests_passed" in row]
        if len(faults) != 1 or faults[0]["fault_tests_passed"] != 4:
            failures.append(
                {
                    "server": server,
                    "protocol": protocol,
                    "mode": mode,
                    "error": "missing fault-injection checks",
                }
            )
        for row in faults:
            row["mode"] = mode
            print(json.dumps(row), flush=True)
    return failures


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
        suite / "python/dname_recursive_probe.py",
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
                "scope": "bounded signed recursive DNAME comparison; no timing claim",
            }
        ),
        flush=True,
    )
    failures = []
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        for mode in ("nsec", "nsec3") if args.mode == "both" else (args.mode,):
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
            docker(
                "cp",
                str(suite / "python/dname_recursive_probe.py"),
                PREFIX + "probe:/suite/dname_recursive_probe.py",
            )
            with tempfile.TemporaryDirectory(
                prefix="donna-dname-recursive-"
            ) as temporary:
                chain.prepare(Path(temporary), 1, mode)
                leaf = docker(
                    "exec", chain.SIGNER, "cat", "/work/leaf/zone.db", capture=True
                )
                target = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 50, "invalid."))
                leaf += (
                    "\nold 120 IN DNAME dest.example.test.\nhop 120 IN DNAME old.example.test.\n"
                    "www.dest 300 IN A 192.0.2.80\nalias 300 IN CNAME www.hop.example.test.\n"
                    f"long 120 IN DNAME {target}\n"
                )
                chain.put(Path(temporary), "leaf/zone.db", leaf)
                chain.sign("leaf", mode)
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/leaf/signed.db",
                    "/work/leaf/active.db",
                )
                public = {}
                for name, origin in chain.ORIGINS.items():
                    verification = docker(
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
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{name}/active.db",
                        capture=True,
                    )
                    public[name] = {
                        "zone": text,
                        "captured_text_sha256": hashlib.sha256(
                            text.encode()
                        ).hexdigest(),
                        "verification": verification,
                    }
                print(
                    json.dumps({"mode": mode, "public_signed_zones": public}),
                    flush=True,
                )
                chain.start_authorities()
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        failures.extend(
                            run_peer(server, protocol, mode, args.donna_image)
                        )
                chain.stop_resolvers()
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/tld/bad-ds.db",
                    "/work/tld/active.db",
                )
                docker("restart", PREFIX + "chain-tld", capture=True)
                bad_zone = docker(
                    "exec", chain.SIGNER, "cat", "/work/tld/active.db", capture=True
                )
                bad_verification = docker(
                    "exec",
                    "-w",
                    "/work/tld",
                    chain.SIGNER,
                    "dnssec-verify",
                    "-o",
                    "test.",
                    "active.db",
                    capture=True,
                )
                print(
                    json.dumps(
                        {
                            "mode": mode,
                            "bad_ds_tld": bad_zone,
                            "captured_text_sha256": hashlib.sha256(
                                bad_zone.encode()
                            ).hexdigest(),
                            "zone_verification": bad_verification,
                        }
                    ),
                    flush=True,
                )
                for server in chain.RESOLVERS:
                    for protocol in ("udp", "tcp"):
                        failures.extend(
                            run_peer(
                                server, protocol, mode, args.donna_image, bad_chain=True
                            )
                        )
                docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
                chain.cleanup()
    finally:
        docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
        chain.cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)
    print(
        json.dumps({"result": "FAIL" if failures else "PASS", "failures": failures}),
        flush=True,
    )
    if failures:
        raise SystemExit("recursive DNAME gate failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    parser.add_argument("--mode", choices=("nsec", "nsec3", "both"), default="both")
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
