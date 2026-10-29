#!/usr/bin/env python3
"""Compare authoritative DNAME behavior against isolated Docker peers."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from support.docker import docker
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes

from labs.authority import similar


@exclusive_laboratory
def execute(args):
    suite = SUITE
    setup = argparse.Namespace(
        control_image=args.donna_image,
        current_image=args.donna_image,
        load_client="batched",
        repeats=1,
        seconds=1,
        modes=["unsigned"],
        cases=None,
        keep=True,
        verify_only=True,
        upstream_semantics=False,
        cleanup=False,
    )
    try:
        similar.execute(setup)
        target = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 50, "invalid."))
        fixture = (
            suite / "fixtures/dname/authority.db"
        ).read_text() + f"overflow 120 IN DNAME {target}\n"
        with tempfile.TemporaryDirectory(prefix="donna-dname-authority-") as directory:
            similar.put(Path(directory), "dname.db", fixture)
        signer = similar.PREFIX + "signer"
        docker(
            "exec",
            "-w",
            "/work",
            signer,
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
            "example.test.",
            "-f",
            "dname-signed.db",
            "dname.db",
            capture=True,
        )
        zone_verification = docker(
            "exec",
            "-w",
            "/work",
            signer,
            "dnssec-verify",
            "-o",
            "example.test.",
            "dname-signed.db",
            capture=True,
        )
        signed_fixture = docker(
            "exec", signer, "cat", "/work/dname-signed.db", capture=True
        )
        paths = (
            Path(__file__).resolve(),
            suite / "fixtures/dname/authority.db",
            suite / "python/dname_authority_probe.py",
            suite / "python/dname_authority_probe_test.py",
            suite / "python/upstream_authority.py",
            suite / "python/authority_expectations.py",
            suite / "labs/authority/similar.py",
            suite / "labs/authority/similar_fixture.py",
            suite / "labs/authority/similar_cli.py",
        )
        print(
            json.dumps(
                {
                    "fixture": fixture,
                    "fixture_sha256": hashlib.sha256(fixture.encode()).hexdigest(),
                    "signed_fixture": signed_fixture,
                    "zone_verification": zone_verification,
                    "signed_fixture_sha256": hashlib.sha256(
                        signed_fixture.encode()
                    ).hexdigest(),
                    "harness_sha256": harness_hashes(suite, paths),
                }
            ),
            flush=True,
        )
        docker(
            "cp",
            str(suite / "python/dname_authority_probe.py"),
            similar.PREFIX + "probe:/suite/dname_authority_probe.py",
        )
        docker(
            "cp",
            str(suite / "python/upstream_authority.py"),
            similar.PREFIX + "probe:/suite/upstream_authority.py",
        )
        docker(
            "cp",
            str(suite / "python/authority_expectations.py"),
            similar.PREFIX + "probe:/suite/authority_expectations.py",
        )
        failed = False
        for mode in ("dname", "dname-signed"):
            similar.start(mode)
            if mode == "dname-signed":
                output = docker(
                    "exec",
                    similar.PREFIX + "probe",
                    "python",
                    "/suite/dname_authority_probe.py",
                    "--server",
                    "current=172.29.54.11:5300",
                    "--signed",
                    "--signed-fault-tests",
                    capture=True,
                )
                if json.loads(output).get("signed_fault_tests") != 5:
                    raise RuntimeError("incomplete signed fault tests")
                print(output, flush=True)
            for role, (_, address) in similar.ROLES.items():
                port = 5300 if role in ("verified", "current") else 53
                command = [
                    "docker",
                    "exec",
                    similar.PREFIX + "probe",
                    "python",
                    "/suite/dname_authority_probe.py",
                    "--server",
                    f"{role}={address}:{port}",
                    "--repeats",
                    str(args.repeats),
                ]
                if mode == "dname-signed":
                    command.append("--signed")
                result = subprocess.run(command, text=True, capture_output=True)
                for line in result.stdout.splitlines():
                    row = json.loads(line)
                    row["mode"] = mode
                    print(json.dumps(row), flush=True)
                if result.returncode:
                    print(result.stderr, flush=True)
                    failed = True
                    continue
                rows = [
                    json.loads(line)
                    for line in result.stdout.splitlines()
                    if line.startswith("{")
                ]
                if len(rows) != 22 or any(not row["passed"] for row in rows):
                    failed = True
        if failed:
            raise RuntimeError("DNAME semantic gate failed")
    finally:
        similar.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", required=True)
    parser.add_argument("--repeats", type=int, default=40)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("positive repeat count required")
    execute(args)


if __name__ == "__main__":
    main()
