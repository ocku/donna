#!/usr/bin/env python3
"""Compare exact and wildcard answer signature sources across authorities."""

import argparse
import json
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
        control_image=args.control_image,
        current_image=args.current_image,
        load_client="batched",
        repeats=1,
        seconds=1,
        modes=["nsec3"],
        cases=None,
        keep=True,
        verify_only=True,
        upstream_semantics=False,
        cleanup=False,
    )
    try:
        similar.execute(setup)
        signer = similar.PREFIX + "signer"
        if args.fixture:
            with tempfile.TemporaryDirectory(
                prefix="donna-signature-source-"
            ) as directory:
                similar.put(
                    Path(directory), "signature-source.db", args.fixture.read_text()
                )
        else:
            base = docker("exec", signer, "cat", "/work/zone.db", capture=True)
            extra = (
                "\n*.example.test. 300 IN A 192.0.2.99\n"
                '*.example.test. 300 IN TXT "other wildcard"\n'
                "*.branch.example.test. 300 IN CNAME wrong.outside.test.\n"
                "*.nested.branch.example.test. 300 IN CNAME right.outside.test.\n"
            )
            with tempfile.TemporaryDirectory(
                prefix="donna-signature-source-"
            ) as directory:
                similar.put(
                    Path(directory), "signature-source-unsigned.db", base + extra
                )
            for flags in ([], ["-f", "KSK"]):
                docker(
                    "exec",
                    "-w",
                    "/work",
                    signer,
                    "dnssec-keygen",
                    "-q",
                    "-a",
                    "ED25519",
                    "-n",
                    "ZONE",
                    *flags,
                    "example.test.",
                    capture=True,
                )
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
                "-3",
                "A1B2",
                "-A",
                "-o",
                "example.test.",
                "-f",
                "signature-source.db",
                "signature-source-unsigned.db",
                capture=True,
            )
        signed = docker(
            "exec", signer, "cat", "/work/signature-source.db", capture=True
        )
        verification = docker(
            "exec",
            "-w",
            "/work",
            signer,
            "dnssec-verify",
            "-o",
            "example.test.",
            "signature-source.db",
            capture=True,
        )
        print(
            json.dumps(
                {
                    "fixture_sha256": docker(
                        "exec",
                        signer,
                        "sha256sum",
                        "/work/signature-source.db",
                        capture=True,
                    ),
                    "public_signed_zone": signed,
                    "zone_verification": verification,
                    "harness_sha256": harness_hashes(
                        suite,
                        (
                            Path(__file__).resolve(),
                            suite / "python/signature_source_probe.py",
                            suite / "python/signature_source_probe_test.py",
                            suite / "python/signed_probe.py",
                            suite / "python/probe.py",
                            suite / "labs/authority/similar.py",
                            suite / "labs/authority/similar_fixture.py",
                            suite / "labs/authority/similar_cli.py",
                        ),
                    ),
                }
            ),
            flush=True,
        )
        similar.start("signature-source")
        for name in (
            "signature_source_probe.py",
            "signature_source_probe_test.py",
            "signed_probe.py",
            "probe.py",
        ):
            docker(
                "cp",
                str(suite / "python" / name),
                similar.PREFIX + "probe:/suite/" + name,
            )
        docker(
            "cp",
            str(suite / "python/test_fixtures") + "/.",
            similar.PREFIX + "probe:/suite/test_fixtures",
        )
        print(
            docker(
                "exec",
                similar.PREFIX + "probe",
                "python",
                "/suite/signature_source_probe_test.py",
                capture=True,
            ),
            flush=True,
        )
        output = docker(
            "exec",
            similar.PREFIX + "probe",
            "python",
            "/suite/signature_source_probe.py",
            capture=True,
        )
        print(output, flush=True)
        rows = [
            json.loads(line) for line in output.splitlines() if line.startswith("{")
        ]
        counts = {
            role: {
                "rows": sum(row["server"] == role for row in rows),
                "failed": sum(
                    row["server"] == role and not row["passed"] for row in rows
                ),
            }
            for role in ("donna-verified", "donna-current", "bind", "knot", "nsd")
        }
        print(json.dumps({"summary": counts}), flush=True)
        if any(v["rows"] != 17 for v in counts.values()):
            raise RuntimeError("incomplete signature-source matrix")
        if any(
            v["failed"]
            for role, v in counts.items()
            if role != "donna-verified" or not args.allow_control_fail
        ):
            raise RuntimeError("signature-source gates failed")
    finally:
        similar.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-image", required=True)
    parser.add_argument("--current-image", required=True)
    parser.add_argument(
        "--fixture", type=Path, help="reuse an independently signed public fixture"
    )
    parser.add_argument(
        "--allow-control-fail",
        action="store_true",
        help="retain failures from the historical control",
    )
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
