#!/usr/bin/env python3
"""Compare original-name visibility around NSEC3 metadata owners."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from support.docker import docker
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes

from labs.authority import similar


def probe(variant, repeats):
    output = docker(
        "exec",
        similar.PREFIX + "probe",
        "python",
        "/suite/nsec3_owner_probe.py",
        "--variant",
        variant,
        "--repeats",
        str(repeats),
        capture=True,
    )
    print(output, flush=True)
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def load_fixtures(path):
    if path is None:
        return None
    rows = json.loads(path.read_text())["rows"]
    fixtures = {}
    for row in rows:
        if "public_signed_zone" not in row or row.get("variant") not in (
            "metadata",
            "wildcard",
            "owner",
            "descendant",
        ):
            continue
        text, expected = row["public_signed_zone"], row["fixture_sha256"].split()[0]
        for suffix in ("", "\n", "\n\n"):
            candidate = text + suffix
            if hashlib.sha256(candidate.encode()).hexdigest() == expected:
                fixtures[row["variant"]] = candidate
                break
        else:
            raise ValueError("cannot reconstruct exact signed fixture bytes")
    if set(fixtures) != {"metadata", "wildcard", "owner", "descendant"}:
        raise ValueError("four public signed fixtures required")
    fixtures["nsec3"] = fixtures["metadata"]
    return fixtures


@exclusive_laboratory
def execute(args):
    suite = SUITE
    fixtures = load_fixtures(args.fixtures)
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
        pre_signed_fixtures=fixtures,
    )
    failed = []
    all_cases = []
    try:
        similar.execute(setup)
        for name in (
            "nsec3_owner_probe.py",
            "nsec3_owner_checks.py",
            "signed_probe.py",
            "probe.py",
        ):
            docker(
                "cp",
                str(suite / "python" / name),
                similar.PREFIX + "probe:/suite/" + name,
            )
        print(
            json.dumps(
                {
                    "suite": "nsec3-owner-visibility",
                    "harness_sha256": harness_hashes(
                        suite,
                        (
                            Path(__file__).resolve(),
                            suite / "labs/authority/similar.py",
                            suite / "labs/authority/similar_fixture.py",
                            suite / "labs/authority/similar_cli.py",
                            suite / "python/nsec3_owner_probe.py",
                            suite / "python/nsec3_owner_checks.py",
                            suite / "python/nsec3_owner_checks_test.py",
                            suite / "python/signed_probe.py",
                            suite / "python/probe.py",
                        ),
                    ),
                }
            ),
            flush=True,
        )
        print(
            json.dumps(
                {
                    "variant": "metadata",
                    "independent_zone_verification": docker(
                        "exec",
                        "-w",
                        "/work",
                        similar.PREFIX + "signer",
                        "dnssec-verify",
                        "-o",
                        "example.test.",
                        "active.db",
                        capture=True,
                    ),
                    "public_signed_zone": docker(
                        "exec",
                        similar.PREFIX + "signer",
                        "cat",
                        "/work/active.db",
                        capture=True,
                    ),
                    "fixture_sha256": docker(
                        "exec",
                        similar.PREFIX + "signer",
                        "sha256sum",
                        "/work/active.db",
                        capture=True,
                    ),
                }
            ),
            flush=True,
        )
        initial = probe("metadata", args.repeats)
        all_cases.extend(row for row in initial if "server" in row)
        owner = initial[0]["metadata_owner"]
        if initial[-1]["result"] != "PASS":
            failed.append("metadata")
        base = (
            docker(
                "exec", similar.PREFIX + "signer", "cat", "/work/zone.db", capture=True
            )
            + "\n"
        )
        with tempfile.TemporaryDirectory(prefix="donna-nsec3-owner-") as directory:
            directory = Path(directory)
            for variant, extra in (
                ("wildcard", "* IN A 192.0.2.89\n"),
                ("owner", f"{owner} IN A 192.0.2.88\n"),
                ("descendant", f'leaf.{owner} IN TXT "ordinary descendant"\n'),
            ):
                if fixtures is None:
                    similar.put(directory, variant + "-unsigned.db", base + extra)
                    docker(
                        "exec",
                        "-w",
                        "/work",
                        similar.PREFIX + "signer",
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
                        variant + ".db",
                        variant + "-unsigned.db",
                        capture=True,
                    )
                verify = docker(
                    "exec",
                    "-w",
                    "/work",
                    similar.PREFIX + "signer",
                    "dnssec-verify",
                    "-o",
                    "example.test.",
                    variant + ".db",
                    capture=True,
                )
                print(
                    json.dumps(
                        {
                            "variant": variant,
                            "independent_zone_verification": verify,
                            "public_signed_zone": docker(
                                "exec",
                                similar.PREFIX + "signer",
                                "cat",
                                "/work/" + variant + ".db",
                                capture=True,
                            ),
                            "fixture_sha256": docker(
                                "exec",
                                similar.PREFIX + "signer",
                                "sha256sum",
                                "/work/" + variant + ".db",
                                capture=True,
                            ),
                        }
                    ),
                    flush=True,
                )
                similar.start(variant)
                rows = probe(variant, args.repeats)
                all_cases.extend(row for row in rows if "server" in row)
                if rows[-1]["result"] != "PASS":
                    failed.append(variant)
        print(
            json.dumps(
                {
                    "suite": "nsec3-owner-visibility",
                    "result": "FAIL" if failed else "PASS",
                    "failed_variants": failed,
                    "implementation_summary": {
                        role: {
                            "rows": sum(row["server"] == role for row in all_cases),
                            "failed": sum(
                                row["server"] == role and not row["passed"]
                                for row in all_cases
                            ),
                        }
                        for role in similar.SERVICES
                    },
                }
            ),
            flush=True,
        )
    finally:
        similar.cleanup()
    if failed:
        raise SystemExit("NSEC3 owner visibility gates failed: " + ", ".join(failed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-image", default="donna-prelinked-current")
    parser.add_argument("--current-image", default="donna-prelinked-current")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument(
        "--fixtures",
        type=Path,
        help="reuse exact public signed zones from a retained owner-visibility artifact",
    )
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("positive repeat count required")
    execute(args)


if __name__ == "__main__":
    main()
