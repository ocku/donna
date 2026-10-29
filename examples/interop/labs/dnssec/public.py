#!/usr/bin/env python3
"""Optional public authoritative DNS + IANA trust-anchor validation smoke."""

from support.paths import ROOT
import argparse
import os
import re
import statistics
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--skip-build", action="store_true")
args = parser.parse_args()
root = ROOT
if not args.skip_build:
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            "examples/interop/docker/Public.Dockerfile",
            "-t",
            "donna-interop-public",
            ".",
        ],
        cwd=root,
        check=True,
    )
for index, (name, success) in enumerate(
    (
        ("example.com", True),
        ("example.org", True),
        ("www.iana.org", True),
        ("does-not-exist-donna-audit.example.com", True),
        ("dnssec-failed.org", False),
    )
):
    container = f"donna-interop-public-{os.getpid()}-{index}"
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container,
                "donna-interop-public",
                name,
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=90,
        )
    finally:
        # Killing the Docker CLI on timeout does not stop its container.
        subprocess.run(
            ["docker", "rm", "-f", container],
            cwd=root,
            capture_output=True,
            timeout=15,
            check=False,
        )
    assert (result.returncode == 0) == success, (name, result.stdout, result.stderr)
    if not success:
        assert result.returncode == 1 and re.search(
            r"(?m)^Error: DnssecBogus\(", result.stderr
        ), (
            "expected DNSSEC validation rejection, not an unrelated failure",
            name,
            result.returncode,
            result.stdout,
            result.stderr,
        )
    print(f"PASS public DNSSEC {'accept' if success else 'reject'} {name}", flush=True)
    scales = {"ns": 0.000001, "µs": 0.001, "ms": 1, "s": 1000}
    samples = [
        float(value) * scales[unit]
        for value, unit in re.findall(
            r"cached query \d+: ([\d.]+)(ns|µs|ms|s)", result.stdout
        )
    ]
    if samples:
        print(
            f"  cached lookup median: {statistics.median(samples):.3f} ms", flush=True
        )
