#!/usr/bin/env python3
"""Compare cached DNSSEC failures through independent signed root/TLD/leaf zones."""

import argparse
import hashlib
import json
import re
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from support.daemon import CLI_IMAGE
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain


def counts(address):
    def read(zone):
        log = docker("logs", PREFIX + "chain-" + zone, capture=True)
        pattern = re.escape(address) + r"#.*query: (\S+) IN (\S+)"
        return zone, dict(Counter("/".join(row) for row in re.findall(pattern, log)))

    with ThreadPoolExecutor(max_workers=3) as pool:
        return dict(pool.map(read, chain.AUTHORITIES))


def transaction(server, cd=False):
    address, port = ("172.29.53.73", 53) if server == "bind" else ("172.29.53.74", 5301)
    return json.loads(
        docker(
            "exec",
            PREFIX + "probe",
            "python",
            "/suite/signed_failure_probe.py",
            "--host",
            address,
            "--port",
            str(port),
            *(("--cd",) if cd else ()),
            capture=True,
        )
    )


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
                },
                "harness_sha256": harness_hashes(
                    suite,
                    (
                        Path(__file__).resolve(),
                        suite / "labs/dnssec/chain.py",
                        suite / "labs/dnssec/chain_fixture.py",
                        suite / "python/signed_failure_probe.py",
                    ),
                ),
                "scope": "signed bad-DS failure caching plus CD bypass; independent root-only anchors and authority counters; no timing claim",
            }
        ),
        flush=True,
    )
    failures = []
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        docker(
            "run",
            "-d",
            "--name",
            PREFIX + "probe",
            "--network",
            NETWORK,
            PREFIX + "peers",
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "cp",
            str(suite / "python/signed_failure_probe.py"),
            PREFIX + "probe:/suite/signed_failure_probe.py",
        )
        for mode in ("nsec", "nsec3") if args.mode == "both" else (args.mode,):
            with tempfile.TemporaryDirectory(
                prefix="donna-signed-failure-"
            ) as temporary:
                chain.prepare(Path(temporary), 1, mode)
                docker(
                    "exec",
                    chain.SIGNER,
                    "cp",
                    "/work/tld/bad-ds.db",
                    "/work/tld/active.db",
                )
                for zone, origin in chain.ORIGINS.items():
                    print(
                        json.dumps(
                            {
                                "mode": mode,
                                "independent_zone_verification": zone,
                                "output": docker(
                                    "exec",
                                    "-w",
                                    "/work/" + zone,
                                    chain.SIGNER,
                                    "dnssec-verify",
                                    "-o",
                                    origin,
                                    "active.db",
                                    capture=True,
                                ),
                            }
                        ),
                        flush=True,
                    )
                public_zones = {}
                for zone in chain.ORIGINS:
                    text = docker(
                        "exec",
                        chain.SIGNER,
                        "cat",
                        f"/work/{zone}/active.db",
                        capture=True,
                    )
                    public_zones[zone] = {
                        "text": text,
                        "sha256": hashlib.sha256(text.encode()).hexdigest(),
                    }
                print(
                    json.dumps({"mode": mode, "public_signed_zones": public_zones}),
                    flush=True,
                )
                chain.start_authorities()
                for server in ("donna", "bind"):
                    chain.start_resolver(server, args.donna_image)
                    address = "172.29.53.73" if server == "bind" else "172.29.53.74"
                    cold = transaction(server)
                    started = time.monotonic()
                    before = counts(address)
                    for zone, origin in chain.ORIGINS.items():
                        owner = origin.rstrip(".") or "."
                        assert any(
                            key.split("/")[0].rstrip(".") == owner.rstrip(".")
                            and key.endswith("/DNSKEY")
                            for key in before[zone]
                        ), (server, zone, "missing DNSKEY acquisition")
                    repeated = transaction(server)
                    after = counts(address)
                    elapsed = time.monotonic() - started
                    # No throughput measurement: elapsed only establishes the
                    # suppression observation was inside default one-second TTL.
                    if elapsed >= 1:
                        raise RuntimeError(
                            "observation exceeded one-second minimum failure window; no cache verdict"
                        )
                    passed = before == after
                    row = {
                        "server": server,
                        "mode": mode,
                        "check": "signed-bad-ds-repeat-suppresses-all-authority-queries",
                        "cold": cold,
                        "repeated": repeated,
                        "before": before,
                        "after": after,
                        "observation_seconds": elapsed,
                        "passed": passed,
                    }
                    print(json.dumps(row), flush=True)
                    if not passed:
                        failures.append(row)
                    bypass = transaction(server, cd=True)
                    before = counts(address)
                    retained_failure = transaction(server)
                    after = counts(address)
                    row = {
                        "server": server,
                        "mode": mode,
                        "check": "cd-bypasses-validation-failure-without-poisoning-ordinary-query",
                        "cd": bypass,
                        "ordinary": retained_failure,
                        "before": before,
                        "after": after,
                        "passed": before == after,
                    }
                    print(json.dumps(row), flush=True)
                    if not row["passed"]:
                        failures.append(row)
                chain.cleanup()
    finally:
        chain.cleanup()
        docker("rm", "-f", PREFIX + "probe", check=False, capture=True)
        docker("network", "rm", NETWORK, check=False, capture=True)
    print(
        json.dumps({"result": "FAIL" if failures else "PASS", "failures": failures}),
        flush=True,
    )
    if failures:
        raise SystemExit("signed failure-cache gate failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=CLI_IMAGE)
    parser.add_argument("--mode", choices=("nsec", "nsec3", "both"), default="both")
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
