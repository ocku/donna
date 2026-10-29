#!/usr/bin/env python3
"""Run native pinned Knot Resolver and Hickory against an isolated signed tree."""

import argparse
import json
import tempfile
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes
from support.recursive_peers import HICKORY_IMAGE, KNOT_IMAGE, start_peer
from support.topology import NETWORK, PREFIX, docker

from labs.dnssec import chain

PEERS = {"knot-resolver": "172.29.53.75", "hickory": "172.29.53.76"}


@exclusive_laboratory
def execute(output):
    if (
        NETWORK
        in docker("network", "ls", "--format", "{{.Name}}", capture=True).splitlines()
    ):
        raise RuntimeError("shared laboratory network already exists")
    record = {
        "scope": "signed iterative recursion smoke; no timing comparison",
        "images": {},
        "fixtures": [],
        "rows": [],
        "logs": {},
        "resources": {},
        "authority_logs": {},
        "configurations": {},
        "harness_sha256": {},
    }
    for role, image in (("knot-resolver", KNOT_IMAGE), ("hickory", HICKORY_IMAGE)):
        identity = json.loads(docker("image", "inspect", image, capture=True))[0]
        record["images"][role] = {
            key: identity[key] for key in ("Id", "RepoDigests", "Architecture")
        }
    record["harness_sha256"] = harness_hashes(
        SUITE,
        (
            "labs/recursive/recursive_peer_smoke.py",
            "support/recursive_peers.py",
            "labs/dnssec/chain.py",
            "labs/dnssec/chain_fixture.py",
            "python/recursive_peer_probe.py",
            "docker/KnotResolver.Dockerfile",
        ),
    )
    docker("network", "create", "--subnet", "172.29.53.0/24", NETWORK, capture=True)
    try:
        for mode in ("nsec", "nsec3"):
            with tempfile.TemporaryDirectory(
                prefix="donna-recursive-peer-"
            ) as temporary:
                directory = Path(temporary)
                docker("volume", "create", chain.VOLUME, capture=True)
                docker(
                    "run",
                    "-d",
                    "--name",
                    PREFIX + "probe",
                    "--network",
                    NETWORK,
                    "--memory",
                    "256m",
                    "--cpus",
                    ".5",
                    "-v",
                    chain.VOLUME + ":/work:ro",
                    PREFIX + "peers",
                    "sleep",
                    "infinity",
                    capture=True,
                )
                docker(
                    "cp",
                    str(SUITE / "python/recursive_peer_probe.py"),
                    PREFIX + "probe:/suite/recursive_peer_probe.py",
                    capture=True,
                )
                chain.prepare(directory, 1, mode)
                for zone, origin in chain.ORIGINS.items():
                    verification = docker(
                        "exec",
                        "-w",
                        "/work/" + zone,
                        chain.SIGNER,
                        "dnssec-verify",
                        "-o",
                        origin,
                        "active.db",
                        capture=True,
                    )
                    record["fixtures"].append(
                        {
                            "mode": mode,
                            "zone": zone,
                            "public_zone": docker(
                                "exec",
                                chain.SIGNER,
                                "cat",
                                f"/work/{zone}/active.db",
                                capture=True,
                            ),
                            "verification": verification,
                        }
                    )
                chain.start_authorities()
                for name in chain.AUTHORITIES:
                    docker(
                        "update",
                        "--memory",
                        "128m",
                        "--memory-swap",
                        "128m",
                        "--cpus",
                        ".15",
                        PREFIX + "chain-" + name,
                        capture=True,
                    )
                for bad_ds in (False, True):
                    if bad_ds:
                        docker(
                            "exec",
                            chain.SIGNER,
                            "cp",
                            "/work/tld/bad-ds.db",
                            "/work/tld/active.db",
                        )
                        docker("restart", PREFIX + "chain-tld", capture=True)
                        record["fixtures"].append(
                            {
                                "mode": mode,
                                "zone": "bad-ds-tld",
                                "public_zone": docker(
                                    "exec",
                                    chain.SIGNER,
                                    "cat",
                                    "/work/tld/active.db",
                                    capture=True,
                                ),
                            }
                        )
                    for role, address in PEERS.items():
                        name = PREFIX + "recursive-smoke-" + role
                        try:
                            start_peer(
                                role,
                                name,
                                NETWORK,
                                chain.VOLUME,
                                address,
                                directory / role,
                            )
                            limits = json.loads(docker("inspect", name, capture=True))[
                                0
                            ]["HostConfig"]
                            record["resources"][role] = {
                                key: limits.get(key)
                                for key in ("NanoCpus", "Memory", "Tmpfs")
                            }
                            record["configurations"][role] = next(
                                (directory / role).iterdir()
                            ).read_text()
                            command = [
                                "exec",
                                PREFIX + "probe",
                                "python",
                                "/suite/recursive_peer_probe.py",
                                "--host",
                                address,
                            ]
                            if bad_ds:
                                command.append("--bad-ds")
                            rows = json.loads(docker(*command, capture=True))
                            if len(rows) != (2 if bad_ds else 6):
                                raise RuntimeError("incomplete peer smoke")
                            for row in rows:
                                row.update(mode=mode, server=role)
                            record["rows"].extend(rows)
                        finally:
                            record["logs"][f"{mode}/{bad_ds}/{role}"] = docker(
                                "logs", name, check=False, capture=True
                            )
                            docker("rm", "-fv", name, check=False, capture=True)
                    record["authority_logs"][f"{mode}/{bad_ds}"] = {
                        zone: docker("logs", PREFIX + "chain-" + zone, capture=True)
                        for zone in chain.AUTHORITIES
                    }
                docker("rm", "-fv", PREFIX + "probe", check=False, capture=True)
                chain.cleanup()
    finally:
        docker(
            "rm",
            "-fv",
            PREFIX + "probe",
            *(PREFIX + "recursive-smoke-" + role for role in PEERS),
            check=False,
            capture=True,
        )
        chain.cleanup()
        docker("network", "rm", NETWORK, check=False, capture=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        record["passed"] = len(record["rows"]) == 32 and all(
            row["passed"] for row in record["rows"]
        )
        output.write_text(json.dumps(record, indent=2) + "\n")
    if not record["passed"]:
        raise SystemExit("recursive peer smoke failed; inspect " + str(output))
    print(
        json.dumps(
            {"result": "PASS", "checks": len(record["rows"]), "output": str(output)}
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=SUITE / ".artifacts/recursive-peer-smoke.json"
    )
    execute(parser.parse_args().output)
