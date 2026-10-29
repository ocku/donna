#!/usr/bin/env python3
"""Bounded Donna/Knot/Hickory framing/truncation comparison; no throughput load."""

import argparse
import gzip
import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import subprocess
import tempfile

from labs.authority import similar as lab
from support.lock import exclusive_laboratory
from support.docker import docker


from support.evidence import write_record


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default="donna-single-worker-batch:local")
    parser.add_argument("--knot-image", default="cznic/knot:3.6")
    parser.add_argument("--hickory-image", default="donna-interop-hickory:0.26.3")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/interop/.artifacts/transport-matrix.json"),
    )
    args = parser.parse_args()
    suite = SUITE
    lab.PREFIX = "donna-transport-matrix-"
    lab.NETWORK, lab.VOLUME, lab.CERTS = (
        lab.PREFIX + kind for kind in ("network", "public-zone", "certificates")
    )
    lab.ROLES = {
        "current": (args.donna_image, "172.29.55.10"),
        "knot": (args.knot_image, "172.29.55.30"),
        "hickory": (args.hickory_image, "172.29.55.50"),
    }
    lab.WORKERS = 2
    offline = lab.PREFIX + "offline"
    identity = {
        role: json.loads(docker("image", "inspect", image, capture=True))[0]["Id"]
        for role, (image, _) in lab.ROLES.items()
    }
    lab.ROLES = {
        role: (identity[role], address) for role, (_, address) in lab.ROLES.items()
    }
    tools = {
        name: json.loads(docker("image", "inspect", name, capture=True))[0]["Id"]
        for name in ("donna-interop-peers", "donna-interop-bind")
    }
    source = [
        suite / "labs/transport/transport_compare.py",
        suite / "python/transport_matrix.py",
        suite / "python/transport_matrix_test.py",
        suite / "python/dns_packet_layout.py",
        suite / "fixtures/basic/zone.db",
        suite / "labs/authority/similar.py",
        suite / "labs/authority/similar_fixture.py",
        suite / "labs/authority/similar_cli.py",
    ]
    record = dict(
        scope="Unsigned bounded TCP framing/pipeline/reuse and UDP truncation/recovery; no throughput or exhaustive RFC claim",
        images=identity,
        tool_images=tools,
        source_sha256={
            str(p.relative_to(suite)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source
        },
        fixture=suite.joinpath("fixtures/basic/zone.db").read_text(),
        dns_signing_keys_created=0,
        configuration={
            "workers": 2,
            "knot_udp_max_payload": 1232,
            "other_udp_limits": "implementation defaults; client payload limits checked independently",
        },
    )
    try:
        docker(
            "network", "create", "--subnet", "172.29.55.0/24", lab.NETWORK, capture=True
        )
        for volume in (lab.VOLUME, lab.CERTS):
            docker("volume", "create", volume, capture=True)
        docker(
            "run",
            "--rm",
            "-v",
            lab.CERTS + ":/certs",
            tools["donna-interop-peers"],
            "python",
            "certificates.py",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            lab.PREFIX + "signer",
            "--network",
            "none",
            "-v",
            lab.VOLUME + ":/work",
            tools["donna-interop-bind"],
            "sleep",
            "infinity",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            lab.PREFIX + "probe",
            "--network",
            lab.NETWORK,
            "--entrypoint",
            "sleep",
            tools["donna-interop-peers"],
            "infinity",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            offline,
            "--network",
            "none",
            "-e",
            "PYTHONPATH=/suite",
            "--entrypoint",
            "sleep",
            tools["donna-interop-peers"],
            "infinity",
            capture=True,
        )
        for container in (lab.PREFIX + "probe", offline):
            for name in (
                "transport_matrix.py",
                "transport_matrix_test.py",
                "dns_packet_layout.py",
            ):
                docker(
                    "cp", str(suite / "python" / name), container + ":/suite/" + name
                )
        unit = subprocess.run(
            ["docker", "exec", offline, "python", "/suite/transport_matrix_test.py"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        record["checker_unit"] = dict(
            exit_code=unit.returncode, output=unit.stdout, network="none"
        )
        assert unit.returncode == 0, unit.stdout
        with tempfile.TemporaryDirectory(prefix="donna-transport-public-") as temporary:
            directory = Path(temporary)
            lab.put(directory, "unsigned.db", record["fixture"])
            lab.put(
                directory,
                "knot.conf",
                "server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n"
                "    udp-workers: 2\n    tcp-workers: 2\n    background-workers: 1\n    udp-max-payload: 1232\n"
                "log:\n  - target: stderr\n    any: error\ndatabase:\n    storage: /tmp/knot-db\n"
                "template:\n  - id: default\n    storage: /tmp\n    zonefile-sync: -1\n"
                "zone:\n  - domain: example.test.\n    file: /work/active.db\n    dnssec-signing: off\n",
            )
            lab.put(
                directory,
                "hickory.toml",
                'listen_addrs_ipv4 = ["0.0.0.0"]\nlisten_addrs_ipv6 = []\n'
                'listen_port = 53\ndirectory = "/work"\ndrop_privileges = false\n'
                '[[zones]]\nzone = "example.test."\nzone_type = "Primary"\nfile = "active.db"\naxfr_policy = "AllowAll"\n',
            )
            lab.start("unsigned")
            command = [
                "docker",
                "exec",
                lab.PREFIX + "probe",
                "python",
                "/suite/transport_matrix.py",
            ]
            for role, (_, address) in lab.ROLES.items():
                command += [
                    "--server",
                    f"{role}={address}:{5300 if role == 'current' else 53}",
                ]
            runtime = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            record["runtime_exit_code"] = runtime.returncode
            record["rows"] = [
                json.loads(line)
                for line in runtime.stdout.splitlines()
                if line.startswith("{")
            ]
            target = args.output.parent / "binaries/transport-matrix-runtime.log.gz"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(gzip.compress(runtime.stdout.encode(), mtime=0))
            record["raw_output"] = str(target)
            record["raw_output_sha256"] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
            if runtime.returncode:
                record["failure_output"] = runtime.stdout[-2000:]
            if any("complete" in row for row in record["rows"]):
                path = directory / "observations.jsonl"
                path.write_text(runtime.stdout)
                docker("cp", str(path), offline + ":/suite/observations.jsonl")
                replay = subprocess.run(
                    [
                        "docker",
                        "exec",
                        offline,
                        "python",
                        "/suite/transport_matrix.py",
                        "--replay",
                        "/suite/observations.jsonl",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                record["offline_replay"] = dict(
                    exit_code=replay.returncode, network="none", output=replay.stdout
                )
                assert replay.returncode == 0, replay.stdout
            assert runtime.returncode == 0, record.get("failure_output")
    finally:
        docker("rm", "-f", offline, check=False, capture=True)
        lab.cleanup()
        record["cleanup"] = (
            "Task-owned role/probe/offline/carrier containers, network and both volumes removed; no images or host targets built."
        )
        write_record(args.output, record)


if __name__ == "__main__":
    main()
