#!/usr/bin/env python3
"""Observe authoritative options/error handling over real UDP and TCP."""

import argparse
import gzip
import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import subprocess
import tarfile
import tempfile

from labs.authority import similar as lab
from benchmarks.diversity_compare import identity, logs, log_digest
from support.lock import exclusive_laboratory
from support.docker import docker
from support.evidence import write_record


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-image", default="donna-ingress-control:local")
    parser.add_argument("--candidate-image")
    parser.add_argument("--candidate-source-manifest", type=Path)
    parser.add_argument("--candidate-source-archive", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/interop/.artifacts/ingress-wire.json"),
    )
    parser.add_argument("--control-source-archive", type=Path, required=True)
    args = parser.parse_args()
    suite = SUITE
    lab.PREFIX = "donna-ingress-wire-"
    lab.NETWORK, lab.VOLUME, lab.CERTS = (
        lab.PREFIX + kind for kind in ("network", "public-zone", "certificates")
    )
    lab.WORKERS = 2
    lab.ROLES = {
        "current": (identity(args.control_image), "172.29.58.11"),
        "knot": (identity("cznic/knot:3.6"), "172.29.58.30"),
        "hickory": (identity("donna-interop-hickory:0.26.3"), "172.29.58.50"),
    }
    if args.candidate_image:
        assert args.candidate_source_manifest and args.candidate_source_archive
        lab.ROLES["verified"] = (identity(args.control_image), "172.29.58.10")
        lab.ROLES["current"] = (identity(args.candidate_image), "172.29.58.11")
    client = identity("donna-interop-diversity-client:checked-v2")
    offline = lab.PREFIX + "offline"
    files = [
        "labs/transport/ingress_wire_compare.py",
        "python/ingress_wire.py",
        "python/ingress_wire_test.py",
        "labs/authority/similar.py",
        "labs/authority/similar_fixture.py",
        "labs/authority/similar_cli.py",
        "benchmarks/diversity_compare.py",
        "labs/transport/transport_compare.py",
        "labs/full.py",
        "support/__init__.py",
        "support/lock.py",
        "support/docker.py",
        "support/paths.py",
        "support/topology.py",
        "support/evidence.py",
    ]
    record = dict(
        scope="Bounded first-response UDP/TCP eligibility, options and error-precedence observations; normal peer observations; optional explicit candidate parity, not throughput or universal precedence certification",
        images={role: image for role, (image, _) in lab.ROLES.items()},
        client=client,
        workers=2,
        source_sha256={
            name: hashlib.sha256((suite / name).read_bytes()).hexdigest()
            for name in files
        },
        fixture=(suite / "fixtures/basic/zone.db").read_text(),
        dns_signing_keys_created=0,
        rows=[],
    )
    if args.candidate_image:
        record["candidate_source_manifest"] = json.loads(
            args.candidate_source_manifest.read_text()
        )
        record["candidate_source_manifest_sha256"] = hashlib.sha256(
            args.candidate_source_manifest.read_bytes()
        ).hexdigest()
        record["candidate_source_archive"] = dict(
            path=str(args.candidate_source_archive),
            sha256=hashlib.sha256(
                args.candidate_source_archive.read_bytes()
            ).hexdigest(),
        )
    normal_source = args.control_source_archive
    record["normal_source"] = dict(
        path=str(normal_source),
        sha256=hashlib.sha256(normal_source.read_bytes()).hexdigest(),
    )
    record["candidate_comparison"] = bool(args.candidate_image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        docker(
            "network", "create", "--subnet", "172.29.58.0/24", lab.NETWORK, capture=True
        )
        for volume in (lab.VOLUME, lab.CERTS):
            docker("volume", "create", volume, capture=True)
        docker(
            "run",
            "--rm",
            "-v",
            lab.CERTS + ":/certs",
            "donna-interop-peers",
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
            "donna-interop-bind",
            "sleep",
            "infinity",
            capture=True,
        )
        for name, network in ((lab.PREFIX + "probe", lab.NETWORK), (offline, "none")):
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                network,
                "--entrypoint",
                "sleep",
                client,
                "infinity",
                capture=True,
            )
            for file in ("ingress_wire.py", "ingress_wire_test.py"):
                docker("cp", str(suite / "python" / file), name + ":/suite/" + file)
        unit = subprocess.run(
            ["docker", "exec", offline, "python", "/suite/ingress_wire_test.py"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        record["unit"] = dict(
            exit_code=unit.returncode, output=unit.stdout, network="none"
        )
        assert unit.returncode == 0, unit.stdout
        with tempfile.TemporaryDirectory(prefix="donna-ingress-wire-") as temporary:
            root = Path(temporary)
            for name in files:
                target = root / "harness" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((suite / name).read_bytes())
            lab.put(root, "unsigned.db", record["fixture"])
            lab.put(
                root,
                "knot.conf",
                "server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n    udp-workers: 2\n    tcp-workers: 2\n    background-workers: 1\n    udp-max-payload: 1232\n"
                "log:\n  - target: stderr\n    any: error\ndatabase:\n    storage: /tmp/knot-db\ntemplate:\n  - id: default\n    storage: /tmp\n    zonefile-sync: -1\n"
                "zone:\n  - domain: example.test.\n    file: /work/active.db\n    dnssec-signing: off\n",
            )
            lab.put(
                root,
                "hickory.toml",
                'listen_addrs_ipv4 = ["0.0.0.0"]\nlisten_addrs_ipv6 = []\nlisten_port = 53\ndirectory = "/work"\ndrop_privileges = false\n'
                '[[zones]]\nzone = "example.test."\nzone_type = "Primary"\nfile = "active.db"\naxfr_policy = "AllowAll"\n',
            )
            lab.start("unsigned")
            record["donna_binary_sha256"] = docker(
                "exec",
                lab.PREFIX + "current",
                "sha256sum",
                "/usr/local/bin/listeners",
                capture=True,
            ).split()[0]
            before = logs()
            command = [
                "docker",
                "exec",
                lab.PREFIX + "probe",
                "python",
                "/suite/ingress_wire.py",
            ]
            for role, (_, address) in lab.ROLES.items():
                command += [
                    "--server",
                    f"{role}={address}:{5300 if role in ('verified', 'current') else 53}",
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
            artifact = args.output.parent / "binaries/ingress-wire-runtime.log.gz"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(gzip.compress(runtime.stdout.encode(), mtime=0))
            record["runtime_artifact"] = dict(
                path=str(artifact),
                sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            )
            assert runtime.returncode == 0, runtime.stdout[-3000:]
            after = logs()
            record["logs"] = dict(
                before=log_digest(before),
                after=log_digest(after),
                unchanged=before == after,
                scope="Malformed traffic may emit diagnostics; this correctness-only corpus is not a quiet throughput run",
            )
            log_artifact = (
                args.output.parent / "binaries/ingress-wire-server-logs.json.gz"
            )
            log_artifact.write_bytes(
                gzip.compress(
                    json.dumps(
                        {
                            "before": {k: v.hex() for k, v in before.items()},
                            "after": {k: v.hex() for k, v in after.items()},
                        }
                    ).encode(),
                    mtime=0,
                )
            )
            record["logs"]["artifact"] = str(log_artifact)
            record["logs"]["artifact_sha256"] = hashlib.sha256(
                log_artifact.read_bytes()
            ).hexdigest()
            observations = dict(
                rows=[row for row in record["rows"] if "complete" not in row],
                roles=list(lab.ROLES),
            )
            (root / "observations.json").write_text(json.dumps(observations))
            (root / "fixture.db").write_text(record["fixture"])
            docker(
                "cp",
                str(root / "observations.json"),
                offline + ":/suite/observations.json",
            )
            replay = subprocess.run(
                [
                    "docker",
                    "exec",
                    offline,
                    "python",
                    "/suite/ingress_wire.py",
                    "--replay",
                    "/suite/observations.json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            record["offline_replay"] = dict(
                exit_code=replay.returncode, output=replay.stdout, network="none"
            )
            assert replay.returncode == 0, replay.stdout
            public = args.output.parent / "binaries/ingress-wire-public.tar.gz"
            with tarfile.open(public, "w:gz") as archive:
                for path in root.iterdir():
                    archive.add(path, arcname=path.name)
            record["public_archive"] = dict(
                path=str(public), sha256=hashlib.sha256(public.read_bytes()).hexdigest()
            )
            record["complete"] = True
    except Exception as error:
        record["complete"] = False
        record["error"] = repr(error)
        raise
    finally:
        docker("rm", "-f", offline, check=False, capture=True)
        lab.cleanup()
        record["cleanup"] = (
            "Task-only role/probe/offline/carrier containers, network and two volumes removed; no runtime images built."
        )
        write_record(args.output, record)


if __name__ == "__main__":
    main()
