#!/usr/bin/env python3
"""One fresh-process candidate correctness pass against the retained 768-query pool."""

import argparse
import gzip
import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

from labs.authority import similar as lab
from benchmarks.diversity_compare import identity, logs, log_digest
from support.lock import exclusive_laboratory
from support.docker import docker
from support.evidence import write_record

sys.path.insert(0, str(SUITE / "python"))
from diversity_fixture import fixture


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--client-image", default="donna-interop-diversity-client:checked-v2"
    )
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-overlay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-archive", type=Path, required=True)
    args = parser.parse_args()
    public = args.baseline_archive
    client = identity(args.client_image)
    lab.PREFIX = "donna-diversity-candidate-"
    lab.NETWORK, lab.VOLUME, lab.CERTS = (
        lab.PREFIX + kind for kind in ("network", "public-zone", "certificates")
    )
    lab.ROLES = {"current": (identity(args.image), "172.29.57.10")}
    lab.WORKERS = 2
    offline = lab.PREFIX + "offline"
    record = dict(
        scope="One fresh-process finite correctness gate; no candidate throughput comparison",
        image=lab.ROLES["current"][0],
        client=client,
        population=768,
        source_manifest=json.loads(args.source_manifest.read_text()),
        source_manifest_sha256=hashlib.sha256(
            args.source_manifest.read_bytes()
        ).hexdigest(),
        source_overlay=dict(
            path=str(args.source_overlay),
            sha256=hashlib.sha256(args.source_overlay.read_bytes()).hexdigest(),
        ),
        baseline_public_pool=dict(
            path=str(public), sha256=hashlib.sha256(public.read_bytes()).hexdigest()
        ),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        docker(
            "network", "create", "--subnet", "172.29.57.0/24", lab.NETWORK, capture=True
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
        with tempfile.TemporaryDirectory(prefix="donna-diversity-candidate-") as temp:
            root = Path(temp)
            with tarfile.open(public) as archive:
                (root / "expected.json").write_bytes(
                    archive.extractfile("current-pre.json").read()
                )
            docker(
                "cp",
                str(root / "expected.json"),
                lab.PREFIX + "probe:/suite/expected.json",
            )
            lab.put(root, "unsigned.db", fixture())
            lab.start("unsigned")  # TCP readiness only; no DNS preflight.
            record["process"] = docker(
                "inspect",
                "--format",
                "{{.Id}} {{.State.StartedAt}}",
                lab.PREFIX + "current",
                capture=True,
            )
            record["binary_sha256"] = docker(
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
                "/suite/diversity_load.py",
                "finite",
                "--server",
                "172.29.57.10:5300",
                "--references",
                "/suite/expected.json",
                "--seconds",
                "5",
            ]
            finite = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            record["native_command_output"] = finite.stdout
            record["native_exit_code"] = finite.returncode
            assert finite.returncode == 0, finite.stdout
            record["finite"] = json.loads(finite.stdout)
            assert (
                record["finite"]["queries"] == 768
                and record["finite"]["response_body_verified"] is True
            )
            captured = subprocess.run(
                [
                    "docker",
                    "exec",
                    lab.PREFIX + "probe",
                    "python",
                    "/suite/diversity_load.py",
                    "capture",
                    "--server",
                    "172.29.57.10:5300",
                    "--references",
                    "/suite/post.json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            record["semantic_output"] = captured.stdout
            assert captured.returncode == 0, captured.stdout
            docker("cp", lab.PREFIX + "probe:/suite/post.json", str(root / "post.json"))
            assert json.loads((root / "post.json").read_text()) == json.loads(
                (root / "expected.json").read_text()
            )
            docker("cp", str(root / "post.json"), offline + ":/suite/post.json")
            replay = subprocess.run(
                [
                    "docker",
                    "exec",
                    offline,
                    "python",
                    "/suite/diversity_load.py",
                    "replay",
                    "--references",
                    "/suite/post.json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            record["offline_replay"] = dict(
                exit_code=replay.returncode, output=replay.stdout, network="none"
            )
            assert replay.returncode == 0, replay.stdout
            assert logs() == before
            record["log_gate"] = dict(
                before=log_digest(before), after=log_digest(logs())
            )
            target = (
                args.output.parent / "binaries" / (args.output.stem + "-public.json.gz")
            )
            target.write_bytes(
                gzip.compress((root / "post.json").read_bytes(), mtime=0)
            )
            record["public_capture"] = dict(
                path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest()
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
            "All task containers/network/two volumes removed; no images built."
        )
        write_record(args.output, record)


if __name__ == "__main__":
    main()
