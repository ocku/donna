#!/usr/bin/env python3
"""One mixed finite-owner workload, cold first pass and cyclic throughput."""

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from labs.authority import similar as lab
from support.docker import docker
from support.evidence import write_record
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes, harness_sources
from support.server_cpu import difference, snapshot

sys.path.insert(0, str(SUITE / "python"))
from diversity_fixture import fixture


def identity(image):
    return json.loads(docker("image", "inspect", image, capture=True))[0]["Id"]


def logs():
    return {
        role: subprocess.check_output(
            ["docker", "logs", lab.PREFIX + role], stderr=subprocess.STDOUT
        )
        for role in lab.ROLES
    }


def log_digest(values):
    return {
        role: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        for role, data in values.items()
    }


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default="donna-ingress-control:local")
    parser.add_argument(
        "--client-image", default="donna-interop-diversity-client:local"
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/interop/.artifacts/diversity-workload.json"),
    )
    args = parser.parse_args()
    assert 1 <= args.repeats <= 10 and 0 < args.seconds <= 10
    suite = SUITE
    lab.PREFIX = "donna-diversity-"
    lab.NETWORK, lab.VOLUME, lab.CERTS = (
        lab.PREFIX + kind for kind in ("network", "public-zone", "certificates")
    )
    lab.WORKERS = 2
    lab.ROLES = {
        "current": (identity(args.donna_image), "172.29.56.10"),
        "knot": (identity("cznic/knot:3.6"), "172.29.56.30"),
        "hickory": (identity("donna-interop-hickory:0.26.3"), "172.29.56.50"),
    }
    client = identity(args.client_image)
    offline = lab.PREFIX + "offline"
    files = [
        "benchmarks/diversity_compare.py",
        "python/diversity_fixture.py",
        "python/diversity_load.py",
        "python/diversity_load_test.py",
        "python/diversity_replay.py",
        "python/diversity_replay_test.py",
        "python/batched_load.c",
        "python/batched_load_test.py",
        "support/server_cpu.py",
        "labs/authority/similar.py",
        "labs/authority/similar_fixture.py",
        "labs/authority/similar_cli.py",
        "labs/transport/transport_compare.py",
        "support/__init__.py",
        "support/lock.py",
        "support/docker.py",
        "support/paths.py",
        "support/topology.py",
        "support/evidence.py",
        "labs/full.py",
        "docker/DiversityClient.Dockerfile",
    ]
    files = harness_sources(suite, files)
    record = dict(
        scope="Unsigned 256 explicit owners x A/AAAA/TXT; deterministic shuffled finite list and cyclic pool, not a popularity/eviction model",
        images={role: image for role, (image, _) in lab.ROLES.items()},
        client_image=client,
        client_build_bases={
            name: identity(name)
            for name in ("rust:bookworm", "donna-interop-cache-client-body:local")
        },
        harness_sha256=harness_hashes(suite, files),
        source_manifest=json.loads(args.source_manifest.read_text()),
        source_manifest_sha256=hashlib.sha256(
            args.source_manifest.read_bytes()
        ).hexdigest(),
        donna_source_archive=dict(
            path=str(args.source_archive),
            sha256=hashlib.sha256(args.source_archive.read_bytes()).hexdigest(),
        ),
        repeats=args.repeats,
        seconds=args.seconds,
        workers=2,
        outstanding=32,
        population=768,
        cold_definition="Each finite pass follows a fresh server process; readiness opens TCP only; no DNS query reaches that server before the finite pass. References captured on earlier processes.",
        resource_limits="No CPU quota/affinity; shared Docker host, laboratory lock; one timed client at a time.",
        limitations="Finite CPU ticks are coarse. Cyclic pool is bounded reuse, not unbounded churn. Singleton immutable authoritative data has no TTL aging or record-order rotation. Body-off controls measure combined lookup+comparison effects in sequential samples, not an isolated instruction cost.",
        dns_signing_keys_created=0,
        restarts=[],
        rows=[],
        references={},
        logging=[],
    )
    raw = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prefix = args.output.parent / "binaries/diversity-workload"

    def execute(command):
        run = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        raw.append(dict(command=command, exit_code=run.returncode, output=run.stdout))
        assert run.returncode == 0, run.stdout
        return run.stdout

    try:
        docker(
            "network", "create", "--subnet", "172.29.56.0/24", lab.NETWORK, capture=True
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
        for container, network in (
            (lab.PREFIX + "probe", lab.NETWORK),
            (offline, "none"),
        ):
            docker(
                "run",
                "-d",
                "--name",
                container,
                "--network",
                network,
                "--entrypoint",
                "sleep",
                client,
                "infinity",
                capture=True,
            )
            for name in (
                "diversity_fixture.py",
                "diversity_load.py",
                "diversity_replay.py",
            ):
                docker(
                    "cp", str(suite / "python" / name), container + ":/suite/" + name
                )
            docker(
                "cp",
                str(suite / "support/server_cpu.py"),
                container + ":/suite/server_cpu.py",
            )
        record["native_binary_sha256"] = docker(
            "exec",
            lab.PREFIX + "probe",
            "sha256sum",
            "/usr/local/bin/batched_load",
            capture=True,
        ).split()[0]
        with tempfile.TemporaryDirectory(prefix="donna-diversity-public-") as temporary:
            root = Path(temporary)
            (root / "source-manifest.json").write_bytes(
                args.source_manifest.read_bytes()
            )
            for name in files:
                target = root / "harness" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((suite / name).read_bytes())
            docker(
                "cp",
                lab.PREFIX + "probe:/usr/local/bin/batched_load",
                str(root / "batched_load"),
            )
            lab.put(root, "unsigned.db", fixture())
            (root / "fixture.db").write_text(fixture())
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
            initial_logs = logs()
            for phase in ("pre",):
                for role, (_, address) in lab.ROLES.items():
                    ref = f"/suite/{role}-{phase}.json"
                    execute(
                        [
                            "docker",
                            "exec",
                            lab.PREFIX + "probe",
                            "python",
                            "/suite/diversity_load.py",
                            "capture",
                            "--server",
                            f"{address}:{5300 if role == 'current' else 53}",
                            "--references",
                            ref,
                        ]
                    )
                    docker(
                        "cp",
                        lab.PREFIX + "probe:" + ref,
                        str(root / f"{role}-{phase}.json"),
                    )
                    record["references"][f"{role}-{phase}"] = hashlib.sha256(
                        (root / f"{role}-{phase}.json").read_bytes()
                    ).hexdigest()
            assert logs() == initial_logs
            record["logging"].append(
                dict(
                    phase="preflight",
                    before=log_digest(initial_logs),
                    after=log_digest(logs()),
                )
            )
            for trial in range(args.repeats):
                lab.start("unsigned")
                processes = {
                    role: docker(
                        "inspect",
                        "--format",
                        "{{.Id}} {{.State.StartedAt}}",
                        lab.PREFIX + role,
                        capture=True,
                    )
                    for role in lab.ROLES
                }
                record["restarts"].append(dict(trial=trial, processes=processes))
                expected_logs = logs()
                roles = list(lab.ROLES)
                roles = roles[trial % 3 :] + roles[: trial % 3]
                for mode, strict in [("finite", True)] + (
                    [("cycle", True), ("cycle", False)]
                    if trial % 2 == 0
                    else [("cycle", False), ("cycle", True)]
                ):
                    for role in roles:
                        address = lab.ROLES[role][1]
                        before = snapshot(lab.PREFIX + role)
                        output = execute(
                            [
                                "docker",
                                "exec",
                                lab.PREFIX + "probe",
                                "python",
                                "/suite/diversity_load.py",
                                mode,
                                "--server",
                                f"{address}:{5300 if role == 'current' else 53}",
                                "--references",
                                f"/suite/{role}-pre.json",
                                "--seconds",
                                str(5 if mode == "finite" else args.seconds),
                            ]
                            + ([] if strict else ["--without-body"])
                        )
                        row = json.loads(output)
                        row.update(
                            role=role,
                            trial=trial,
                            server_cpu=difference(
                                before, snapshot(lab.PREFIX + role), row["queries"]
                            ),
                        )
                        record["rows"].append(row)
                        assert logs() == expected_logs
                record["logging"].append(
                    dict(
                        phase=f"trial-{trial}",
                        before=log_digest(expected_logs),
                        after=log_digest(logs()),
                    )
                )
            for role, (_, address) in lab.ROLES.items():
                ref = f"/suite/{role}-post.json"
                execute(
                    [
                        "docker",
                        "exec",
                        lab.PREFIX + "probe",
                        "python",
                        "/suite/diversity_load.py",
                        "capture",
                        "--server",
                        f"{address}:{5300 if role == 'current' else 53}",
                        "--references",
                        ref,
                    ]
                )
                docker(
                    "cp", lab.PREFIX + "probe:" + ref, str(root / f"{role}-post.json")
                )
                record["references"][f"{role}-post"] = hashlib.sha256(
                    (root / f"{role}-post.json").read_bytes()
                ).hexdigest()
                assert json.loads(
                    (root / f"{role}-pre.json").read_text()
                ) == json.loads((root / f"{role}-post.json").read_text())
            assert logs() == expected_logs
            record["logging"].append(
                dict(
                    phase="postflight",
                    before=log_digest(expected_logs),
                    after=log_digest(logs()),
                )
            )
            record["complete"] = True
            write_record(root / "result.json", record)
            docker("cp", str(root) + "/.", offline + ":/evidence")
            record["offline_replay"] = execute(
                [
                    "docker",
                    "exec",
                    offline,
                    "python",
                    "/suite/diversity_replay.py",
                    "/evidence",
                ]
            )
            prefix.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(str(prefix) + "-public.tar.gz", "w:gz") as archive:
                for path in root.iterdir():
                    archive.add(path, arcname=path.name)
    except Exception as error:
        record["complete"] = False
        record["error"] = repr(error)
        raise
    finally:
        docker("rm", "-f", offline, check=False, capture=True)
        lab.cleanup()
        record["cleanup"] = (
            "Task-owned containers/network/two volumes removed; shared runtime/client images retained."
        )
        prefix.parent.mkdir(parents=True, exist_ok=True)
        raw_path = Path(str(prefix) + "-raw.json.gz")
        raw_path.write_bytes(gzip.compress(json.dumps(raw).encode(), mtime=0))
        record["raw_artifact"] = str(raw_path)
        record["raw_sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
        write_record(args.output, record)


if __name__ == "__main__":
    main()
