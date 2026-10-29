#!/usr/bin/env python3
"""Retain signed recursive negative-cache observations before any optimization."""

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from support.capture_trials import checkpoint, request_delta
from support.daemon import (
    CLI_IMAGE,
    record_runtime_identity,
    require_cli,
    resolver_port,
)
from support.docker import docker
from support.evidence import write_record
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes, harness_sources
from support.recursive_lab import ADDRESSES, CLIENT, PREFIX, Lab, identity
from support.recursive_peers import HICKORY_IMAGE, KNOT_IMAGE

sys.path.insert(0, str(SUITE / "python"))
from negative_fixture import CHILD, additions
from recursive_refresh import events

MODULES = [
    "negative_fixture.py",
    "negative_denial.py",
    "negative_evidence.py",
    "negative_refresh.py",
    "negative_security.py",
    "negative_proof_bank.py",
    "negative_worker.py",
    "recursive_fixture.py",
    "recursive_evidence.py",
    "recursive_capture.py",
    "recursive_refresh.py",
    "recursive_worker.py",
]
FILES = [
    "benchmarks/negative_discovery.py",
    "support/recursive_lab.py",
    "support/recursive_peers.py",
    "support/capture_trials.py",
    "support/__init__.py",
    "support/lock.py",
    "support/docker.py",
    "support/paths.py",
    "support/topology.py",
    "support/evidence.py",
    "labs/full.py",
    "python/batched_load.c",
    "docker/RecursiveClient.Dockerfile",
] + ["python/" + name for name in MODULES]
FILES = harness_sources(SUITE, FILES)


def child_zone(lab, public):
    public["unsigned_child"] = CHILD
    lab.put("child.db", CHILD, public=True)
    config = (
        (lab.directory / "tld.conf").read_text()
        + '\nzone "cut.example.test." { type primary; file "/work/child.db"; };\n'
    )
    lab.put("tld.conf", config, public=True)
    lab.put("public.json", json.dumps(public), public=True)
    lab.run("restart", PREFIX + "tld")


def stream(lab, role, scenario, record, extra=()):
    record_runtime_identity(record, role, PREFIX + role)
    previous = lab.authority_logs()
    argv = [
        "docker",
        "exec",
        "-i",
        CLIENT,
        "python",
        "/suite/negative_worker.py",
        "stream",
        "--host",
        ADDRESSES[role],
        "--port",
        str(resolver_port(role)),
        "--scenario",
        scenario,
        *extra,
    ]
    rows, trace = [], []
    with subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        for line in process.stdout:
            trace.append(line)
            if not line.startswith("{"):
                continue
            value = json.loads(line)
            if value.get("checked"):
                rows[-1].update(value)
                continue
            current = lab.authority_logs()
            witnesses = events(previous, current, ADDRESSES[role])
            value.update(
                role=role,
                scenario=scenario,
                authority_requests=request_delta(previous, current, ADDRESSES[role]),
                mode=record["active_mode"],
                events=witnesses,
                log_checkpoints=dict(
                    before=checkpoint(previous), after=checkpoint(current)
                ),
            )
            rows.append(value)
            record["observations"].append(value)
            previous = current
            process.stdin.write(json.dumps(dict(events=witnesses)) + "\n")
            process.stdin.flush()
        code = process.wait()
    record["raw_commands"].append(
        dict(argv=argv, exit_code=code, output="".join(trace))
    )
    assert code == 0, "".join(trace)
    return rows


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--modes", nargs="+", choices=("nsec", "nsec3"), default=["nsec", "nsec3"]
    )
    parser.add_argument(
        "--roles",
        nargs="+",
        choices=("donna", "knot-resolver", "hickory"),
        default=["donna", "knot-resolver", "hickory"],
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=("descendant", "sibling", "guards", "expiry"),
        default=["descendant", "sibling", "guards", "expiry"],
    )
    parser.add_argument(
        "--donna-image",
        default=CLI_IMAGE,
    )
    parser.add_argument("--donna-source-manifest", type=Path, required=True)
    parser.add_argument("--donna-source-archive", type=Path, required=True)
    parser.add_argument("--cache-capacity", type=int)
    parser.add_argument("--public-discovery", type=Path)
    parser.add_argument("--baseline-report", type=Path, required=True)
    args = parser.parse_args()
    client, donna = (
        identity("donna-interop-recursive-client:v2"),
        identity(args.donna_image),
    )
    require_cli(donna)
    peers = {
        "knot-resolver": identity(KNOT_IMAGE),
        "hickory": identity(HICKORY_IMAGE),
        "authority": identity("donna-interop-bind"),
    }
    record = dict(
        scope="Untimed signed negative-cache discovery; no performance or blanket RFC-conformance claim",
        images=dict(client=client, donna=donna, **peers),
        roles=args.roles,
        modes=args.modes,
        scenarios=args.scenarios,
        observations=[],
        harness_sha256=harness_hashes(SUITE, FILES),
        raw_commands=[],
        authority_logs={},
        public={},
        complete=False,
    )
    control = json.loads(args.baseline_report.read_text())
    for key in (
        "native_binary_sha256",
        "client_build_bases",
    ):
        record[key] = control[key]
    raw = args.donna_source_manifest.read_bytes()
    record.update(
        donna_source_manifest=json.loads(raw),
        donna_source_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        donna_source_archive=dict(
            path=str(args.donna_source_archive),
            sha256=hashlib.sha256(args.donna_source_archive.read_bytes()).hexdigest(),
        ),
        baseline_reference=dict(
            image=control["images"]["donna"],
            report_sha256=hashlib.sha256(args.baseline_report.read_bytes()).hexdigest(),
        ),
    )
    record["donna_cache_capacity"] = args.cache_capacity
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prefix = args.output.parent / "binaries" / args.output.stem
    prefix.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="donna-negative-discovery-") as temporary:
        evidence = Path(temporary) / "evidence"
        evidence.mkdir()
        for name in FILES:
            target = evidence / "harness" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((SUITE / name).read_bytes())
        try:
            for mode in args.modes:
                record["active_mode"] = mode
                lab = Lab(
                    Path(temporary) / mode,
                    client,
                    donna,
                    peers,
                    denial=mode,
                    negative_ttl=5,
                    cache_capacity=args.cache_capacity,
                )
                try:
                    reused = (
                        json.loads(args.public_discovery.read_text())["public"][mode]
                        if args.public_discovery
                        else None
                    )
                    public = lab.prepare(additions(), reused)
                    child_zone(lab, public)
                    record["public"][mode] = public
                    for name in MODULES:
                        docker(
                            "cp",
                            str(SUITE / "python" / name),
                            CLIENT + ":/suite/" + name,
                        )
                    for role in args.roles:
                        for scenario in args.scenarios:
                            lab.start(role)
                            stream(lab, role, scenario, record)
                            lab.stop()
                    record["authority_logs"][mode] = lab.authority_logs()
                finally:
                    if mode not in record["authority_logs"]:
                        try:
                            record["authority_logs"][mode] = lab.authority_logs()
                        except Exception:
                            pass
                    lab.cleanup()
            record["complete"] = True
        finally:
            raw = Path(str(prefix) + "-commands.json.gz")
            raw.write_bytes(
                gzip.compress(json.dumps(record.pop("raw_commands")).encode(), mtime=0)
            )
            record["raw_commands_artifact"] = str(raw)
            write_record(evidence / "result.json", record, sequence_key="trials")
            archive = Path(str(prefix) + "-public.tar.gz")
            with tarfile.open(archive, "w:gz") as out:
                for path in evidence.iterdir():
                    out.add(path, arcname=path.name)
            record["public_archive"] = dict(
                path=str(archive),
                sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            record["cleanup"] = (
                "All task containers/network/private+public volumes removed; no signing keys exported."
            )
            write_record(args.output, record, sequence_key="trials")


if __name__ == "__main__":
    main()
