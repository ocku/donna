#!/usr/bin/env python3
"""Bounded signed iterative-resolver comparison with complete native packet evidence."""

import argparse
import gzip
import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

from support.capture_trials import (
    CaptureTrials,
    checkpoint,
    request_delta,
)
from support.daemon import CLI_IMAGE, require_cli, resolver_port
from support.docker import docker
from support.evidence import write_record
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes, harness_sources
from support.recursive_lab import (
    ADDRESSES,
    CLIENT,
    ORIGINS,
    PREFIX,
    Lab,
    delta,
    identity,
    stats,
)
from support.recursive_peers import HICKORY_IMAGE, KNOT_IMAGE


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donna-image", default=CLI_IMAGE)
    parser.add_argument("--donna-source-manifest", type=Path, required=True)
    parser.add_argument("--donna-source-archive", type=Path, required=True)
    parser.add_argument(
        "--roles",
        nargs="+",
        choices=("donna", "knot-resolver", "hickory"),
        default=["donna", "knot-resolver", "hickory"],
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=1)
    parser.add_argument("--gates-only", action="store_true")
    parser.add_argument(
        "--cache-capacity",
        type=int,
        help="candidate example only; omit for immutable baseline default",
    )
    parser.add_argument(
        "--offline-cpus",
        type=float,
        default=1,
        help="post-measurement replay quota; timed client stays at 0.5 CPU",
    )
    parser.add_argument(
        "--public-fixture",
        type=Path,
        help="reuse retained public signed zones/anchor; no signing keys required",
    )
    args = parser.parse_args()
    assert 1 <= args.repeats <= 5 and 1 <= args.seconds <= 3
    assert len(args.roles) == len(set(args.roles))
    assert args.cache_capacity is None or args.cache_capacity >= 0
    assert 0.5 <= args.offline_cpus <= 1
    suite = SUITE
    sysfiles = [
        "benchmarks/recursive_compare.py",
        "support/recursive_lab.py",
        "support/capture_trials.py",
        "support/recursive_peers.py",
        "support/__init__.py",
        "support/lock.py",
        "support/docker.py",
        "support/paths.py",
        "support/topology.py",
        "support/evidence.py",
        "labs/full.py",
        "python/batched_load.c",
        "docker/RecursiveClient.Dockerfile",
    ]
    modules = [
        "recursive_fixture.py",
        "recursive_capture.py",
        "recursive_evidence.py",
        "recursive_worker.py",
        "recursive_replay.py",
        "recursive_refresh.py",
    ]
    files = sysfiles + ["python/" + name for name in modules]
    files = harness_sources(suite, files)
    client = identity("donna-interop-recursive-client:v2")
    donna = identity(args.donna_image)
    require_cli(donna)
    peers = {
        "knot-resolver": identity(KNOT_IMAGE),
        "hickory": identity(HICKORY_IMAGE),
        "authority": identity("donna-interop-bind"),
    }
    source_archive = args.donna_source_archive
    record = dict(
        scope="One signed NSEC private root/test/example.test chain; recursive UDP; cold diagnostic, prepared distinct DNAME targets and cyclic diverse owners; no authoritative Knot DNS comparison",
        images=dict(donna=donna, client=client, **peers),
        client_build_bases={
            name: identity(name)
            for name in ("rust:bookworm", "donna-interop-authority-client-body:local")
        },
        donna_source_archive=dict(
            path=str(source_archive),
            sha256=hashlib.sha256(source_archive.read_bytes()).hexdigest(),
        ),
        donna_source_manifest=json.loads(args.donna_source_manifest.read_text()),
        donna_source_manifest_sha256=hashlib.sha256(
            args.donna_source_manifest.read_bytes()
        ).hexdigest(),
        harness_sha256=harness_hashes(suite, files),
        resources={
            "resolver": "1worker/1CPU/256MiB",
            "client": "0.5CPU/256MiB",
            "each_authority": "1worker/0.15CPU/128MiB",
            "public_carrier": "0.02CPU/64MiB",
            "signer": "0.5CPU/256MiB; stopped before service measurements",
            "authority_log_timezone": "UTC, explicitly configured with TZ=UTC",
            "offline_verification": f"{args.offline_cpus}CPU/256MiB, after all native measurements and resolver shutdown",
            "cache": "Donna4096entries/cache; Knot Resolver64MiB; Hickory65536response entries (no byte-cap API)",
            "scope": "Configured active aggregate1.97CPU/960MiB; shared VM and unrelated containers retained",
        },
        repeats=args.repeats,
        seconds=args.seconds,
        roles=args.roles,
        donna_cache_capacity=args.cache_capacity,
        gates_only=args.gates_only,
        capabilities=[],
        security=[],
        coherence=[],
        expiry=[],
        trials=[],
        raw_commands=[],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prefix = args.output.parent / ("binaries/" + args.output.stem)
    with tempfile.TemporaryDirectory(prefix="donna-recursive-evidence-") as temporary:
        root = Path(temporary)
        lab = Lab(
            root / "lab", client, donna, peers, cache_capacity=args.cache_capacity
        )
        evidence = root / "evidence"
        evidence.mkdir()

        capture = CaptureTrials(args, lab, record, evidence)
        command, worker, phase = capture.command, capture.worker, capture.phase

        try:
            import sys

            sys.path.insert(0, str(suite / "python"))
            from recursive_fixture import additions

            public = lab.prepare(
                additions(),
                json.loads(args.public_fixture.read_text())
                if args.public_fixture
                else None,
            )
            (evidence / "public.json").write_text(json.dumps(public))
            (evidence / "source-manifest.json").write_bytes(
                args.donna_source_manifest.read_bytes()
            )
            for name in files:
                target = evidence / "harness" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((suite / name).read_bytes())
            for module in modules:
                docker(
                    "cp", str(suite / "python" / module), CLIENT + ":/suite/" + module
                )
            worker("inputs")
            record["native_binary_sha256"] = docker(
                "exec", CLIENT, "sha256sum", "/usr/local/bin/batched_load", capture=True
            ).split()[0]
            roles = args.roles
            for role in roles:
                lab.start(role)
                capability = worker("capability", role)
                record["capabilities"].append(dict(role=role, **capability))
                lab.stop()
            direct_ok = {
                row["role"]: all(
                    item["passed"]
                    for item in row["capabilities"]
                    if item["kind"] == "direct"
                )
                for row in record["capabilities"]
            }
            dname_ok = {
                row["role"]: all(
                    item["passed"]
                    for item in row["capabilities"]
                    if item["kind"] == "dname"
                )
                for row in record["capabilities"]
            }
            assert all(direct_ok.values()), record["capabilities"]
            common = "direct"  # Same 256 A/AAAA questions for every variant/peer.
            record["common_workload"] = common
            record["limitations"] = {
                "signed_dname_eligible": dname_ok,
                "timing": "One-second finite-duration cyclic captures; rates may be client/quota-limited. Cold256/512first-pass figures are diagnostic, not steady-state rates.",
                "ttl": "All wire TTLs/time bounds checked per reply; only signature math deduplicated by exact RRset/signature/authenticated keys.",
            }
            for role in roles:
                lab.start(role)
                before = lab.authority_logs()
                row = worker("coherence", role)
                after = lab.authority_logs()
                record["coherence"].append(
                    dict(
                        role=role,
                        **row,
                        log_checkpoints=dict(
                            before=checkpoint(before), after=checkpoint(after)
                        ),
                        authority_requests=request_delta(
                            before, after, ADDRESSES[role]
                        ),
                    )
                )
                lab.stop()
            lab.set_bad_ds(True)
            for role in roles:
                for cd_first in (False, True):
                    lab.start(role)
                    before = lab.authority_logs()
                    result = worker(
                        "security", role, ("--cd-first",) if cd_first else ()
                    )
                    after = lab.authority_logs()
                    record["security"].append(
                        dict(
                            role=role,
                            **result,
                            log_checkpoints=dict(
                                before=checkpoint(before), after=checkpoint(after)
                            ),
                            authority_requests=request_delta(
                                before, after, ADDRESSES[role]
                            ),
                        )
                    )
                    lab.stop()
            lab.set_bad_ds(False)
            for role in roles:
                lab.start(role)
                previous = lab.authority_logs()
                invocation = [
                    "docker",
                    "exec",
                    "-i",
                    CLIENT,
                    "python",
                    "/suite/recursive_worker.py",
                    "expiry",
                    "--host",
                    ADDRESSES[role],
                    "--port",
                    str(resolver_port(role)),
                    "--kind",
                    "all" if dname_ok[role] else "direct",
                ]
                with subprocess.Popen(
                    invocation,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                ) as process:
                    trace = []
                    for line in process.stdout:
                        trace.append(line)
                        if not line.startswith("{"):
                            continue
                        row = json.loads(line)
                        current = lab.authority_logs()
                        row.update(
                            role=role,
                            authority_requests=request_delta(
                                previous, current, ADDRESSES[role]
                            ),
                            log_checkpoints=dict(
                                before=checkpoint(previous), after=checkpoint(current)
                            ),
                        )
                        previous = current
                        row["request_total"] = sum(row["authority_requests"].values())
                        if row["expiry_phase"] == "expired":
                            assert row["authority_requests"], row
                        record["expiry"].append(row)
                        process.stdin.write("continue\n")
                        process.stdin.flush()
                    assert process.wait() == 0, "".join(trace)
                lab.stop()
            if not args.gates_only:
                for role in roles:
                    logs_before = lab.authority_logs()
                    authority_before = {zone: stats(PREFIX + zone) for zone in ORIGINS}
                    lab.start(role)
                    flags = next(
                        item["flags"]
                        for row in record["capabilities"]
                        if row["role"] == role
                        for item in row["capabilities"]
                        if item["passed"] and item["kind"] == "direct"
                    )
                    item = phase(role, "cold", 0, common, flags, cold_logs=logs_before)
                    item["authority_cpu_including_startup"] = {
                        zone: delta(authority_before[zone], item["cpu_after"][zone])
                        for zone in ORIGINS
                    }
                    item["cold_total_server_usage_usec"] = item[
                        "resolver_total_usage_since_creation_usec"
                    ] + sum(
                        row["usage_usec"]
                        for row in item["authority_cpu_including_startup"].values()
                    )
                    lab.stop()
                for trial in range(args.repeats):
                    shift = trial % len(roles)
                    order = roles[shift:] + roles[:shift]
                    for role in order:
                        lab.start(role)
                        state = "/suite/preload-" + role + "-" + str(trial) + ".json"
                        prepared = worker(
                            "preload",
                            role,
                            (
                                "--kind",
                                "all" if dname_ok[role] else "direct",
                                "--path",
                                state,
                            ),
                        )
                        if dname_ok[role]:
                            phase(
                                role,
                                "prepared",
                                trial,
                                "dname",
                                prepared["flags"],
                                preload=state,
                            )
                        phase(
                            role,
                            "warm",
                            trial,
                            common,
                            prepared["flags"],
                            preload=state,
                        )
                        lab.stop()
            record["authority_logs"] = lab.authority_logs()
            record["peer_configurations"] = {
                role: {
                    p.name: p.read_text()
                    for p in (root / "lab" / role).glob("*")
                    if p.is_file()
                }
                for role in roles
                if role in ("knot-resolver", "hickory")
            }
            record["complete"] = True
            # Public evidence contains no signing-key files. Its signed zones
            # and all captured packets replay at their recorded wall times.
            write_record(evidence / "result.json", record, sequence_key="trials")
            offline = PREFIX + "offline"
            docker(
                "run",
                "-d",
                "--name",
                offline,
                "--network",
                "none",
                "--cpus",
                str(args.offline_cpus),
                "--memory",
                "256m",
                "--entrypoint",
                "sleep",
                client,
                "infinity",
                capture=True,
            )
            try:
                for module in modules:
                    docker(
                        "cp",
                        str(suite / "python" / module),
                        offline + ":/suite/" + module,
                    )
                docker("cp", str(evidence) + "/.", offline + ":/evidence")
                record["offline_replay"] = command(
                    [
                        "docker",
                        "exec",
                        offline,
                        "python",
                        "/suite/recursive_replay.py",
                        "/evidence",
                    ]
                )
            finally:
                docker("rm", "-fv", offline, check=False, capture=True)
            prefix.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(str(prefix) + "-public.tar.gz", "w:gz") as archive:
                for path in evidence.iterdir():
                    archive.add(path, arcname=path.name)
            record["public_archive"] = dict(
                path=str(prefix) + "-public.tar.gz",
                sha256=hashlib.sha256(
                    Path(str(prefix) + "-public.tar.gz").read_bytes()
                ).hexdigest(),
            )
        except Exception as error:
            record["complete"] = False
            record["error"] = repr(error)
            raise
        finally:
            record["fixture_commands"] = lab.commands
            if "authority_logs" not in record:
                try:
                    record["authority_logs"] = lab.authority_logs()
                except Exception as log_error:
                    record["logs_collection_error"] = repr(log_error)
            if not record.get("complete") and any(evidence.iterdir()):
                failed = Path(str(prefix) + "-failed-public.tar.gz")
                failed.parent.mkdir(parents=True, exist_ok=True)
                with tarfile.open(failed, "w:gz") as archive:
                    for path in evidence.iterdir():
                        archive.add(path, arcname=path.name)
                record["failed_public_archive"] = str(failed)
            lab.cleanup()
            record["cleanup"] = (
                "All task containers/network/public+private volumes removed; signing keys were never exported; shared images retained."
            )
            raw = Path(str(prefix) + "-commands.json.gz")
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_bytes(
                gzip.compress(json.dumps(record["raw_commands"]).encode(), mtime=0)
            )
            record["raw_commands_artifact"] = str(raw)
            del record["raw_commands"]
            write_record(args.output, record, sequence_key="trials")


if __name__ == "__main__":
    main()
