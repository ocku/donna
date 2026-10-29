#!/usr/bin/env python3
"""Signed negative-cache workload with distinct exact, descendant and sibling phases."""

import argparse
import gzip
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from negative_fixture import additions
from support.capture_trials import CaptureTrials
from support.daemon import CLI_IMAGE, require_cli
from support.docker import docker
from support.evidence import write_record
from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes, harness_sources
from support.recursive_lab import (
    ADDRESSES,
    CARRIER,
    CLIENT,
    PREFIX,
    Lab,
    identity,
)
from support.recursive_peers import HICKORY_IMAGE, KNOT_IMAGE

from benchmarks.negative_discovery import FILES, MODULES, child_zone, stream

EXTRA = [
    "benchmarks/negative_compare.py",
    "python/negative_discovery_replay.py",
    "python/negative_replay.py",
    "python/recursive_replay.py",
    "python/capture_budget_test.py",
    "python/clock_snapshot_test.c",
    "python/clock_capture_test.py",
    "python/batched_capture_test.py",
    "python/batched_load_test.py",
]


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--donna-image", default=CLI_IMAGE)
    parser.add_argument("--donna-source-manifest", type=Path, required=True)
    parser.add_argument("--donna-source-archive", type=Path, required=True)
    parser.add_argument(
        "--roles", nargs="+", choices=tuple(ADDRESSES), default=list(ADDRESSES)
    )
    parser.add_argument("--skip-warm", nargs="*", choices=tuple(ADDRESSES), default=[])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=1)
    parser.add_argument("--gates-only", action="store_true")
    parser.add_argument("--cache-capacity", type=int)
    parser.add_argument(
        "--client-image", default="donna-interop-recursive-client:budget-v4"
    )
    parser.add_argument("--capture-budget-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument(
        "--warm-only",
        action="store_true",
        help="Only matched cyclic exact phases; finite diagnostics retained separately",
    )
    parser.add_argument(
        "--functional-scenarios",
        nargs="*",
        choices=("descendant", "sibling", "guards", "expiry"),
        default=["descendant", "sibling", "guards", "expiry"],
    )
    parser.add_argument("--baseline-report", type=Path, required=True)
    parser.add_argument("--discovery-report", type=Path, required=True)
    args = parser.parse_args()
    assert 1 <= args.capture_budget_bytes <= 512 * 1024 * 1024
    if args.warm_only:
        assert not args.gates_only and not args.skip_warm
        args.functional_scenarios = []
    assert 1 <= args.repeats <= 5 and 1 <= args.seconds <= 2
    assert len(set(args.roles)) == len(args.roles) and set(args.skip_warm) <= set(
        args.roles
    )
    assert args.cache_capacity is None or args.cache_capacity >= 0
    assert (
        args.warm_only or args.gates_only or "descendant" in args.functional_scenarios
    )
    client, donna = identity(args.client_image), identity(args.donna_image)
    require_cli(donna)
    peers = {
        "knot-resolver": identity(KNOT_IMAGE),
        "hickory": identity(HICKORY_IMAGE),
        "authority": identity("donna-interop-bind"),
    }
    old = json.loads(args.baseline_report.read_text())
    manifest_raw = args.donna_source_manifest.read_bytes()
    manifest = json.loads(manifest_raw)
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    archive = dict(
        path=str(args.donna_source_archive),
        sha256=hashlib.sha256(args.donna_source_archive.read_bytes()).hexdigest(),
    )
    files = FILES + EXTRA
    files = harness_sources(SUITE, files)
    modules = MODULES + [
        "negative_discovery_replay.py",
        "negative_replay.py",
        "recursive_replay.py",
    ]
    record = dict(
        scope="Signed NSEC recursion: exact NXDOMAIN cyclic throughput, fresh descendant and proof-covered sibling finite diagnostics; no full RFC8198 claim",
        images=dict(donna=donna, client=client, **peers),
        roles=args.roles,
        modes=["nsec"],
        active_mode="nsec",
        scenarios=args.functional_scenarios,
        skip_warm=args.skip_warm,
        repeats=args.repeats,
        seconds=args.seconds,
        gates_only=args.gates_only,
        warm_only=args.warm_only,
        capture_budget_bytes=args.capture_budget_bytes,
        donna_cache_capacity=args.cache_capacity,
        donna_source_manifest=manifest,
        donna_source_manifest_sha256=manifest_sha,
        donna_source_archive=archive,
        baseline_reference=dict(
            image=old["images"]["donna"],
            report_sha256=hashlib.sha256(args.baseline_report.read_bytes()).hexdigest(),
        ),
        client_build_bases=dict(
            old["client_build_bases"], legacy_capture=old["images"]["client"]
        ),
        legacy_native_reference=dict(
            image=old["images"]["client"],
            binary_sha256=old["native_binary_sha256"],
            clock_method="unbracketed endpoints/last receive elapsed; historical bytes unchanged",
        ),
        harness_sha256=harness_hashes(SUITE, files),
        observations=[],
        trials=[],
        raw_commands=[],
        public={},
        authority_logs={},
        complete=False,
        resources={
            "resolver": "one worker/1 CPU/256 MiB",
            "timed_client": ".5 CPU/512 MiB"
            if args.capture_budget_bytes > 128 * 1024 * 1024
            else ".5 CPU/256 MiB",
            "each_authority": "one worker/.15 CPU/128 MiB",
            "public_carrier": ".02 CPU/64 MiB",
            "offline_replay": "1 CPU after native phases and resolver shutdown",
            "cache_defaults": "Donna4096entries/cache;Kres64MiB;Hickory65536entries;explicit zero override recorded separately",
            "authority_log_timezone": "UTC; TZ=UTC",
            "scope": "2-CPU VM context; unrelated services preserved",
        },
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prefix = args.output.parent / "binaries" / args.output.stem
    prefix.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="donna-negative-comparison-") as temporary:
        evidence = Path(temporary) / "evidence"
        evidence.mkdir()
        lab = Lab(
            Path(temporary) / "lab",
            client,
            donna,
            peers,
            cache_capacity=args.cache_capacity,
            negative_ttl=5,
            client_memory="512m"
            if args.capture_budget_bytes > 128 * 1024 * 1024
            else "256m",
        )

        capture = CaptureTrials(args, lab, record, evidence, negative=True)
        command, worker, phase = capture.command, capture.worker, capture.phase

        try:
            original = json.loads(args.discovery_report.read_text())["public"]["nsec"]
            public = lab.prepare(additions(), original)
            child_zone(lab, public)
            record["public"]["nsec"] = public
            (evidence / "source-manifest.json").write_bytes(manifest_raw)
            for name in files:
                target = evidence / "harness" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((SUITE / name).read_bytes())
            for name in modules:
                docker("cp", str(SUITE / "python" / name), CLIENT + ":/suite/" + name)
            worker("inputs")
            record["native_binary_sha256"] = docker(
                "exec", CLIENT, "sha256sum", "/usr/local/bin/batched_load", capture=True
            ).split()[0]
            record["clock_method"] = (
                "Protocol2: bounded monotonic/realtime brackets; end snapshot includes final processing; CPU sampling encloses both pairs; writes follow end. Per-reply uncertainty includes50ms endpoint budget; undetected out-and-back clock excursions remain a model limit."
            )
            for role in args.roles:
                for scenario in record["scenarios"]:
                    lab.start(role)
                    stream(lab, role, scenario, record)
                    lab.stop()
            # Construct and independently reject one deliberately bad NSEC signature.
            remote = "/suite/bad-leaf.db"
            bad_info = worker("makebad", extra=("--path", remote))
            bad_path = evidence / "bad-leaf.db"
            docker("cp", CLIENT + ":" + remote, str(bad_path))
            public["bad_leaf"] = bad_path.read_text()
            public["bad_signature"] = bad_info
            lab.put("leaf/bad-signature.db", public["bad_leaf"], public=True)
            lab.put("leaf/good.db", public["zones"]["leaf"], public=True)
            lab.put("public.json", json.dumps(public), public=True)
            for reason in () if args.warm_only else ("bad-ds", "bad-signature"):
                if reason == "bad-ds":
                    lab.set_bad_ds(True)
                else:
                    lab.run(
                        "exec",
                        CARRIER,
                        "cp",
                        "/work/leaf/bad-signature.db",
                        "/work/leaf/active.db",
                    )
                    lab.run("restart", PREFIX + "leaf")
                for role in args.roles:
                    for cd_first in (False, True):
                        lab.start(role)
                        extra = ["--security", reason] + (
                            ["--cd-first"] if cd_first else []
                        )
                        stream(lab, role, "security", record, extra=extra)
                        lab.stop()
                if reason == "bad-ds":
                    lab.set_bad_ds(False)
                else:
                    lab.run(
                        "exec",
                        CARRIER,
                        "cp",
                        "/work/leaf/good.db",
                        "/work/leaf/active.db",
                    )
                    lab.run("restart", PREFIX + "leaf")
            if not args.gates_only:
                flags = (
                    {
                        role: next(
                            row["verification"]["flags"]
                            for row in record["observations"]
                            if row["role"] == role
                            and row["scenario"] == "descendant"
                            and row["step"] == 0
                            and row["passed"]
                        )
                        for role in args.roles
                    }
                    if not args.warm_only
                    else {}
                )
                for role in [] if args.warm_only else args.roles:
                    before_logs = lab.authority_logs()
                    lab.start(role)
                    phase(role, "cold", 0, "exact", flags[role], cold_logs=before_logs)
                    lab.stop()
                for role in [] if args.warm_only else args.roles:
                    for kind in ("descendant", "sibling"):
                        lab.start(role)
                        state = "/suite/preload-" + role + "-" + kind + ".json"
                        pre_logs = lab.authority_logs()
                        pre = worker("preload", role, ("--kind", kind, "--path", state))
                        phase(
                            role,
                            "fresh",
                            0,
                            kind,
                            pre["flags"],
                            preload=state,
                            preload_logs=pre_logs,
                        )
                        lab.stop()
                for repeat in range(args.repeats):
                    shift = repeat % len(args.roles)
                    order = args.roles[shift:] + args.roles[:shift]
                    for role in order:
                        if role in args.skip_warm:
                            continue
                        lab.start(role)
                        state = f"/suite/preload-{role}-{repeat}.json"
                        pre_logs = lab.authority_logs()
                        pre = worker(
                            "preload", role, ("--kind", "exact", "--path", state)
                        )
                        phase(
                            role,
                            "warm",
                            repeat,
                            "exact",
                            pre["flags"],
                            preload=state,
                            preload_logs=pre_logs,
                        )
                        lab.stop()
            record["authority_logs"]["nsec"] = lab.authority_logs()
            record["peer_configurations"] = {
                role: {
                    p.name: p.read_text()
                    for p in (lab.directory / role).glob("*")
                    if p.is_file()
                }
                for role in args.roles
                if role != "donna"
            }
            record["fixture_commands"] = list(lab.commands)
            record["complete"] = True
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
                "1",
                "--memory",
                "256m",
                "--entrypoint",
                "sleep",
                client,
                "infinity",
                capture=True,
            )
            try:
                for name in modules:
                    docker(
                        "cp", str(SUITE / "python" / name), offline + ":/suite/" + name
                    )
                docker("cp", str(evidence) + "/.", offline + ":/evidence")
                record["offline_replay"] = command(
                    [
                        "docker",
                        "exec",
                        offline,
                        "python",
                        "/suite/negative_replay.py",
                        "/evidence",
                    ]
                )
            finally:
                docker("rm", "-fv", offline, check=False, capture=True)
        except Exception as error:
            record["complete"] = False
            record["error"] = repr(error)
            raise
        finally:
            if "nsec" not in record["authority_logs"]:
                try:
                    record["authority_logs"]["nsec"] = lab.authority_logs()
                except Exception:
                    pass
            lab.cleanup()
            raw = Path(str(prefix) + "-commands.json.gz")
            raw.write_bytes(
                gzip.compress(json.dumps(record.pop("raw_commands")).encode(), mtime=0)
            )
            record["raw_commands_artifact"] = str(raw)
            record["cleanup"] = (
                "All task containers/network/public+private volumes removed; no private keys exported."
            )
            write_record(evidence / "result.json", record, sequence_key="trials")
            target = Path(
                str(prefix)
                + ("-public.tar.gz" if record["complete"] else "-failed-public.tar.gz")
            )
            with tarfile.open(target, "w:gz") as out:
                for path in evidence.iterdir():
                    out.add(path, arcname=path.name)
            record["public_archive"] = dict(
                path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest()
            )
            write_record(args.output, record, sequence_key="trials")


if __name__ == "__main__":
    main()
