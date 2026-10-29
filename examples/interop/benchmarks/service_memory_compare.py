#!/usr/bin/env python3
"""Matched unsigned service RSS/PSS/cgroup snapshots, not a throughput benchmark."""

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from support.lock import exclusive_laboratory
from support.paths import SUITE
from support.provenance import harness_hashes, harness_sources

sys.path.insert(0, str(SUITE / "python"))
from service_memory_fixture import fixture

DONNA = "sha256:b73ea4646e67aa6c72ed784393b014f2a9efed04010e52b720151254f6971759"
KNOT = "sha256:174b0fcb24c6c3bc5065c9d1ce46b588eec607a5f32bc40ff0cda60150f00bd9"
HICKORY = "sha256:b40d16e1b92fac9a6819497293fe17c074e097e42e6eef246e3a8c90b0afdce7"
CLIENT = "sha256:1039033546695b2bb66145d10ce5c516d765f579a99dc377261a056293913523"
OBSERVER = "sha256:ab586d5831c862ff58df75d5e7e4db44bf38dda35ca602bd952b07605f21c917"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def summary(rows):
    output = {}
    for role in ("donna", "knot", "hickory"):
        output[role] = {}
        for phase in ("idle", "warm"):
            samples = [s for row in rows if row["role"] == role for s in row[phase]]
            metrics = {
                key: [s["process_totals"][key] for s in samples]
                for key in samples[0]["process_totals"]
            }
            metrics.update(
                cgroup_current_bytes=[
                    s["cgroup_after"]["current_bytes"] for s in samples
                ],
                cgroup_lifetime_peak_bytes=[
                    s["cgroup_after"]["lifetime_peak_bytes"] for s in samples
                ],
            )
            output[role][phase] = {
                key: dict(median=statistics.median(v), minimum=min(v), maximum=max(v))
                for key, v in metrics.items()
            }
    return output


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-report", type=Path, required=True)
    args = parser.parse_args()
    prefix = "donna-memory-" + uuid.uuid4().hex[:8]
    network, volume, client, target = (
        prefix + "-" + item for item in ("net", "zone", "client", "server")
    )
    result_path = SUITE / ".artifacts/service-memory.json"
    record = dict(
        schema=1,
        complete=False,
        profile="Unsigned 4096 explicit owners x A/AAAA/TXT; 768-query pool",
        repetitions=3,
        samples_per_phase=3,
        warm_passes=40,
        warm_replies_per_process=30720,
        images=dict(
            donna=DONNA, knot=KNOT, hickory=HICKORY, client=CLIENT, observer=OBSERVER
        ),
        resources=dict(
            service_cpu=1,
            service_memory="256m",
            client_cpu=0.5,
            client_memory="256m",
            observer_cpu=0.2,
            observer_memory="64m",
        ),
        workers="Donna/Hickory one Tokio worker; Knot one UDP, one TCP, one background worker; raw process thread counts retained.",
        limitations=[
            "Process RSS/PSS and cgroup charge are different accounting views.",
            "Fresh processes are not cold OS page cache; no page cache drop.",
            "Observer separate cgroup excludes its direct charge, but shared-library PSS attribution can vary.",
            "Snapshots are intervals, not atomic. Lifetime peak includes startup and warm traffic.",
            "Three process replicates, one small unsigned dataset; no general memory scaling or service QPS claim.",
        ],
        rows=[],
        references={},
        commands=[],
    )
    source_files = [
        "benchmarks/service_memory_compare.py",
        "python/service_memory.py",
        "python/service_memory_fixture.py",
        "python/service_memory_client.py",
        "python/service_memory_test.py",
        "src/bin/memory_authority.rs",
        "support/__init__.py",
        "support/lock.py",
        "support/docker.py",
        "support/paths.py",
        "support/topology.py",
        "support/evidence.py",
    ]
    source_files = harness_sources(SUITE, source_files)

    def run(*args, input=None, check=True):
        proc = subprocess.run(
            ["docker", *map(str, args)], input=input, capture_output=True, text=True
        )
        record["commands"].append(
            dict(
                argv=["docker", *map(str, args)],
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        )
        if check and proc.returncode:
            raise RuntimeError(proc.stderr or proc.stdout)
        return proc.stdout

    def execute(*args):
        return json.loads(
            run("exec", client, "python", "/suite/service_memory_client.py", *args)
        )

    def logs():
        return run("logs", target) + record["commands"][-1]["stderr"]

    def start(role):
        run("rm", "-fv", target, check=False)
        args = [
            "run",
            "-d",
            "--name",
            target,
            "--network",
            network,
            "--ip",
            "172.29.57.10",
            "--cpus",
            "1",
            "--memory",
            "256m",
            "-v",
            volume + ":/work:ro",
        ]
        if role == "donna":
            args += ["-e", "LISTEN_ADDR=172.29.57.10:53", DONNA]
        elif role == "knot":
            args += [KNOT, "knotd", "-c", "/work/knot.conf"]
        else:
            args += [
                "-e",
                "RUST_LOG=error",
                HICKORY,
                "hickory-dns",
                "--config",
                "/work/hickory.toml",
                "--workers",
                "1",
                "--port",
                "53",
            ]
        run(*args)
        deadline = time.monotonic() + 15
        while True:
            try:
                execute("ready")
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    run("logs", target, check=False)
                    run("inspect", target, check=False)
                    raise
                time.sleep(0.2)
        time.sleep(0.5)
        return json.loads(run("inspect", target))[0]

    def sample():
        value = json.loads(
            run(
                "run",
                "--rm",
                "-i",
                "--network",
                "none",
                "--pid=container:" + target,
                "--cgroupns=host",
                "--cap-add=SYS_PTRACE",
                "--read-only",
                "--cpus",
                ".2",
                "--memory",
                "64m",
                "--entrypoint",
                "python",
                OBSERVER,
                "-",
                "--root-pid",
                "1",
                "--role",
                "memory_authority=authority",
                "--role",
                "knotd=authority",
                "--role",
                "hickory-dns=authority",
                input=(SUITE / "python/service_memory.py").read_text(),
            )
        )
        assert value["observer"]["charged_to_service"] is False
        for edge in ("cgroup_before", "cgroup_after"):
            assert (
                value[edge]["events"].get("oom", 0)
                == value[edge]["events"].get("oom_kill", 0)
                == 0
            )
        return value

    with tempfile.TemporaryDirectory(prefix="donna-memory-evidence-") as temporary:
        root = Path(temporary)
        try:
            zone, pool, cases = fixture()
            for name, data in [("zone.db", zone), ("queries.framed", pool)]:
                (root / name).write_bytes(data)
            (root / "cases.json").write_text(json.dumps(cases))
            (root / "knot.conf").write_text(
                "server:\n    rundir: /tmp\n    listen: 0.0.0.0@53\n    udp-workers: 1\n    tcp-workers: 1\n    background-workers: 1\n    udp-max-payload: 1232\nlog:\n  - target: stderr\n    any: error\ndatabase:\n    storage: /tmp/knot-db\ntemplate:\n  - id: default\n    storage: /tmp\n    zonefile-sync: -1\nzone:\n  - domain: example.test.\n    file: /work/zone.db\n    dnssec-signing: off\n"
            )
            (root / "hickory.toml").write_text(
                'listen_addrs_ipv4 = ["0.0.0.0"]\nlisten_addrs_ipv6 = []\nlisten_port = 53\ndirectory = "/work"\ndrop_privileges = false\n[[zones]]\nzone = "example.test."\nzone_type = "Primary"\nfile = "zone.db"\naxfr_policy = "AllowAll"\n'
            )
            record["fixture"] = dict(
                zone_sha256=sha(zone),
                query_pool_sha256=sha(pool),
                owners=4096,
                data_rrsets=12288,
                query_population=768,
            )
            record["build"] = json.loads(args.build_report.read_text())
            run("network", "create", "--subnet", "172.29.57.0/24", network)
            run("volume", "create", volume)
            run(
                "run",
                "-d",
                "--name",
                client,
                "--network",
                network,
                "--cpus",
                ".5",
                "--memory",
                "256m",
                "-v",
                volume + ":/work",
                "--entrypoint",
                "sleep",
                CLIENT,
                "infinity",
            )
            for name in ("zone.db", "knot.conf", "hickory.toml"):
                run("cp", root / name, client + ":/work/" + name)
            for name in ("service_memory_fixture.py", "service_memory_client.py"):
                run("cp", SUITE / "python" / name, client + ":/suite/" + name)
            run("cp", client + ":/usr/local/bin/batched_load", root / "batched_load")
            record["native_binary_sha256"] = sha((root / "batched_load").read_bytes())
            # References are captured before measured processes exist.
            for role in ("donna", "knot", "hickory"):
                start(role)
                before = logs()
                execute("capture", "--references", "/suite/" + role + ".json")
                run(
                    "cp",
                    client + ":/suite/" + role + ".json",
                    root / (role + "-reference.json"),
                )
                assert logs() == before
                record["references"][role] = sha(
                    (root / (role + "-reference.json")).read_bytes()
                )
                run("rm", "-fv", target)
            for trial in range(3):
                roles = ["donna", "knot", "hickory"]
                roles = roles[trial:] + roles[:trial]
                for role in roles:
                    identity = start(role)
                    before = logs()
                    row = dict(
                        role=role,
                        trial=trial,
                        container_id=identity["Id"],
                        started_at=identity["State"]["StartedAt"],
                        idle=[],
                        warm=[],
                    )
                    record["rows"].append(row)
                    for _ in range(3):
                        row["idle"].append(sample())
                        time.sleep(0.2)
                    row["workload"] = execute(
                        "warm",
                        "--references",
                        "/suite/" + role + ".json",
                        "--passes",
                        "40",
                    )
                    time.sleep(0.5)
                    for _ in range(3):
                        row["warm"].append(sample())
                        time.sleep(0.2)
                    post = f"/suite/{role}-post.json"
                    execute("capture", "--references", post)
                    dest = root / f"{role}-{trial}-post.json"
                    run("cp", client + ":" + post, dest)
                    assert json.loads(dest.read_text()) == json.loads(
                        (root / (role + "-reference.json")).read_text()
                    )
                    after = logs()
                    assert before == after
                    row["logging"] = dict(
                        before_bytes=len(before.encode()),
                        after_bytes=len(after.encode()),
                        before_sha256=sha(before.encode()),
                        after_sha256=sha(after.encode()),
                    )
                    row["post_capture_sha256"] = sha(dest.read_bytes())
                    run("rm", "-fv", target)
            record["summary"] = summary(record["rows"])
            record["complete"] = True
        except Exception as error:
            record["error"] = repr(error)
            raise
        finally:
            run("rm", "-fv", target, client, check=False)
            run("volume", "rm", volume, check=False)
            run("network", "rm", network, check=False)
            record["cleanup"] = (
                "Task-owned containers/network/volume removed; images retained for evidence export."
            )
            for name in source_files:
                dest = root / "harness" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((SUITE / name).read_bytes())
            record["harness_sha256"] = harness_hashes(SUITE, source_files)
            if Path("/tmp/donna-service-memory/runtime/memory_authority").exists():
                (root / "memory_authority").write_bytes(
                    Path(
                        "/tmp/donna-service-memory/runtime/memory_authority"
                    ).read_bytes()
                )
            record["artifact_members_sha256"] = {
                str(p.relative_to(root)): sha(p.read_bytes())
                for p in root.rglob("*")
                if p.is_file()
            }
            (root / "result.json").write_text(json.dumps(record, indent=2) + "\n")
            capsule = SUITE / ".artifacts/binaries/service-memory-public.tar.gz"
            with tarfile.open(capsule, "w:gz") as tar:
                for path in sorted(root.iterdir()):
                    tar.add(path, arcname=path.name)
            record["public_capsule"] = dict(
                path=str(capsule.relative_to(SUITE)), sha256=sha(capsule.read_bytes())
            )
            result_path.write_text(json.dumps(record, indent=2) + "\n")
            print(
                json.dumps(
                    dict(
                        complete=record["complete"],
                        rows=len(record["rows"]),
                        result=str(result_path),
                    )
                )
            )


if __name__ == "__main__":
    main()
