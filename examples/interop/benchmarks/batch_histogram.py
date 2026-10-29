#!/usr/bin/env python3
"""Actual private UDP batch counters, with an unchanged normal release control."""

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from support.evidence import write_record
from support.lock import laboratory_lock
from support.paths import SUITE


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if check and result.returncode:
        raise RuntimeError(result.stdout.decode()[-4000:])
    return result.stdout


def identity(image):
    return json.loads(docker("image", "inspect", image))[0]["Id"]


def snapshot(name):
    old = docker("logs", name)
    docker("kill", "--signal=USR1", name)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        new = docker("logs", name)
        rows = [
            line
            for line in new[len(old) :].splitlines()
            if line.startswith(b"UDP_BATCH_PROFILE ")
        ]
        if rows:
            assert len(rows) == 1
            return json.loads(rows[0].split(b" ", 1)[1])
        time.sleep(0.02)
    raise RuntimeError("profile snapshot did not arrive")


def difference(before, after):
    result = {}
    for field in ("rx", "dispatch", "send"):
        assert len(before[field]) == len(after[field]) == 17
        result[field] = [b - a for a, b in zip(before[field], after[field])]
        assert all(value >= 0 for value in result[field])
    result["counts"] = {
        name: after["counts"][name] - value for name, value in before["counts"].items()
    }
    assert all(value >= 0 for value in result["counts"].values())
    return result


def validate_counts(delta, queries):
    count = delta["counts"]
    weighted = lambda values: sum(i * n for i, n in enumerate(values))
    assert weighted(delta["rx"]) == queries == count["sync_some"] == count["prepared"]
    assert (
        count["rx_calls"]
        == sum(delta["rx"]) + count["rx_would_block"] + count["rx_interrupted"]
    )
    assert count["first_attempt"] == count["first_sent"] == sum(delta["rx"][1:])
    assert (
        weighted(delta["dispatch"])
        == weighted(delta["send"])
        == count["send_committed"]
    )
    assert queries == count["first_sent"] + count["send_committed"]
    for name in (
        "sync_none",
        "deferred",
        "deferred_ready",
        "deferred_pending",
        "first_would_block",
        "first_error",
        "first_expired",
        "send_error",
    ):
        assert count[name] == 0, (name, count[name])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", default="donna-ingress-control:local")
    parser.add_argument("--profile", default="donna-batch-histogram:local")
    parser.add_argument("--client", default="donna-interop-diversity-client:local")
    parser.add_argument("--seconds", type=int, default=1)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/interop/.artifacts/udp-batch-histogram.json"),
    )
    args = parser.parse_args()
    assert 1 <= args.seconds <= 5
    suite = SUITE
    prefix = "donna-batch-hist-"
    network, certs, probe = (prefix + part for part in ("network", "certs", "client"))
    peers = identity("donna-interop-peers")
    images = {
        role: identity(image)
        for role, image in (
            ("normal", args.normal),
            ("profile", args.profile),
            ("client", args.client),
        )
    }
    record = {
        "scope": "Diagnostic actual batch counters; normal/profile observer comparison, no optimization speedup claim",
        "images": images,
        "peers_image": peers,
        "seconds": args.seconds,
        "fixture_sha256": hashlib.sha256(
            (suite / "fixtures/basic/zone.db").read_bytes()
        ).hexdigest(),
        "instrumentation": "Relaxed aggregate atomics; snapshots only between trials; syscall, allocation, scheduling and admission control flow unchanged",
        "rows": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with laboratory_lock():
        try:
            docker("network", "create", "--subnet", "172.29.57.0/24", network)
            docker("volume", "create", certs)
            docker(
                "run",
                "--rm",
                "-v",
                certs + ":/certs",
                peers,
                "python",
                "certificates.py",
            )
            docker(
                "run",
                "-d",
                "--name",
                probe,
                "--network",
                network,
                "--entrypoint",
                "sleep",
                images["client"],
                "infinity",
            )
            for name in ("batch_histogram_probe.py", "similar_load.py"):
                docker("cp", str(suite / "python" / name), probe + ":/suite/" + name)
            for workers in (1, 2):
                for role, last in (("normal", "10"), ("profile", "11")):
                    name = prefix + role
                    docker(
                        "run",
                        "-d",
                        "--name",
                        name,
                        "--network",
                        network,
                        "--ip",
                        "172.29.57." + last,
                        "-v",
                        certs + ":/certs:ro",
                        "-e",
                        "LISTEN_HOST=172.29.57." + last,
                        "-e",
                        "ZONE_FILE=/suite/fixtures/basic/zone.db",
                        "-e",
                        "RUST_LOG=error",
                        "-e",
                        "TOKIO_WORKER_THREADS=" + str(workers),
                        images[role],
                    )
                deadline = time.monotonic() + 10
                while True:
                    ready = docker(
                        "exec",
                        probe,
                        "python",
                        "-c",
                        "import socket;socket.create_connection(('172.29.57.10',5300),.3).close();socket.create_connection(('172.29.57.11',5300),.3).close();print('ready')",
                        check=False,
                    )
                    if ready.strip() == b"ready":
                        break
                    assert time.monotonic() < deadline, ready.decode()
                    time.sleep(0.05)
                for window in (1, 32):
                    for case_index, case in enumerate(
                        ("positive", "wildcard", "negative")
                    ):
                        roles = (
                            ("normal", "profile")
                            if case_index % 2 == 0
                            else ("profile", "normal")
                        )
                        for role in roles:
                            address = "172.29.57." + (
                                "10" if role == "normal" else "11"
                            )
                            name = prefix + role
                            prepare = json.loads(
                                docker(
                                    "exec",
                                    probe,
                                    "python",
                                    "/suite/batch_histogram_probe.py",
                                    address + ":5300",
                                    case,
                                )
                            )
                            before = snapshot(name) if role == "profile" else None
                            log_before = docker("logs", name)
                            raw = docker(
                                "exec",
                                probe,
                                "batched_load",
                                address,
                                "5300",
                                str(args.seconds),
                                str(prepare["flags"]),
                                "/tmp/batch-query.wire",
                                "--window",
                                str(window),
                                "--expected-response",
                                "/tmp/batch-expected.wire",
                            )
                            assert docker("logs", name) == log_before, (
                                "query-time server logging"
                            )
                            after = snapshot(name) if role == "profile" else None
                            load = json.loads(raw)
                            assert (
                                load["lost"] == 0
                                and load["sent"] == load["queries"] > 0
                            )
                            assert (
                                load["outstanding"] == window
                                and load["response_body_verified"] is True
                            )
                            post = json.loads(
                                docker(
                                    "exec",
                                    probe,
                                    "python",
                                    "/suite/batch_histogram_probe.py",
                                    address + ":5300",
                                    case,
                                    "--post",
                                )
                            )
                            assert (
                                post["query_wire_hex"] == prepare["query_wire_hex"]
                                and post["response_wire_hex"]
                                == prepare["response_wire_hex"]
                            )
                            row = dict(
                                role=role,
                                workers=workers,
                                outstanding=window,
                                case=case,
                                preflight=prepare,
                                postflight=post,
                                native=load,
                                native_stdout=raw.decode(),
                            )
                            if before is not None:
                                delta = difference(before, after)
                                validate_counts(delta, load["queries"])
                                row.update(before=before, after=after, delta=delta)
                            record["rows"].append(row)
                            write_record(args.output, record)
                            print(
                                json.dumps(
                                    {
                                        "role": role,
                                        "workers": workers,
                                        "outstanding": window,
                                        "case": case,
                                        "queries": load["queries"],
                                        "qps": load["qps"],
                                        "rx": row.get("delta", {}).get("rx"),
                                    }
                                ),
                                flush=True,
                            )
                for role in ("normal", "profile"):
                    docker("rm", "-f", prefix + role)
            record["completed"] = True
        finally:
            docker(
                "rm", "-f", prefix + "normal", prefix + "profile", probe, check=False
            )
            docker("network", "rm", network, check=False)
            docker("volume", "rm", certs, check=False)
            record["cleanup"] = (
                "Task runtime containers, network and certificate volume removed."
            )
            write_record(args.output, record)


if __name__ == "__main__":
    main()
