"""Offline replay of exact public mixed-workload packets and native/CPU rows."""

import json
from pathlib import Path
import sys

from diversity_fixture import digest, fixture
from diversity_load import check_reference
from server_cpu import difference


def check(root):
    record = json.loads((root / "result.json").read_text())
    assert record["harness_sha256"]
    for name, expected_hash in record["harness_sha256"].items():
        assert digest((root / "harness" / name).read_bytes()) == expected_hash
    assert (
        digest((root / "batched_load").read_bytes()) == record["native_binary_sha256"]
    )
    assert record["complete"] is True and record["population"] == 768
    repeats = record["repeats"]
    assert type(repeats) is int and 1 <= repeats <= 10
    roles = {"current", "knot", "hickory"}
    assert set(record["images"]) == roles
    assert (root / "fixture.db").read_text() == fixture()
    assert (
        digest((root / "source-manifest.json").read_bytes())
        == record["source_manifest_sha256"]
    )
    assert (
        json.loads((root / "source-manifest.json").read_text())
        == record["source_manifest"]
    )
    assert set(record["references"]) == {
        f"{role}-{phase}" for role in roles for phase in ("pre", "post")
    }
    references = {}
    for name, expected_hash in record["references"].items():
        path = root / (name + ".json")
        assert digest(path.read_bytes()) == expected_hash
        reference = json.loads(path.read_text())
        check_reference(reference)
        references[name] = reference
    for role in roles:
        assert references[role + "-pre"] == references[role + "-post"]
    expected = {
        (trial, role, mode, body)
        for trial in range(repeats)
        for role in roles
        for mode, body in (("finite", True), ("cycle", True), ("cycle", False))
    }
    seen = set()
    for row in record["rows"]:
        assert type(row["trial"]) is int and type(row["queries"]) is int
        key = (
            row["trial"],
            row["role"],
            row["input_mode"],
            row["response_body_verified"],
        )
        assert (
            type(row["response_body_verified"]) is bool
            and key in expected
            and key not in seen
        )
        seen.add(key)
        native = json.loads(row["native_output"])
        required_native = {
            "queries",
            "sent",
            "lost",
            "qps",
            "mean_us",
            "min_us",
            "max_us",
            "elapsed_seconds",
            "timed_cpu_seconds",
            "timed_cpu_percent",
            "response_body_verified",
            "outstanding",
        }
        assert required_native <= native.keys(), "missing native measurement fields"
        assert all(row[field] == value for field, value in native.items())
        assert row["queries"] == row["sent"] > 0 and row["lost"] == 0
        assert row["population"] == 768 and row["outstanding"] == 32
        assert (
            row["queries"] == 768
            if row["input_mode"] == "finite"
            else row["queries"] > 768
        )
        elapsed = row["elapsed_seconds"]
        assert elapsed > 0 and row["timed_cpu_seconds"] >= 0
        assert (
            abs(row["qps"] - row["queries"] / elapsed)
            <= 0.000001 + row["queries"] * 0.00000000051 / elapsed**2
        )
        cpu_rounding = 0.00000051 + 100 * 0.00000000051 * (
            1 / elapsed + row["timed_cpu_seconds"] / elapsed**2
        )
        assert (
            abs(row["timed_cpu_percent"] - 100 * row["timed_cpu_seconds"] / elapsed)
            <= cpu_rounding
        )
        assert 0 <= row["min_us"] <= row["mean_us"] <= row["max_us"]
        reference = references[row["role"] + "-pre"]
        for field in ("query_pool_sha256", "response_pool_sha256"):
            assert row[field] == reference[field]
        cpu = row["server_cpu"]
        assert difference(cpu["before"], cpu["after"], row["queries"]) == cpu
    assert seen == expected
    assert len(record["restarts"]) == repeats
    seen_trials = set()
    identities = {role: set() for role in roles}
    for restart in record["restarts"]:
        trial = restart["trial"]
        assert (
            type(trial) is int and trial in range(repeats) and trial not in seen_trials
        )
        seen_trials.add(trial)
        assert set(restart["processes"]) == roles
        for role, identity in restart["processes"].items():
            assert identity not in identities[role]
            identities[role].add(identity)
    assert {row["phase"] for row in record["logging"]} == {
        "preflight",
        "postflight",
    } | {f"trial-{i}" for i in range(repeats)}
    assert len(record["logging"]) == repeats + 2
    for row in record["logging"]:
        assert set(row["before"]) == roles and row["before"] == row["after"]
    return dict(
        trials=len(seen),
        strict_trials=sum(row["response_body_verified"] for row in record["rows"]),
        responses=sum(row["queries"] for row in record["rows"]),
        strict_responses=sum(
            row["queries"] for row in record["rows"] if row["response_body_verified"]
        ),
        lost=0,
        semantic_packets=768 * 6,
        restart_sets=repeats,
        log_equality_checkpoints=len(record["logging"]),
        network="none",
    )


if __name__ == "__main__":
    print(json.dumps(check(Path(sys.argv[1]))))
