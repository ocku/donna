"""Offline full-frame, proof, TTL, CPU and authority-count replay of negative trials."""

import hashlib
import json
from pathlib import Path
import sys

from negative_discovery_replay import replay_rows
from negative_evidence import NegativeVerifier
from negative_fixture import cases, inputs, SEEDS
from negative_refresh import NegativeRefreshes
from negative_security import verify as verify_security
from negative_proof_bank import freeze, clock_domain
from recursive_capture import expanded, read_compact
from recursive_replay import logs_at, verify_counts, ADDRESSES
from recursive_refresh import events
from recursive_evidence import authenticated_keys


def replay(root):
    record = json.loads((root / "result.json").read_text())
    assert record["complete"] is True and record["modes"] == ["nsec"]
    for name, digest in record["harness_sha256"].items():
        assert (
            hashlib.sha256((root / "harness" / name).read_bytes()).hexdigest() == digest
        )
    raw = (root / "source-manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record["donna_source_manifest_sha256"]
    assert json.loads(raw) == record["donna_source_manifest"]
    roles = record["roles"]
    assert roles and len(roles) == len(set(roles)) and set(roles) <= set(ADDRESSES)
    repeats = record["repeats"]
    assert type(repeats) is int and 1 <= repeats <= 5 and 1 <= record["seconds"] <= 2
    assert type(record["gates_only"]) is bool and set(record["skip_warm"]) <= set(roles)
    ordinary = dict(
        record,
        observations=[
            row for row in record["observations"] if row["scenario"] != "security"
        ],
    )
    if record["scenarios"]:
        functional = replay_rows(ordinary)
    else:
        assert not ordinary["observations"]
        functional = dict(
            observations=0, passed=0, failed=0, network="none", private_signing_keys=0
        )
    public = record["public"]["nsec"]
    scoped = dict(record, authority_logs=record["authority_logs"]["nsec"])
    expected = (
        {
            (role, reason, cd_first, step)
            for role in roles
            for reason in ("bad-ds", "bad-signature")
            for cd_first in (False, True)
            for step in (0, 1)
        }
        if not record["warm_only"]
        else set()
    )
    seen = set()
    security_passed = security_failed = 0
    for row in record["observations"]:
        if row["scenario"] != "security":
            continue
        identity = row["role"], row["security"], row["cd_first"], row["step"]
        assert identity in expected and identity not in seen
        seen.add(identity)
        verify_counts(scoped, row)
        assert row["case"] == SEEDS["sibling"] and row["capture"]["case"] == row["case"]
        assert row["capture"]["cd"] is (row["step"] == (0 if row["cd_first"] else 1))
        try:
            info = verify_security(public, row["case"], row["capture"], row["security"])
            valid = True
        except Exception:
            info = None
            valid = False
        assert row["passed"] is valid
        if valid:
            assert info == row["verification"]
            security_passed += 1
        else:
            security_failed += 1
    assert seen == expected
    expected_trials = set()
    if not record["gates_only"] and not record["warm_only"]:
        expected_trials |= {(role, "cold", "exact", 0) for role in roles}
        expected_trials |= {
            (role, "fresh", kind, 0)
            for role in roles
            for kind in ("descendant", "sibling")
        }
    if not record["gates_only"]:
        expected_trials |= {
            (role, "warm", "exact", repeat)
            for role in roles
            if role not in record["skip_warm"]
            for repeat in range(repeats)
        }
    seen = set()
    responses = math_checks = ttl_checks = 0
    for row in record["trials"]:
        identity = row["role"], row["label"], row["kind"], row["repeat"]
        assert identity in expected_trials and identity not in seen
        seen.add(identity)
        verify_counts(scoped, row)
        before = logs_at(scoped, row["log_checkpoints"]["before"])
        after = logs_at(scoped, row["log_checkpoints"]["after"])
        witnesses = events(before, after, ADDRESSES[row["role"]])
        assert witnesses == row["authority_events"]
        assert row["request_total"] == sum(row["authority_requests"].values())
        assert row["zero_upstream_reuse"] is (not row["authority_requests"])
        native = json.loads(row["native_output"])
        assert native == row["native"]
        assert native["capture_budget_bytes"] == record["capture_budget_bytes"]
        assert (
            type(native["capture_budget_bytes"]) is int
            and 1 <= native["capture_budget_bytes"] <= 512 * 1024 * 1024
        )
        required = {
            "queries",
            "sent",
            "lost",
            "qps",
            "elapsed_seconds",
            "timed_cpu_seconds",
            "timed_cpu_percent",
            "outstanding",
            "captured_responses",
            "capture_bytes",
            "started_unix_seconds",
            "ended_unix_seconds",
            "started_monotonic_seconds",
        }
        assert (
            required <= native.keys()
            and native["lost"] == 0
            and native["outstanding"] == 32
        )
        assert (
            type(native["queries"]) is int and native["queries"] == native["sent"] > 0
        )
        elapsed = native["elapsed_seconds"]
        assert elapsed > 0
        assert (
            abs(native["qps"] - native["queries"] / elapsed)
            <= 0.000001 + native["queries"] * 0.00000000051 / elapsed**2
        )
        assert (
            abs(
                native["timed_cpu_percent"]
                - 100 * native["timed_cpu_seconds"] / elapsed
            )
            < 0.00001
        )
        if row["label"] == "warm":
            assert elapsed >= record["seconds"]
        plan = cases(row["kind"])
        packets = inputs(row["kind"])
        if row["label"] != "warm":
            assert native["queries"] == len(plan)
        path = root / row["capture"]
        packing = row["verification"]["compaction"]
        assert (
            hashlib.sha256(path.read_bytes()).hexdigest() == packing["compact_sha256"]
        )
        digest = hashlib.sha256()
        for block in expanded(path):
            digest.update(block)
        assert digest.hexdigest() == packing["raw_sha256"]
        state = root / (path.stem + ".preload.json")
        deadlines = None
        if state.exists():
            saved = json.loads(state.read_text())
            pre_before = logs_at(scoped, row["preload_log_checkpoints"]["before"])
            pre_after = logs_at(scoped, row["preload_log_checkpoints"]["after"])
            pre_events = events(pre_before, pre_after, ADDRESSES[row["role"]])
            assert (
                pre_events
                == saved["acquisition_events"]
                == json.loads((root / (path.stem + ".preload.events.json")).read_text())
            )
            assert clock_domain(saved["captures"]) == saved["clock_domain"]
            assert (
                clock_domain(saved["captures"], native)
                == row["verification"]["clock_domain"]
            )
            frozen = freeze(public, saved["captures"], pre_events)
            assert frozen == saved["verification"]
            assert {
                key: value for key, value in frozen.items() if key != "deadlines"
            } == saved["observation_checks"]
            deadlines = frozen["deadlines"]
            if row["kind"] == "exact":
                assert [capture["case"] for capture in saved["captures"]] == plan
            else:
                assert (
                    len(saved["captures"]) == 1
                    and saved["captures"][0]["case"] == SEEDS[row["kind"]]
                )
                import dns.message

                seed = dns.message.from_wire(
                    bytes.fromhex(saved["captures"][0]["response"])
                )
                oracle = NegativeVerifier(
                    public, saved["captures"][0]["checked_at"]
                ).oracle
                for case in plan:
                    oracle.verify(case, seed)
        elif row["label"] != "cold":
            raise AssertionError("warm/fresh trial has no authenticated seed/preload")
        verifier = NegativeVerifier(
            public,
            native["started_unix_seconds"],
            deadlines=deadlines,
            frozen=True,
            require_seed=state.exists(),
        )
        verifier.refreshes = NegativeRefreshes(verifier.oracle, witnesses, plan)
        for capture in read_compact(path, packets, native):
            info = verifier.verify(plan[capture["index"]], capture)
            assert info["flags"] == row["expected_response_flags"]
        authenticated_keys(public, native["ended_unix_seconds"])
        summary = {
            key: value
            for key, value in verifier.summary().items()
            if key != "deadlines"
        }
        assert (
            summary == row["verification"]["verification"]
            and summary["responses"] == native["queries"] == packing["packets"]
        )
        for name in row["cpu_before"]:
            old, new = row["cpu_before"][name], row["cpu_after"][name]
            assert {key: new[key] - value for key, value in old.items()} == row[
                "cpu_delta"
            ][name]
            assert all(value >= 0 for value in row["cpu_delta"][name].values())
        responses += native["queries"]
        math_checks += summary["unique_math_verifications"]
        ttl_checks += summary["ttl_checks"]
    assert seen == expected_trials
    return dict(
        native_trials=len(seen),
        timed_replies=responses,
        leaf_math_checks=math_checks,
        per_reply_ttl_checks=ttl_checks,
        functional=functional,
        security_passed=security_passed,
        security_failed=security_failed,
        network="none",
        private_signing_keys=0,
    )


if __name__ == "__main__":
    print(json.dumps(replay(Path(sys.argv[1]))), flush=True)
