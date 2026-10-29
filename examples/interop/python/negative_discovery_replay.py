"""Offline reproduction of every signed negative discovery observation."""

import hashlib
import json
from pathlib import Path
import sys

import dns.message

from negative_fixture import guards, cases, SEEDS
from negative_evidence import NegativeVerifier
from negative_refresh import NegativeRefreshes
from recursive_replay import logs_at, verify_counts, ADDRESSES
from recursive_refresh import events


def replay_rows(record):
    assert record["complete"] is True
    roles, modes = record["roles"], record["modes"]
    assert roles and len(set(roles)) == len(roles) and set(roles) <= set(ADDRESSES)
    assert modes and len(set(modes)) == len(modes) and set(modes) <= {"nsec", "nsec3"}
    scenarios = record.get("scenarios", ["descendant", "sibling", "guards", "expiry"])
    assert (
        scenarios
        and len(set(scenarios)) == len(scenarios)
        and set(scenarios) <= {"descendant", "sibling", "guards", "expiry"}
    )
    expected = {
        (mode, role, scenario)
        for mode in modes
        for role in roles
        for scenario in scenarios
    }
    grouped = {identity: [] for identity in expected}
    for row in record["observations"]:
        identity = row["mode"], row["role"], row["scenario"]
        assert identity in grouped
        grouped[identity].append(row)
    passed = failed = 0
    for (mode, role, scenario), rows in grouped.items():
        assert len(rows) == (10 if scenario == "guards" else 3)
        assert [row["step"] for row in rows] == list(range(len(rows)))
        public = record["public"][mode]
        assert public["denial"] == mode
        scoped = dict(record, authority_logs=record["authority_logs"][mode])
        verifier = NegativeVerifier(public, rows[0]["capture"]["checked_at"])
        plan = [row["case"] for row in rows]
        if scenario == "guards":
            wanted = guards()
            wanted.insert(1, dict(wanted[0]))
            assert plan == wanted
        else:
            seed = SEEDS["descendant" if scenario == "expiry" else scenario]
            assert plan[:2] == [seed, seed]
            if scenario != "sibling" or mode == "nsec":
                assert (
                    plan[2]
                    == cases("descendant" if scenario == "expiry" else scenario)[0]
                )
            if scenario == "sibling":
                # A new sibling is eligible only if the actual seed packet
                # independently proves its denial, not merely an interval guess.
                verifier.oracle.verify(
                    plan[2],
                    dns.message.from_wire(
                        bytes.fromhex(rows[0]["capture"]["response"])
                    ),
                )
        witnesses = []
        for row in rows:
            assert row["capture"]["case"] == row["case"]
            verify_counts(scoped, row)
            before = logs_at(scoped, row["log_checkpoints"]["before"])
            after = logs_at(scoped, row["log_checkpoints"]["after"])
            fresh = events(before, after, ADDRESSES[role])
            assert fresh == row["events"]
            witnesses.extend(fresh)
            if scenario == "expiry" and row["step"] == 2:
                initial = rows[0]["capture"]
                reply = dns.message.from_wire(bytes.fromhex(initial["response"]))
                deadline = (
                    initial["received_monotonic_ns"]
                    + min(rr.ttl for rr in reply.authority) * 1_000_000_000
                )
                assert all(item["deadline_ns"] == deadline for item in rows)
                grace = row.get("expiry_wait_grace_seconds", 0.25)
                assert row["capture"]["received_monotonic_ns"] > deadline + int(
                    grace * 1e9
                )
                verifier = NegativeVerifier(public, row["capture"]["checked_at"])
            verifier.refreshes = NegativeRefreshes(verifier.oracle, witnesses, plan)
            try:
                info = verifier.verify(
                    row["case"],
                    row["capture"],
                    ad=row["case"]["kind"] != "insecure-positive",
                )
                valid = True
            except Exception:
                valid = False
                info = None
            assert row["passed"] is valid
            if valid:
                assert info == row["verification"]
                passed += 1
            else:
                failed += 1
    return dict(
        observations=passed + failed,
        passed=passed,
        failed=failed,
        network="none",
        private_signing_keys=0,
    )


def replay(root):
    record = json.loads((root / "result.json").read_text())
    for name, digest in record["harness_sha256"].items():
        assert (
            hashlib.sha256((root / "harness" / name).read_bytes()).hexdigest() == digest
        )
    return replay_rows(record)


if __name__ == "__main__":
    print(json.dumps(replay(Path(sys.argv[1]))))
