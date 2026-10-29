"""Replay public authoritative benchmark evidence inside Docker, without network."""

import argparse
import hashlib
import gzip
import json
from pathlib import Path

import dns.message
import dns.name
import dns.rdatatype
import dns.zone

from similar_load import CASES, query_for, verify_response

APEX = dns.name.from_text("example.test.")
ALIASES = {"current": "donna-current", "verified": "donna-verified"}


def records(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


def replay(rows):
    fixtures, keys, complete = {}, {}, None
    logs, captures, preflights, timings = {}, {}, {}, {}
    independently_replayed = 0
    wire_packets = set()
    cases = {kind: (name, rtype, code) for kind, name, rtype, code in CASES}
    for row in rows:
        if "public_fixture" in row:
            fixture = row["public_fixture"]
            mode, text = fixture["mode"], fixture["zone_text"]
            assert mode not in fixtures, "duplicate public fixture"
            assert hashlib.sha256(text.encode()).hexdigest() == fixture["sha256"], (
                "fixture hash mismatch"
            )
            zone = dns.zone.from_text(text, origin=APEX, relativize=False)
            fixtures[mode] = fixture
            keyset = zone.get_rdataset(APEX, dns.rdatatype.DNSKEY)
            assert mode == "unsigned" or keyset, "signed fixture has no public DNSKEY"
            keys[mode] = {APEX: keyset} if mode != "unsigned" else None
        if "logging_gate" in row:
            mode, checkpoint = row["mode"], row["checkpoint"]
            assert checkpoint not in logs.setdefault(mode, {}), (
                "duplicate log checkpoint"
            )
            logs[mode][checkpoint] = row["logging_gate"]
        if "comparison_complete" in row:
            assert complete is None, "duplicate completion record"
            complete = row["comparison_complete"]
        if "verification" in row:
            mode, server, kind, phase = (
                row["mode"],
                row["server"],
                row["workload"],
                row["phase"],
            )
            assert phase in ("before", "after"), "unexpected proof gate phase"
            identity = (mode, server, kind, phase)
            assert identity not in captures, "duplicate proof gate"
            query_wire = bytes.fromhex(row["query_wire_hex"])
            query = dns.message.from_wire(query_wire)
            assert query_wire == query_for(mode, *cases[kind][:2]).to_wire(), (
                "wrong benchmark query"
            )
            assert row["captures"] and all(
                type(c["occurrences"]) is int and c["occurrences"] > 0
                for c in row["captures"]
            ), "invalid captured occurrence count"
            assert len(
                {bytes.fromhex(c["response_wire_hex"]) for c in row["captures"]}
            ) == len(row["captures"]), "duplicate captured packet"
            assert (
                sum(c["occurrences"] for c in row["captures"])
                == row["verified_replies"]
                == 40
            )
            for capture in row["captures"]:
                wire = bytes.fromhex(capture["response_wire_hex"])
                assert len(wire) <= 1232
                response = dns.message.from_wire(wire)
                assert capture["checked_at"] <= capture["last_checked_at"]
                for at in (capture["checked_at"], capture["last_checked_at"]):
                    verify_response(
                        mode, query, response, kind, cases[kind][2], keys[mode], now=at
                    )
                independently_replayed += 1
                wire_packets.add(wire)
            captures[identity] = row
        if "checked_at" in row and "server" in row and "repeat" in row:
            identity = (row["mode"], row["server"], row["workload"], row["repeat"])
            assert identity not in preflights, "duplicate timing reference"
            preflights[identity] = row
        if "qps" in row:
            identity = (row["mode"], row["server"], row["workload"], row["repeat"])
            assert identity not in timings, "duplicate timing row"
            assert row["response_body_verified"] is True, "timed body was not checked"
            assert row["queries"] == row["sent"] > 0 and row["lost"] == 0
            native = json.loads(row["native_output"])
            for field in (
                "queries",
                "sent",
                "lost",
                "response_body_verified",
                "qps",
                "mean_us",
                "min_us",
                "max_us",
                "elapsed_seconds",
                "timed_cpu_seconds",
                "timed_cpu_percent",
            ):
                assert native[field] == row[field], "native measurement mismatch"
            if "server_cpu" in row:
                from server_cpu import difference

                cpu = row["server_cpu"]
                assert cpu["before"]["processes"], "missing server CPU processes"
                assert cpu == difference(cpu["before"], cpu["after"], row["queries"]), (
                    "server CPU arithmetic mismatch"
                )
            reference = preflights[identity]
            assert (
                reference["expected_response_wire_hex"]
                == row["expected_response_wire_hex"]
            ), "reference body changed"
            query_wire = bytes.fromhex(row["query_wire_hex"])
            assert reference["query_wire_hex"] == query_wire.hex(), (
                "reference question changed"
            )
            mode, _, kind, _ = identity
            assert query_wire == query_for(mode, *cases[kind][:2]).to_wire(), (
                "wrong timed query"
            )
            assert hashlib.sha256(query_wire).hexdigest() == reference["query_sha256"]
            wire = bytes.fromhex(row["expected_response_wire_hex"])
            assert len(wire) == row["expected_response_bytes"] <= 1232
            assert hashlib.sha256(wire[2:]).hexdigest() == row["expected_body_sha256"]
            verify_response(
                mode,
                dns.message.from_wire(query_wire),
                dns.message.from_wire(wire),
                kind,
                cases[kind][2],
                keys[mode],
                now=reference["checked_at"],
            )
            independently_replayed += 1
            wire_packets.add(wire)
            timings[identity] = row
    assert complete and complete["verify_wire"] and not complete["verify_only"], (
        "missing successful strict completion"
    )
    selected = list(cases) if complete["cases"] is None else complete["cases"]
    assert type(complete["repeats"]) is int and complete["repeats"] > 0, (
        "invalid repeat count"
    )
    for values in (complete["modes"], complete["roles"], selected):
        assert values and len(values) == len(set(values)), (
            "empty or duplicate matrix dimension"
        )
    assert set(complete["modes"]) <= {"unsigned", "nsec", "nsec3"}
    assert set(complete["roles"]) <= {
        "current",
        "verified",
        "bind",
        "knot",
        "nsd",
        "hickory",
    }
    assert set(selected) <= set(cases)
    servers = [ALIASES.get(role, role) for role in complete["roles"]]
    expected = {
        (mode, server, kind, repeat)
        for mode in complete["modes"]
        for server in servers
        for kind in selected
        for repeat in range(complete["repeats"])
    }
    assert set(timings) == expected == set(preflights), (
        "incomplete or extra timing matrix"
    )
    expected_captures = {
        (mode, server, kind, phase)
        for mode in complete["modes"]
        for server in servers
        for kind in selected
        for phase in ("before", "after")
    }
    assert set(captures) == expected_captures, "incomplete or extra pre/post matrix"
    assert set(fixtures) == set(complete["modes"]), "missing or extra public catalog"
    for mode in complete["modes"]:
        checkpoints = logs[mode]
        assert set(checkpoints) == {
            "before",
            "after-preflight",
            "after-timing",
            "after",
        }, "incomplete log equality gate"
        assert set(checkpoints["before"]) == set(complete["roles"]), (
            "wrong log server set"
        )
        assert all(value == checkpoints["before"] for value in checkpoints.values()), (
            "server log bytes changed"
        )
        for server in servers:
            for kind in selected:
                for phase in ("before", "after"):
                    assert (mode, server, kind, phase) in captures, (
                        "missing pre/post reply proof"
                    )
    return {
        "public_fixtures": len(fixtures),
        "timing_trials": len(timings),
        "strict_responses": sum(row["queries"] for row in timings.values()),
        "signed_strict_responses": sum(
            row["queries"]
            for identity, row in timings.items()
            if identity[0] != "unsigned"
        ),
        "pre_post_case_rows": len(captures),
        "packet_contexts_replayed": independently_replayed,
        "unique_wire_packets": len(wire_packets),
        "log_checkpoints": sum(len(checkpoint) for checkpoint in logs.values()),
        "network_required": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    text = (
        gzip.decompress(args.evidence.read_bytes()).decode()
        if args.evidence.suffix == ".gz"
        else args.evidence.read_text()
    )
    print(json.dumps(replay(records(text))), flush=True)


if __name__ == "__main__":
    main()
