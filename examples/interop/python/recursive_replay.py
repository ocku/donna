"""Offline full-packet replay of signed recursive measurements and control gates."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

import dns.dnssec
import dns.flags
import dns.rdatatype
import dns.message
import dns.rcode

from recursive_capture import read_compact, expanded
from recursive_evidence import Verifier, authenticated_keys, zones, rrset, record_key
from recursive_fixture import cases, pool
from recursive_refresh import events, Refreshes

ADDRESSES = {
    "donna": "172.29.53.74",
    "knot-resolver": "172.29.53.75",
    "hickory": "172.29.53.76",
}


def counts(logs, address):
    result = Counter()
    for zone, text in logs.items():
        for name, kind in re.findall(
            re.escape(address) + r"#.*query: (\S+) IN (\S+)", text
        ):
            result[zone + "/" + name.lower().rstrip(".") + "/" + kind] += 1
    return result


def logs_at(record, checkpoint):
    assert set(checkpoint) == {"root", "tld", "leaf"}
    result = {}
    for zone, boundary in checkpoint.items():
        data = record["authority_logs"][zone].encode()[: boundary["bytes"]]
        assert len(data) == boundary["bytes"]
        assert hashlib.sha256(data).hexdigest() == boundary["sha256"]
        result[zone] = data.decode()
    return result


def verify_counts(record, row):
    before = logs_at(record, row["log_checkpoints"]["before"])
    after = logs_at(record, row["log_checkpoints"]["after"])
    old, new = (
        counts(before, ADDRESSES[row["role"]]),
        counts(after, ADDRESSES[row["role"]]),
    )
    assert all(new[key] >= value for key, value in old.items())
    assert dict(new - old) == row["authority_requests"]


def refreshed_deadlines(verifier, row):
    deadlines = dict(verifier.deadlines)

    def queried(name, kinds):
        prefix = "leaf/" + name.lower().rstrip(".") + "/"
        return any(row["authority_requests"].get(prefix + kind, 0) for kind in kinds)

    for capture in row["captures"]:
        case = capture["case"]
        response = dns.message.from_wire(bytes.fromhex(capture["response"]))
        if case["kind"] == "direct":
            assert queried(case["name"], (case["rtype"], "ANY")), (
                "expiry has no owner-specific reacquisition witness"
            )
            for rr in response.answer:
                if rr.rdtype != dns.rdatatype.RRSIG:
                    deadlines.pop(record_key(rr), None)
        else:
            dname = next(
                rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNAME
            )
            full = queried(case["name"], (case["rtype"], "ANY"))
            assert full or queried(dname.name.to_text(), ("DNAME", "ANY")), (
                "DNAME expiry has no reacquisition witness"
            )
            deadlines.pop(record_key(dname), None)
            if full or queried(case["target"], (case["rtype"], "ANY")):
                for rr in response.answer:
                    if rr.rdtype == dns.rdatatype.A:
                        deadlines.pop(record_key(rr), None)
    return deadlines


def replay(root):
    record = json.loads((root / "result.json").read_text())
    public = json.loads((root / "public.json").read_text())
    assert record["complete"] is True and type(record["gates_only"]) is bool
    repeats = record["repeats"]
    assert type(repeats) is int and 1 <= repeats <= 5 and 1 <= record["seconds"] <= 3
    for name, digest in record["harness_sha256"].items():
        assert (
            hashlib.sha256((root / "harness" / name).read_bytes()).hexdigest() == digest
        )
    source = (root / "source-manifest.json").read_bytes()
    assert hashlib.sha256(source).hexdigest() == record["donna_source_manifest_sha256"]
    assert json.loads(source) == record["donna_source_manifest"]
    selected = record["roles"]
    assert (
        selected
        and len(set(selected)) == len(selected)
        and set(selected) <= set(ADDRESSES)
    )
    roles = set(selected)
    assert {row["role"] for row in record["capabilities"]} == roles and len(
        record["capabilities"]
    ) == len(roles)
    eligible = {}
    capability_packets = security_packets = expiry_packets = 0
    for row in record["capabilities"]:
        assert len(row["capabilities"]) == 3
        dnames = []
        for item in row["capabilities"]:
            capture = item["capture"]
            assert capture and capture["case"] == item["case"]
            passed = True
            try:
                Verifier(public, capture["checked_at"]).verify(item["case"], capture)
            except Exception:
                passed = False
            assert item["passed"] is passed
            if item["kind"] == "direct":
                assert passed
            else:
                dnames.append(passed)
            capability_packets += 1
        assert len(dnames) == 1
        eligible[row["role"]] = dnames[0]
    common = "direct"
    assert record["common_workload"] == common
    coherence_packets = 0
    assert (
        len(record["coherence"]) == len(roles)
        and {row["role"] for row in record["coherence"]} == roles
    )
    for row in record["coherence"]:
        verify_counts(record, row)
        assert len(row["coherence"]) == 3
        for capture, kind in zip(row["coherence"], ("A", "AAAA", "TXT"), strict=True):
            assert (
                capture["case"]["rtype"] == kind
                and capture["case"]["name"] == "coherence.example.test."
            )
            Verifier(public, capture["checked_at"]).verify(capture["case"], capture)
            coherence_packets += 1
        capture = row["rrsig_observation"]
        query = dns.message.from_wire(bytes.fromhex(capture["query"]))
        message = dns.message.from_wire(bytes.fromhex(capture["response"]))
        assert query.is_response(message) and message.rcode() == row["rrsig_rcode"]
        covered = []
        if message.rcode() == 0:
            leaf = zones(public)["leaf"]
            keys = authenticated_keys(public, capture["checked_at"])
            for recordset in message.answer:
                assert (
                    recordset.rdtype == dns.rdatatype.RRSIG
                    and recordset.name == query.question[0].name
                )
                for sig in recordset:
                    dns.dnssec.validate_rrsig(
                        rrset(leaf, recordset.name, sig.type_covered),
                        sig,
                        keys,
                        now=capture["checked_at"],
                    )
                    covered.append(sig.type_covered)
        assert sorted(covered) == row["covered_types"]
        coherence_packets += 1
    expected_security = {(role, cd) for role in roles for cd in (False, True)}
    seen = set()
    for row in record["security"]:
        identity = row["role"], row["cd_first"]
        assert identity in expected_security and identity not in seen
        seen.add(identity)
        verify_counts(record, row)
        assert len(row["security"]) == 2
        order = (True, False) if row["cd_first"] else (False, True)
        for capture, cd in zip(row["security"], order, strict=True):
            assert capture["cd"] is cd
            query = dns.message.from_wire(bytes.fromhex(capture["query"]))
            response = dns.message.from_wire(bytes.fromhex(capture["response"]))
            assert (
                query.is_response(response)
                and bool(response.flags & dns.flags.CD) == cd
            )
            assert not response.flags & dns.flags.AD
            try:
                authenticated_keys(public, capture["checked_at"], bad=True)
            except AssertionError as error:
                assert "DS does not match" in str(error)
            else:
                raise AssertionError("bogus DS accepted")
            if cd:
                Verifier(public, capture["checked_at"], trusted=False).verify(
                    capture["case"], capture, cd=True, ad=False
                )
            else:
                assert response.rcode() == dns.rcode.SERVFAIL and not response.answer
            security_packets += 1
    assert seen == expected_security
    expected_expiry = {
        (role, phase) for role in roles for phase in ("initial", "warm", "expired")
    }
    seen, expiry_verifiers, expiry_deadlines = set(), {}, {}
    for row in record["expiry"]:
        identity = row["role"], row["expiry_phase"]
        assert identity in expected_expiry and identity not in seen
        seen.add(identity)
        verify_counts(record, row)
        if row["expiry_phase"] == "initial":
            expiry_deadlines[row["role"]] = max(
                capture["received_monotonic_ns"]
                + min(
                    rr.ttl
                    for rr in dns.message.from_wire(
                        bytes.fromhex(capture["response"])
                    ).answer
                )
                * 1_000_000_000
                for capture in row["captures"]
            )
        assert row["deadline_ns"] == expiry_deadlines[row["role"]]
        if row["expiry_phase"] == "initial":
            expiry_verifiers[row["role"]] = Verifier(
                public, row["captures"][0]["checked_at"]
            )
        elif row["expiry_phase"] == "expired":
            renewed = refreshed_deadlines(expiry_verifiers[row["role"]], row)
            expiry_verifiers[row["role"]] = Verifier(
                public, row["captures"][0]["checked_at"], deadlines=renewed
            )
        assert len(row["captures"]) == (2 if eligible[row["role"]] else 1)
        if row["expiry_phase"] == "expired":
            assert row["authority_requests"]
            assert (
                min(c["received_monotonic_ns"] for c in row["captures"])
                > row["deadline_ns"]
            )
        for capture in row["captures"]:
            expiry_verifiers[row["role"]].verify(capture["case"], capture)
            expiry_packets += 1
    assert seen == expected_expiry
    expected_trials = set()
    if not record["gates_only"]:
        expected_trials |= {(role, "cold", 0, common) for role in roles}
        expected_trials |= {
            (role, "warm", repeat, common)
            for role in roles
            for repeat in range(repeats)
        }
        expected_trials |= {
            (role, "prepared", repeat, "dname")
            for role in roles
            if eligible[role]
            for repeat in range(repeats)
        }
    seen, responses, math_calls, ttl_checks = set(), 0, 0, 0
    for row in record["trials"]:
        identity = row["role"], row["label"], row["repeat"], row["kind"]
        assert identity in expected_trials and identity not in seen
        seen.add(identity)
        verify_counts(record, row)
        assert row["request_total"] == sum(row["authority_requests"].values())
        witnesses = events(
            logs_at(record, row["log_checkpoints"]["before"]),
            logs_at(record, row["log_checkpoints"]["after"]),
            ADDRESSES[row["role"]],
        )
        assert witnesses == row["authority_events"]
        assert row["zero_upstream_reuse"] is (not row["authority_requests"])
        native = json.loads(row["native_output"])
        assert native == row["native"]
        required = {
            "queries",
            "sent",
            "lost",
            "qps",
            "elapsed_seconds",
            "timed_cpu_seconds",
            "timed_cpu_percent",
            "captured_responses",
            "capture_bytes",
            "outstanding",
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
        if row["label"] == "warm":
            assert elapsed >= record["seconds"]
        kind = None if row["kind"] == "all" else row["kind"]
        inputs, plan = pool(kind=kind), cases(kind)
        if row["label"] != "warm":
            assert native["queries"] == len(inputs)
        path = root / row["capture"]
        packing = row["verification"]["compaction"]
        assert (
            hashlib.sha256(path.read_bytes()).hexdigest() == packing["compact_sha256"]
        )
        reconstructed = hashlib.sha256()
        for block in expanded(path):
            reconstructed.update(block)
        assert reconstructed.hexdigest() == packing["raw_sha256"]
        preload = root / (path.stem + ".preload.json")
        deadlines = (
            json.loads(preload.read_text())["verification"]["deadlines"]
            if preload.exists()
            else None
        )
        # Revalidate preload packets so saved deadlines cannot invent lifetimes.
        if preload.exists():
            saved = json.loads(preload.read_text())
            pre = Verifier(public, saved["captures"][0]["checked_at"])
            for capture in saved["captures"]:
                pre.verify(capture["case"], capture)
            assert pre.summary() == saved["verification"]
        verifier = Verifier(
            public,
            native["started_unix_seconds"],
            deadlines=deadlines,
            refreshes=Refreshes(witnesses),
        )
        for capture in read_compact(path, inputs, native):
            verifier.verify(plan[capture["index"]], capture)
        authenticated_keys(public, native["ended_unix_seconds"])
        summary = {
            key: value
            for key, value in verifier.summary().items()
            if key != "deadlines"
        }
        assert summary == row["verification"]["verification"]
        assert summary["responses"] == native["queries"] == packing["packets"]
        for name in row["cpu_before"]:
            before, after = row["cpu_before"][name], row["cpu_after"][name]
            assert {key: after[key] - value for key, value in before.items()} == row[
                "cpu_delta"
            ][name]
            assert all(value >= 0 for value in row["cpu_delta"][name].values())
        responses += native["queries"]
        math_calls += summary["unique_math_verifications"]
        ttl_checks += summary["ttl_checks"]
    assert seen == expected_trials
    return dict(
        capability_packets=capability_packets,
        security_packets=security_packets,
        coherence_packets=coherence_packets,
        expiry_packets=expiry_packets,
        timing_trials=len(seen),
        captured_responses=responses,
        unique_math_verifications=math_calls,
        per_reply_ttl_checks=ttl_checks,
        dns_signing_keys_retained=0,
        network="none",
    )


if __name__ == "__main__":
    print(json.dumps(replay(Path(sys.argv[1]))), flush=True)
