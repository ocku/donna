"""Fault injection for offline mathematical replay; run only inside Docker."""

import copy
import hashlib
import json
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
import dns.dnssec
import dns.flags
import dns.message
import dns.rrset

from authority_replay import replay
from similar_load import query_for


def fixture():
    at = int(time.time())
    private = ec.generate_private_key(ec.SECP256R1())
    key = dns.dnssec.make_dnskey(private.public_key(), "ECDSAP256SHA256", flags=257)
    query = query_for("nsec", "www.example.test.", "A")
    answer = dns.rrset.from_text("www.example.test.", 300, "IN", "A", "192.0.2.80")
    signature = dns.dnssec.sign(
        answer, private, "example.test.", key, inception=at - 60, expiration=at + 3600
    )
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    response.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
    response.answer.extend([answer, dns.rrset.from_rdata(answer.name, 300, signature)])
    wire = response.to_wire()
    text = (
        "$ORIGIN example.test.\n$TTL 300\n"
        "@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 60 30\n"
        "@ IN NS ns.example.test.\nns IN A 192.0.2.53\n"
        f"@ IN DNSKEY {key.to_text()}\nwww IN A 192.0.2.80\n"
    )
    rows = [
        {
            "public_fixture": {
                "mode": "nsec",
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "zone_text": text,
            }
        }
    ]
    for checkpoint in ("before", "after-preflight", "after-timing", "after"):
        rows.append(
            {
                "mode": "nsec",
                "checkpoint": checkpoint,
                "logging_gate": {
                    "knot": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
                },
            }
        )
    common = dict(
        mode="nsec",
        server="knot",
        workload="positive",
        query_wire_hex=query.to_wire().hex(),
    )
    for phase in ("before", "after"):
        rows.append(
            dict(
                common,
                verification="signature/shape",
                phase=phase,
                verified_replies=40,
                captures=[
                    dict(
                        response_wire_hex=wire.hex(),
                        checked_at=at,
                        last_checked_at=at,
                        occurrences=40,
                    )
                ],
            )
        )
    rows.append(
        dict(
            common,
            repeat=0,
            checked_at=at,
            expected_response_wire_hex=wire.hex(),
            query_sha256=hashlib.sha256(query.to_wire()).hexdigest(),
        )
    )
    native = dict(
        queries=32,
        sent=32,
        lost=0,
        response_body_verified=True,
        qps=32,
        mean_us=10,
        min_us=1,
        max_us=20,
        elapsed_seconds=1,
        timed_cpu_seconds=0.5,
        timed_cpu_percent=50,
    )
    rows.append(
        dict(
            common,
            repeat=0,
            **native,
            native_output=json.dumps(native),
            expected_response_wire_hex=wire.hex(),
            expected_response_bytes=len(wire),
            expected_body_sha256=hashlib.sha256(wire[2:]).hexdigest(),
        )
    )
    rows.append(
        {
            "comparison_complete": dict(
                modes=["nsec"],
                roles=["knot"],
                cases=["positive"],
                repeats=1,
                verify_wire=True,
                verify_only=False,
            )
        }
    )
    return rows


class AuthorityReplayTests(unittest.TestCase):
    def setUp(self):
        self.rows = fixture()

    def test_public_fixture_replays_after_real_time_expiration_without_network(self):
        with patch("time.time", return_value=time.time() + 86400 * 365):
            result = replay(self.rows)
        self.assertEqual(result["strict_responses"], 32)
        self.assertEqual(result["signed_strict_responses"], 32)
        self.assertEqual(result["pre_post_case_rows"], 2)
        self.assertEqual(result["log_checkpoints"], 4)
        self.assertEqual(result["packet_contexts_replayed"], 3)
        self.assertEqual(result["unique_wire_packets"], 1)
        self.assertFalse(result["network_required"])
        self.assertNotIn("PRIVATE KEY", json.dumps(self.rows))

    def test_corrupted_signature_is_rejected_even_with_consistent_body_hashes(self):
        preflight = next(row for row in self.rows if "checked_at" in row)
        timed = next(row for row in self.rows if "qps" in row)
        response = dns.message.from_wire(
            bytes.fromhex(timed["expected_response_wire_hex"])
        )
        signatures = response.answer[1]
        signature = signatures[0]
        corrupted = signature.signature[:-1] + bytes([signature.signature[-1] ^ 1])
        signatures.clear()
        signatures.add(signature.replace(signature=corrupted))
        wire = response.to_wire()
        preflight["expected_response_wire_hex"] = wire.hex()
        timed.update(
            expected_response_wire_hex=wire.hex(),
            expected_body_sha256=hashlib.sha256(wire[2:]).hexdigest(),
        )
        with self.assertRaises(dns.dnssec.ValidationFailure):
            replay(self.rows)

    def test_wrong_public_key_is_rejected_after_catalog_hash_is_updated(self):
        public = self.rows[0]["public_fixture"]
        replacement = dns.dnssec.make_dnskey(
            ec.generate_private_key(ec.SECP256R1()).public_key(),
            "ECDSAP256SHA256",
            flags=257,
        )
        lines = public["zone_text"].splitlines()
        public["zone_text"] = (
            "\n".join(
                f"@ IN DNSKEY {replacement}" if " IN DNSKEY " in line else line
                for line in lines
            )
            + "\n"
        )
        public["sha256"] = hashlib.sha256(public["zone_text"].encode()).hexdigest()
        with self.assertRaises(dns.dnssec.ValidationFailure):
            replay(self.rows)

    def test_missing_evidence_cannot_be_reported_as_a_complete_run(self):
        for label, predicate in (
            ("catalog", lambda row: "public_fixture" in row),
            ("completion", lambda row: "comparison_complete" in row),
            ("log-checkpoint", lambda row: row.get("checkpoint") == "after"),
            ("postflight", lambda row: row.get("phase") == "after"),
            ("timed-row", lambda row: "qps" in row),
            ("timing-reference", lambda row: "checked_at" in row),
        ):
            with (
                self.subTest(label=label),
                self.assertRaises((AssertionError, KeyError)),
            ):
                replay([row for row in self.rows if not predicate(row)])

    def test_corrupt_counts_question_fixture_hash_and_logs_fail(self):
        for label in (
            "native-count",
            "loss",
            "question",
            "fixture-hash",
            "logs",
            "unchecked-body",
            "duplicate",
        ):
            rows = copy.deepcopy(self.rows)
            timed = next(row for row in rows if "qps" in row)
            if label == "native-count":
                native = json.loads(timed["native_output"])
                native["queries"] -= 1
                timed["native_output"] = json.dumps(native)
            elif label == "loss":
                timed["lost"] = 1
            elif label == "question":
                timed["query_wire_hex"] = (
                    query_for("nsec", "wrong.example.test.", "A").to_wire().hex()
                )
            elif label == "fixture-hash":
                rows[0]["public_fixture"]["sha256"] = "0" * 64
            elif label == "logs":
                rows[4]["logging_gate"]["knot"]["bytes"] = 1
            elif label == "unchecked-body":
                timed["response_body_verified"] = False
            else:
                rows.insert(-1, copy.deepcopy(timed))
            with (
                self.subTest(label=label),
                self.assertRaises((AssertionError, KeyError)),
            ):
                replay(rows)

    def test_reported_native_metrics_cannot_change_independently(self):
        for field in (
            "qps",
            "mean_us",
            "min_us",
            "max_us",
            "elapsed_seconds",
            "timed_cpu_seconds",
            "timed_cpu_percent",
        ):
            rows = copy.deepcopy(self.rows)
            next(row for row in rows if "qps" in row)[field] += 1
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(AssertionError, "native measurement mismatch"),
            ):
                replay(rows)

    def test_empty_or_duplicate_matrix_dimensions_and_extra_capture_fail(self):
        for field, value in (
            ("repeats", 0),
            ("modes", []),
            ("roles", []),
            ("cases", []),
            ("modes", ["nsec", "nsec"]),
            ("roles", ["knot", "knot"]),
        ):
            rows = copy.deepcopy(self.rows)
            rows = [row for row in rows if "qps" not in row and "checked_at" not in row]
            rows[-1]["comparison_complete"][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(AssertionError),
            ):
                replay(rows)
        rows = copy.deepcopy(self.rows)
        extra = copy.deepcopy(next(row for row in rows if "verification" in row))
        extra["server"] = "hickory"
        rows.insert(-1, extra)
        with self.assertRaisesRegex(AssertionError, "pre/post matrix"):
            replay(rows)

    def test_server_cpu_arithmetic_is_recomputed_from_retained_counters(self):
        from server_cpu import difference

        before = dict(
            hz=100, processes={"1:10": dict(comm="knotd", user_ticks=1, system_ticks=2)}
        )
        after = dict(
            hz=100, processes={"1:10": dict(comm="knotd", user_ticks=2, system_ticks=3)}
        )
        timed = next(row for row in self.rows if "qps" in row)
        timed["server_cpu"] = difference(before, after, timed["queries"])
        replay(self.rows)
        timed["server_cpu"]["total_ns_per_query"] += 1
        with self.assertRaisesRegex(AssertionError, "CPU arithmetic mismatch"):
            replay(self.rows)

    def test_capture_counts_cannot_be_nonpositive_or_duplicate_packets(self):
        for count in (0, -1, True, 20):
            rows = copy.deepcopy(self.rows)
            samples = next(row for row in rows if "verification" in row)["captures"]
            extra = copy.deepcopy(samples[0])
            samples[0]["occurrences"] = 40 - int(count)
            extra["occurrences"] = count
            samples.append(extra)
            with self.subTest(count=count), self.assertRaises(AssertionError):
                replay(rows)


if __name__ == "__main__":
    unittest.main()
