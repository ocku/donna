"""Fault tests for the bounded wire comparison, independent of server implementations."""

import copy
import json
import unittest

import dns.flags
import dns.message
import dns.rrset

from ingress_wire import catalog, check_rows, normalized, read_exact


def synthetic():
    rows = []
    for role in ("verified", "current", "knot", "hickory"):
        for case in catalog():
            query = bytes.fromhex(case["query"])
            if case["positive"]:
                reply = dns.message.make_response(dns.message.from_wire(query))
                reply.flags |= dns.flags.AA
                reply.answer.append(
                    dns.rrset.from_text(
                        "www.example.test.", 300, "IN", "A", "192.0.2.80"
                    )
                )
            else:
                reply = dns.message.Message(int.from_bytes(query[:2], "big"))
                reply.flags = dns.flags.QR
                reply.use_edns(0, payload=1232)
                reply.set_rcode(
                    case["expected_rcode"] if case["expected_rcode"] is not None else 1
                )
            wire = reply.to_wire()
            for protocol in ("udp", "tcp"):
                row = dict(
                    role=role,
                    case=case["case"],
                    protocol=protocol,
                    query=case["query"],
                    outcome="reply",
                    response=wire.hex(),
                    normalized=normalized(wire),
                    expectation_failed=False,
                )
                if protocol == "tcp":
                    row["response_frame"] = (len(wire).to_bytes(2, "big") + wire).hex()
                    row["received_stream"] = row["response_frame"]
                rows.append(row)
    return rows


class WireTest(unittest.TestCase):
    def test_catalog_has_valid_options_and_compression_only_after_an_earlier_name(self):
        cases = {item["case"]: item for item in catalog()}
        self.assertGreaterEqual(len(cases), 24)
        for name in (
            "classic",
            "edns",
            "unknown-option",
            "padding",
            "dnssec-ok-unsigned",
        ):
            query = dns.message.from_wire(bytes.fromhex(cases[name]["query"]))
            self.assertEqual(len(query.question), 1)
        ixfr = bytes.fromhex(cases["ixfr-malformed-option"]["query"])
        self.assertEqual(int.from_bytes(ixfr[8:10], "big"), 1)
        wire = bytes.fromhex(cases["two-questions-compressed-second"]["query"])
        self.assertIn(b"\xc0\x0c", wire)
        self.assertEqual(len(dns.message.from_wire(wire).question), 2)
        for name in (
            "malformed-option",
            "badvers-malformed-option",
            "truncated-additional-cname",
        ):
            with self.subTest(name=name), self.assertRaises(Exception):
                dns.message.from_wire(bytes.fromhex(cases[name]["query"]))

    def test_partial_tcp_bytes_are_retained_before_eof(self):
        class Peer:
            chunks = iter([b"x", b""])

            def recv(self, length):
                return next(self.chunks)

        captured = bytearray()
        with self.assertRaises(EOFError):
            read_exact(Peer(), 2, captured)
        self.assertEqual(captured, b"x")

    def test_complete_matrix_and_json_round_trip_replay(self):
        rows = synthetic()
        result = check_rows(
            json.loads(json.dumps(rows)), ["verified", "current", "knot", "hickory"]
        )
        self.assertEqual(result["observations"], len(catalog()) * 8)
        self.assertEqual(result["compatibility_pairs"], len(catalog()) * 2)
        self.assertEqual(result["expectation_failures"], [])

    def test_normal_only_matrix_makes_no_candidate_parity_claim(self):
        rows = [row for row in synthetic() if row["role"] != "verified"]
        result = check_rows(rows, ["current", "knot", "hickory"])
        self.assertEqual(result["observations"], len(catalog()) * 6)
        self.assertEqual(result["compatibility_pairs"], 0)

    def test_missing_duplicate_or_falsified_packet_evidence_fails(self):
        for fault in (
            "missing",
            "duplicate",
            "query",
            "id",
            "data",
            "normalized",
            "frame",
            "finding",
            "parity",
        ):
            with self.subTest(fault=fault):
                rows = copy.deepcopy(synthetic())
                if fault == "missing":
                    rows.pop()
                elif fault == "duplicate":
                    rows[-1] = rows[0]
                elif fault == "query":
                    rows[0]["query"] += "00"
                elif fault == "id":
                    rows[0]["response"] = "0000" + rows[0]["response"][4:]
                elif fault == "data":
                    row = rows[0]
                    response = dns.message.from_wire(bytes.fromhex(row["response"]))
                    response.answer[0] = dns.rrset.from_text(
                        "www.example.test.", 300, "IN", "A", "192.0.2.81"
                    )
                    row["response"] = response.to_wire().hex()
                    row["normalized"] = normalized(response.to_wire())
                    row["expectation_failed"] = True
                elif fault == "normalized":
                    rows[0]["normalized"]["rcode"] = 3
                elif fault == "frame":
                    rows[1]["response_frame"] = "0000" + rows[1]["response"]
                elif fault == "finding":
                    rows[0]["expectation_failed"] = True
                else:
                    row = next(
                        r
                        for r in rows
                        if r["role"] == "current"
                        and r["case"] == "trailing-byte"
                        and r["protocol"] == "udp"
                    )
                    row.clear()
                    row.update(
                        role="current",
                        case="trailing-byte",
                        protocol="udp",
                        query=next(
                            c["query"]
                            for c in catalog()
                            if c["case"] == "trailing-byte"
                        ),
                        outcome="timeout",
                        expectation_failed=False,
                    )
                with self.assertRaises(Exception):
                    check_rows(rows, ["verified", "current", "knot", "hickory"])

    def test_peer_finding_is_retained_without_losing_remaining_case_observations(self):
        rows = synthetic()
        for row in rows:
            if row["role"] == "hickory" and row["case"] == "duplicate-opt-v0":
                response = dns.message.from_wire(bytes.fromhex(row["response"]))
                response.set_rcode(16)
                wire = response.to_wire()
                row.update(
                    response=wire.hex(),
                    normalized=normalized(wire),
                    expectation_failed=True,
                )
                if row["protocol"] == "tcp":
                    row["response_frame"] = (len(wire).to_bytes(2, "big") + wire).hex()
                    row["received_stream"] = row["response_frame"]
        result = check_rows(rows, ["verified", "current", "knot", "hickory"])
        self.assertEqual(len(result["expectation_failures"]), 2)
        self.assertEqual(result["observations"], len(catalog()) * 8)


if __name__ == "__main__":
    unittest.main()
