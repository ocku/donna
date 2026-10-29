"""Independent per-query native gate and complete fixture replay fault tests."""

import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest

import dns.message
import dns.rrset

from diversity_fixture import cases, digest, fixture, framed, queries, value
from diversity_load import check_reference, validate


def reference():
    packets = []
    for query, (index, name, kind) in zip(queries(), cases(), strict=True):
        response = dns.message.make_response(dns.message.from_wire(query))
        response.flags = 0x8400
        response.answer.append(
            dns.rrset.from_text(name, 300, "IN", kind, value(index, kind))
        )
        wire = response.to_wire()
        validate(query, wire, (index, name, kind))
        packets.append(dict(query=query.hex(), response=wire.hex()))
    return dict(
        packets=packets,
        fixture_sha256=digest(fixture().encode()),
        query_pool_sha256=digest(framed([bytes.fromhex(p["query"]) for p in packets])),
        response_pool_sha256=digest(
            framed([bytes.fromhex(p["response"]) for p in packets])
        ),
    )


class DiversityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = reference()

    def test_complete_fixture_has_varied_questions_and_exact_singleton_data(self):
        query_wires, replies, flags = check_reference(self.record)
        self.assertEqual(len(set(query_wires)), 768)
        self.assertGreater(len(set(map(len, query_wires))), 10)
        self.assertGreater(len(set(map(len, replies))), 10)
        self.assertEqual(flags, 0x8400)
        self.assertEqual(
            [sum(kind == t for _, _, kind in cases()) for t in ("A", "AAAA", "TXT")],
            [256] * 3,
        )

    def test_offline_replay_rejects_wrong_values_order_count_flags_ttl_and_trailers(
        self,
    ):
        for fault in (
            "value",
            "order",
            "count",
            "flags",
            "ttl",
            "trailer",
            "query",
            "fixture",
            "hash",
        ):
            with self.subTest(fault=fault):
                record = copy.deepcopy(self.record)
                packet = record["packets"][0]
                if fault == "order":
                    record["packets"][0], record["packets"][1] = (
                        record["packets"][1],
                        record["packets"][0],
                    )
                elif fault == "count":
                    record["packets"].pop()
                elif fault in ("value", "flags", "ttl"):
                    response = dns.message.from_wire(bytes.fromhex(packet["response"]))
                    if fault == "flags":
                        response.flags ^= 0x0080
                    elif fault == "ttl":
                        response.answer[0].ttl -= 1
                    else:
                        response.answer.clear()
                    packet["response"] = response.to_wire().hex()
                elif fault == "trailer":
                    packet["response"] += "00"
                elif fault == "query":
                    packet["query"] = record["packets"][1]["query"]
                elif fault == "fixture":
                    record["fixture_sha256"] = "0" * 64
                else:
                    record["response_pool_sha256"] = "0" * 64
                with self.assertRaises(Exception):
                    check_reference(record)

    def native(self, mode, fault=None, window=32):
        packets = self.record["packets"][:97]
        query_wires = [bytes.fromhex(p["query"]) for p in packets]
        replies = [bytes.fromhex(p["response"]) for p in packets]
        lookup = {q[2:]: r for q, r in zip(query_wires, replies, strict=True)}
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer,
            tempfile.TemporaryDirectory() as temp,
        ):
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(0.01)
            root = Path(temp)
            (root / "queries").write_bytes(framed(query_wires))
            reference_wires = replies.copy()
            if fault == "missing":
                reference_wires.pop()
            elif fault == "extra":
                reference_wires.append(replies[0])
            elif fault == "order":
                reference_wires.reverse()
            (root / "responses").write_bytes(framed(reference_wires))
            stop = threading.Event()
            observed = []

            def serve():
                pending = []
                while not stop.is_set():
                    try:
                        wire, destination = peer.recvfrom(65535)
                        observed.append(wire[2:])
                        response = bytearray(lookup[wire[2:]])
                        response[:2] = wire[:2]
                        if fault == "body":
                            response[-1] ^= 1
                        pending.append((response, destination))
                        if len(pending) < window:
                            continue
                    except TimeoutError:
                        pass
                    for response, destination in reversed(pending):
                        peer.sendto(response, destination)
                    pending.clear()

            worker = threading.Thread(target=serve)
            worker.start()
            try:
                result = subprocess.run(
                    [
                        "batched_load",
                        "127.0.0.1",
                        str(peer.getsockname()[1]),
                        ".15" if mode == "cycle" else "2",
                        str(0x8400),
                        str(root / "queries"),
                        mode,
                        "--expected-responses",
                        str(root / "responses"),
                        "--window",
                        str(window),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=4,
                )
            finally:
                stop.set()
                worker.join()
            if not fault:
                self.assertEqual(result.returncode, 0, result.stderr)
                row = json.loads(result.stdout)
                self.assertTrue(row["response_body_verified"])
                self.assertEqual(row["lost"], 0)
                self.assertEqual(row["outstanding"], window)
                self.assertEqual(
                    observed, [query_wires[i % 97][2:] for i in range(row["queries"])]
                )
                self.assertEqual(
                    row["queries"], 97
                ) if mode == "finite" else self.assertGreater(row["queries"], 97)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_finite_and_cyclic_per_query_body_gate_accept_reordered_variable_responses(
        self,
    ):
        for mode in ("finite", "cycle"):
            with self.subTest(mode=mode):
                self.native(mode)

    def test_bounded_windows_preserve_finite_and_cyclic_correlation(self):
        for window in (1, 7, 32):
            for mode in ("finite", "cycle"):
                with self.subTest(window=window, mode=mode):
                    self.native(mode, window=window)
        for window in (0, 33):
            self.native("finite", fault="window", window=window)

    def test_wrong_body_and_malformed_reference_matrix_emit_no_measurement(self):
        for fault in ("body", "missing", "extra", "order"):
            for mode in ("finite", "cycle"):
                with self.subTest(mode=mode, fault=fault):
                    self.native(mode, fault)


if __name__ == "__main__":
    unittest.main()
