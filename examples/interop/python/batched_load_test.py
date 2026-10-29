"""Exercise the diagnostic executable against a deliberately faulty UDP peer.

Run in the cache-client image: python /suite/batched_load_test.py.
This checks measurement integrity independently of either DNS implementation.
"""

import json
import contextlib
import io
import socket
import subprocess
import tempfile
import threading
import unittest


class BatchedLoadTest(unittest.TestCase):
    def run_peer(
        self,
        mutation=None,
        queries=None,
        cycling=False,
        python_driver=False,
        verify_body=False,
    ):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(0.05)
            stop = threading.Event()
            observed = []
            delayed = []

            def serve():
                while not stop.is_set():
                    try:
                        wire, address = peer.recvfrom(65535)
                    except TimeoutError:
                        if cycling and delayed:
                            for packet, destination in reversed(delayed):
                                peer.sendto(packet, destination)
                            delayed.clear()
                        continue
                    observed.append(wire[12:])
                    reply = bytearray(wire)
                    reply[2:4] = bytes.fromhex("8180")
                    if verify_body or (mutation and mutation.startswith("answer-")):
                        reply[6:8] = b"\x00\x01"
                        reply.extend(bytes.fromhex("c00c000100010000003c0004c0000250"))
                    if mutation == "flags":
                        reply[3] ^= 3
                    elif mutation == "question":
                        reply[13] ^= 1
                    elif mutation == "id":
                        reply[0] ^= 1
                    elif mutation == "short":
                        reply = reply[:1]
                    elif mutation == "drop":
                        continue
                    elif mutation == "answer-address":
                        reply[-1] ^= 1
                    elif mutation == "answer-type":
                        reply[-14:-12] = b"\x00\x10"
                    elif mutation == "answer-missing":
                        reply[6:8] = b"\x00\x00"
                        reply = reply[:-16]
                    elif mutation == "answer-extra":
                        reply[6:8] = b"\x00\x02"
                        reply.extend(reply[-16:])
                    elif mutation == "answer-under-load" and 64 <= len(observed) <= 96:
                        reply[-1] ^= 1
                    if mutation == "reorder":
                        delayed.append((reply, address))
                        if len(delayed) < 32 and len(observed) != len(queries):
                            continue
                        for packet, destination in reversed(delayed):
                            peer.sendto(packet, destination)
                        delayed.clear()
                    else:
                        peer.sendto(reply, address)
                    if mutation == "duplicate":
                        peer.sendto(reply, address)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with (
                    tempfile.NamedTemporaryFile() as query,
                    tempfile.NamedTemporaryFile() as expected,
                ):
                    if queries is None:
                        query.write(
                            bytes.fromhex("12340100000100000000000001610000010001")
                        )
                    else:
                        for wire in queries:
                            query.write(len(wire).to_bytes(2, "big") + wire)
                    query.flush()
                    command = [
                        "batched_load",
                        "127.0.0.1",
                        str(peer.getsockname()[1]),
                        ".3" if cycling else (".05" if queries is None else "3"),
                        str(0x8180),
                        query.name,
                    ]
                    if queries is not None:
                        command.append("cycle" if cycling else "finite")
                    if verify_body:
                        template = bytearray(
                            bytes.fromhex("12348180000100010000000001610000010001")
                        )
                        template.extend(
                            bytes.fromhex("c00c000100010000003c0004c0000250")
                        )
                        expected.write(template)
                        expected.flush()
                        command += ["--expected-response", expected.name]
                    if python_driver:
                        import dns.message
                        from cache_load import measure

                        prepared = [
                            (dns.message.from_wire(wire), wire, 0)
                            for wire in (
                                queries
                                or [
                                    bytes.fromhex(
                                        "12340100000100000000000001610000010001"
                                    )
                                ]
                            )
                        ]
                        output = io.StringIO()
                        with contextlib.redirect_stdout(output):
                            measure(
                                "fixture",
                                peer.getsockname(),
                                prepared,
                                "positive",
                                0,
                                0.05,
                                query_format="classic",
                                load_client="batched",
                                expected_response_wire=bytes(template)
                                if verify_body
                                else None,
                            )
                        result = subprocess.CompletedProcess(
                            command, 0, output.getvalue(), ""
                        )
                    else:
                        result = subprocess.run(
                            command, capture_output=True, text=True, timeout=5
                        )
                    result.observed = observed.copy()
                    return result
            finally:
                stop.set()
                thread.join()

    def test_complete_correlated_run(self):
        result = self.run_peer()
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)
        self.assertGreater(row["queries"], 32)
        self.assertEqual(row["queries"], row["sent"])
        self.assertEqual(row["lost"], 0)
        self.assertGreater(row["qps"], 0)
        self.assertGreaterEqual(row["elapsed_seconds"], 0.05)
        self.assertLessEqual(row["min_us"], row["mean_us"])
        self.assertLessEqual(row["mean_us"], row["max_us"])

    def test_faults_fail_the_run(self):
        for mutation in ("flags", "question", "id", "short", "duplicate", "drop"):
            with self.subTest(mutation=mutation):
                result = self.run_peer(mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_every_response_body_matches_the_validated_authority_packet(self):
        result = self.run_peer(verify_body=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["response_body_verified"])
        for mutation in (
            "answer-address",
            "answer-type",
            "answer-missing",
            "answer-extra",
            "answer-under-load",
        ):
            with self.subTest(mutation=mutation):
                # Each fault preserves IDs, flags and questions: the historical
                # correlation gate accepts it, but the strict body gate rejects it.
                weak = self.run_peer(mutation)
                self.assertEqual(weak.returncode, 0, weak.stderr)
                result = self.run_peer(mutation, verify_body=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("response body mismatch", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_python_driver_enforces_body_gate_and_retains_actual_reference(self):
        result = self.run_peer(python_driver=True, verify_body=True)
        row = json.loads(result.stdout)
        self.assertTrue(row["response_body_verified"])
        self.assertEqual(
            len(bytes.fromhex(row["expected_response_wire_hex"])),
            row["expected_response_bytes"],
        )
        with self.assertRaisesRegex(RuntimeError, "response body mismatch"):
            self.run_peer("answer-under-load", python_driver=True, verify_body=True)

    def test_finite_queries_are_sent_once_with_variable_lengths_and_reordered_replies(
        self,
    ):
        for count in [1, 7, 32, 33, 97, 2048]:
            for mutation in [None, "reorder"]:
                with self.subTest(count=count, mutation=mutation):
                    queries = [
                        bytes.fromhex("123401000001000000000000")
                        + bytes([len(label)])
                        + label
                        + bytes.fromhex("0000010001")
                        for label in [f"owner-{i}".encode() for i in range(count)]
                    ]
                    result = self.run_peer(mutation, queries)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    row = json.loads(result.stdout)
                    self.assertEqual(row["queries"], count)
                    self.assertEqual(row["sent"], count)
                    self.assertEqual(row["lost"], 0)
                    self.assertCountEqual(
                        result.observed, [wire[12:] for wire in queries]
                    )
                    self.assertGreater(row["timed_cpu_seconds"], 0)
                    self.assertGreater(row["timed_cpu_percent"], 0)

    def test_cyclic_pool_preserves_variable_questions_across_wraps_and_reordering(self):
        for count in [1, 7, 32, 33, 97, 2048]:
            queries = [
                bytes.fromhex("123401000001000000000000")
                + bytes([len(label)])
                + label
                + bytes.fromhex("0000010001")
                for label in [f"owner-{i}".encode() for i in range(count)]
            ]
            for mutation in [None, "reorder"]:
                with self.subTest(count=count, mutation=mutation):
                    result = self.run_peer(mutation, queries, cycling=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    row = json.loads(result.stdout)
                    self.assertGreater(row["queries"], count)
                    self.assertEqual(row["queries"], row["sent"])
                    self.assertEqual(row["lost"], 0)
                    self.assertEqual(
                        result.observed,
                        [queries[i % count][12:] for i in range(row["queries"])],
                    )
                    self.assertGreaterEqual(row["elapsed_seconds"], 0.3)

    def test_python_driver_runs_the_same_bounded_cyclic_pool(self):
        queries = [
            bytes.fromhex("123401000001000000000000")
            + bytes([len(label)])
            + label
            + bytes.fromhex("0000010001")
            for label in [f"owner-{i}".encode() for i in range(33)]
        ]
        result = self.run_peer(queries=queries, cycling=True, python_driver=True)
        row = json.loads(result.stdout)
        self.assertEqual(row["input_mode"], "cycle")
        self.assertEqual(row["population"], 33)
        self.assertEqual(row["outstanding"], 32)
        self.assertGreater(row["queries"], 33)
        self.assertEqual(row["queries"], row["sent"])
        self.assertEqual(row["lost"], 0)

    def test_cyclic_faults_fail_without_a_measurement(self):
        queries = [bytes.fromhex("12340100000100000000000001610000010001")] * 33
        for mutation in ["flags", "question", "id", "short", "duplicate", "drop"]:
            with self.subTest(mutation=mutation):
                result = self.run_peer(mutation, queries, cycling=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_finite_faults_and_malformed_files_fail_without_a_measurement(self):
        query = bytes.fromhex("12340100000100000000000001610000010001")
        for mutation in ["flags", "question", "id", "short", "duplicate", "drop"]:
            with self.subTest(mutation=mutation):
                result = self.run_peer(mutation, [query] * 33)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        for wire in [
            b"",
            b"x",
            b"\x00\x20short",
            (len(query).to_bytes(2, "big") + query) * 2049,
        ]:
            with self.subTest(size=len(wire)), tempfile.NamedTemporaryFile() as file:
                file.write(wire)
                file.flush()
                result = subprocess.run(
                    [
                        "batched_load",
                        "127.0.0.1",
                        "9",
                        "1",
                        str(0x8180),
                        file.name,
                        "finite",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
