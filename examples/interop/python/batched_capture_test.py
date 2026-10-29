"""Live finite native capture and independent framing/correlation fault checks."""

import copy
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest

from recursive_capture import decode, compact, read_compact


def inputs(count):
    return [
        bytes.fromhex("beef01000001000000000000")
        + bytes([len(name)])
        + name
        + b"\0\0\1\0\1"
        for name in [f"owner-{index}".encode() for index in range(count)]
    ]


class CaptureTest(unittest.TestCase):
    def run_capture(
        self,
        count=33,
        drop=False,
        cycling=False,
        binary="batched_load",
        extra=(),
        error=None,
    ):
        queries = inputs(count)
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer,
            tempfile.TemporaryDirectory() as temp,
        ):
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(0.01)
            root = Path(temp)
            (root / "queries").write_bytes(
                b"".join(len(q).to_bytes(2, "big") + q for q in queries)
            )
            stop = threading.Event()
            replies = {}

            def serve():
                queued = []
                while not stop.is_set():
                    try:
                        packet, destination = peer.recvfrom(65535)
                        if drop:
                            continue
                        response = bytearray(packet)
                        response[2:4] = b"\x81\x80"
                        response[6:8] = b"\0\1"
                        response.extend(
                            bytes.fromhex("c00c000100010000003c0004c0000250")
                        )
                        replies[bytes(packet[12:])] = bytes(response)
                        queued.append((response, destination))
                        if len(queued) < 32:
                            continue
                    except TimeoutError:
                        pass
                    for response, destination in reversed(queued):
                        peer.sendto(response, destination)
                    queued.clear()

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                run = subprocess.run(
                    [
                        binary,
                        "127.0.0.1",
                        str(peer.getsockname()[1]),
                        ".15" if cycling else "4",
                        str(0x8180),
                        str(root / "queries"),
                        "cycle" if cycling else "finite",
                        "--capture-responses",
                        str(root / "capture"),
                        *extra,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=6,
                )
            finally:
                stop.set()
                thread.join()
            if drop or error:
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "")
                if error:
                    self.assertIn(error, run.stderr)
                self.assertFalse((root / "capture").exists())
                return
            self.assertEqual(run.returncode, 0, run.stderr)
            native = json.loads(run.stdout)
            raw = (root / "capture").read_bytes()
            packets = decode(raw, queries, native)
            self.assertEqual(len(packets), native["queries"])
            self.assertEqual(
                len(packets), count
            ) if not cycling else self.assertGreater(len(packets), count)
            for packet in packets:
                query = queries[packet["index"]]
                self.assertEqual(
                    bytes.fromhex(packet["response"])[2:], replies[query[12:]][2:]
                )
            manifest = compact(root / "capture", root / "compact", queries, native)
            self.assertEqual(manifest["packets"], len(packets))
            self.assertEqual(
                list(read_compact(root / "compact", queries, native)), packets
            )
            return raw, queries, native

    def test_every_finite_response_is_retained_after_reordering(self):
        for count in (1, 33, 512):
            with self.subTest(count=count):
                self.run_capture(count)

    def test_cyclic_pool_capture_is_lossless_after_repeated_inputs(self):
        self.run_capture(33, cycling=True)

    def test_incomplete_run_emits_no_capture_or_metrics(self):
        self.run_capture(drop=True)

    def test_capture_decoder_rejects_truncation_extra_data_indices_ids_and_times(self):
        raw, queries, native = self.run_capture()
        for fault in ("short", "extra", "index", "id", "time", "metric", "clock"):
            with self.subTest(fault=fault):
                data, row = bytearray(raw), copy.deepcopy(native)
                if fault == "short":
                    data.pop()
                elif fault == "extra":
                    data.append(0)
                elif fault == "index":
                    data[34:36] = b"\xff\xff"
                elif fault == "id":
                    data[36:38] = b"\xff\xff"
                elif fault == "time":
                    data[40:48] = struct.pack("!Q", 2**63)
                elif fault == "metric":
                    row["captured_responses"] -= 1
                else:
                    row["ended_unix_seconds"] += 1
                with self.assertRaises(Exception):
                    decode(bytes(data), queries, row)


if __name__ == "__main__":
    unittest.main()
