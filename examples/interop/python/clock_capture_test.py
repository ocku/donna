"""Coherent clock endpoints, delayed final processing and strict capture decoding."""

import copy
import json
import subprocess
import unittest

from batched_capture_test import CaptureTest
from recursive_capture import decode


class ClockCaptureTest(unittest.TestCase):
    def test_snapshot_midpoint_and_bounded_retry(self):
        for scenario, attempts in (("normal", 1), ("retry", 2), ("last", 8)):
            run = subprocess.run(
                ["clock_snapshot_test", scenario], text=True, capture_output=True
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            row = json.loads(run.stdout)
            self.assertEqual(row["attempts"], attempts)
            self.assertEqual(row["span_ns"], 200)
            self.assertEqual(row["uncertainty_ns"], 1100)
            self.assertEqual(
                row["monotonic_ns"], 1_000_000_100 + (attempts - 1) * 10_000_000
            )

    def test_eight_incoherent_brackets_fail_closed(self):
        run = subprocess.run(
            ["clock_snapshot_test", "exhausted"], text=True, capture_output=True
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, "")
        self.assertIn("clock snapshot exceeded bounded bracket", run.stderr)
        self.assertIn("clock_calls=24", run.stderr)

    def test_post_receive_delay_is_included_in_coherent_elapsed(self):
        raw, queries, native = CaptureTest().run_capture(
            count=1, binary="batched_load_clock_delay"
        )
        self.assertEqual(raw[:8], b"DNSCAP03")
        self.assertGreaterEqual(native["elapsed_seconds"], 0.6)
        packets = decode(raw, queries, native)
        received = (
            packets[-1]["received_monotonic_ns"] / 1e9
            - native["started_monotonic_seconds"]
        )
        self.assertLess(received, native["elapsed_seconds"] - 0.5)
        self.assertAlmostEqual(
            native["elapsed_seconds"],
            native["ended_monotonic_seconds"] - native["started_monotonic_seconds"],
            places=6,
        )
        self.assertGreaterEqual(packets[0]["clock_uncertainty_seconds"], 0.05)

    def test_clock_jump_elapsed_and_uncertainty_tampering_remain_rejected(self):
        raw, queries, native = CaptureTest().run_capture(count=1)
        for fault in ("wall", "mono", "span", "uncertainty", "attempts", "version"):
            row = copy.deepcopy(native)
            if fault == "wall":
                row["ended_unix_seconds"] += 0.06
            elif fault == "mono":
                row["ended_monotonic_seconds"] += 0.1
            elif fault == "span":
                row["clock_end_span_ns"] = 1_000_001
            elif fault == "uncertainty":
                row["clock_start_uncertainty_ns"] = 0
            elif fault == "attempts":
                row["clock_end_attempts"] = 9
            else:
                row["clock_protocol_version"] = 1
            with self.assertRaises(AssertionError):
                decode(raw, queries, row)

    def test_unsupported_capture_formats_and_missing_clock_metadata_are_rejected(self):
        raw, queries, native = CaptureTest().run_capture(count=1)
        for magic in (b"DNSCAP01", b"DNSCAP02", b"DNSCAP04"):
            with self.subTest(magic=magic), self.assertRaises(AssertionError):
                decode(magic + raw[8:], queries, native)
        for field in (
            "clock_protocol_version",
            "ended_monotonic_seconds",
            "clock_start_span_ns",
            "clock_end_uncertainty_ns",
        ):
            row = copy.deepcopy(native)
            row.pop(field)
            with self.subTest(field=field), self.assertRaises(KeyError):
                decode(raw, queries, row)


if __name__ == "__main__":
    unittest.main()
