"""Bounded capture reserve, exact byte accounting and fail-closed CLI faults."""

import copy
import subprocess
import unittest

from batched_capture_test import CaptureTest
from recursive_capture import decode, LIMIT, MAX_BUDGET


class BudgetTest(unittest.TestCase):
    def test_default_explicit_large_max_and_exact_fit(self):
        raw, queries, native = CaptureTest().run_capture(count=1)
        self.assertEqual(native["capture_budget_bytes"], LIMIT)
        exact = len(raw) - 34
        for budget in (exact, 256 * 1024 * 1024, MAX_BUDGET):
            raw, queries, native = CaptureTest().run_capture(
                count=1, extra=("--capture-budget-bytes", str(budget))
            )
            self.assertEqual(native["capture_budget_bytes"], budget)
            self.assertEqual(len(decode(raw, queries, native)), 1)
        CaptureTest().run_capture(
            count=1,
            extra=("--capture-budget-bytes", str(exact - 1)),
            error="response capture capacity exceeded",
        )

    def test_invalid_missing_duplicate_and_without_capture_budgets(self):
        base = ["batched_load", "127.0.0.1", "53", "1", "33152", "/dev/null"]
        for text in (
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.5",
            "1x",
            "",
            "536870913",
            "18446744073709551616",
        ):
            run = subprocess.run(
                base
                + [
                    "--capture-responses",
                    "/tmp/unwritten",
                    "--capture-budget-bytes",
                    text,
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, "")
            self.assertIn("invalid capture budget", run.stderr)
        for extra in (
            ["--capture-budget-bytes"],
            ["--capture-budget-bytes", "1"],
            [
                "--capture-responses",
                "/tmp/unwritten",
                "--capture-budget-bytes",
                "1",
                "--capture-budget-bytes",
                "1",
            ],
        ):
            run = subprocess.run(base + extra, text=True, capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, "")

    def test_decoder_budget_bounds_and_required_metadata(self):
        raw, queries, native = CaptureTest().run_capture(count=1)
        for budget in (0, -1, MAX_BUDGET + 1, True, "128", len(raw) - 35):
            row = copy.deepcopy(native)
            row["capture_budget_bytes"] = budget
            with self.assertRaises(AssertionError):
                decode(raw, queries, row)
        row = copy.deepcopy(native)
        row.pop("capture_budget_bytes")
        with self.assertRaises(KeyError):
            decode(raw, queries, row)


if __name__ == "__main__":
    unittest.main()
