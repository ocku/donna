"""Check report completeness when a recursive comparison adds another peer."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent


class ReportGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((DIRECTORY / "results/2026-10-29.json").read_text())

    def summarize(self, report):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report))
            return subprocess.run(
                [sys.executable, str(DIRECTORY / "summarize.py"), str(path)],
                capture_output=True,
                text=True,
            )

    def extended_report(self):
        report = copy.deepcopy(self.original)
        report["arguments"]["phases"] = ["recursive"]
        report.pop("cli")
        report["roles"] = {
            "recursive": ["donna", "bind", "kresd", "hickory", "unbound"]
        }
        # Synthetic rows exercise validation, not measured Unbound performance.
        for phase in ("recursive", "cold"):
            report[phase] += [
                row | {"server": "unbound"}
                for row in report[phase]
                if row["server"] == "donna"
            ]
        return report

    def test_original_report_remains_supported(self):
        result = self.summarize(self.original)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_additional_recursive_peer(self):
        result = self.summarize(self.extended_report())
        self.assertEqual(result.returncode, 0, result.stderr)
        for case in ("positive", "negative", "cname"):
            self.assertIn(f"| unbound | {case} |", result.stdout)
        self.assertIn("| unbound |", result.stdout.split("Cold median ms")[1])

    def test_missing_or_duplicate_trials_fail(self):
        for phase in ("recursive", "cold"):
            for duplicate in (False, True):
                with self.subTest(phase=phase, duplicate=duplicate):
                    report = self.extended_report()
                    removed = report[phase].pop()
                    if duplicate:
                        replacement = next(
                            row
                            for row in report[phase]
                            if row["server"] == removed["server"]
                            and row.get("workload") == removed.get("workload")
                        )
                        report[phase].append(replacement)
                    self.assertNotEqual(self.summarize(report).returncode, 0)

    def test_failed_unbound_gate_fails(self):
        for field, value in (("lost", 1), ("semantic_pre_post_checks", "FAIL")):
            with self.subTest(field=field):
                report = self.extended_report()
                report["recursive"][-1][field] = value
                self.assertNotEqual(self.summarize(report).returncode, 0)


if __name__ == "__main__":
    unittest.main()
