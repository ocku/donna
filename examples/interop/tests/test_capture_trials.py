"""Capture trials preserve evidence and fail closed before publishing metrics."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from support.capture_trials import CaptureTrials


class CaptureTrialTests(unittest.TestCase):
    def runner(self, root, *, negative=False):
        lab = Mock()
        lab.authority_logs.return_value = {"leaf": ""}
        lab.snapshots.side_effect = [
            {"donna": {"usage_usec": 10}},
            {"donna": {"usage_usec": 25}},
        ]
        args = SimpleNamespace(seconds=1, capture_budget_bytes=128 * 1024 * 1024)
        record = {
            "raw_commands": [],
            "trials": [],
            "donna_binary_sha256": "previously captured runtime identity",
        }
        return CaptureTrials(args, lab, record, root, negative=negative)

    @patch("support.capture_trials.time.sleep")
    @patch("support.capture_trials.docker")
    @patch("support.capture_trials.events", return_value=[])
    def test_cold_recursive_trial_retains_cpu_metadata_and_verified_evidence(self, *_):
        with tempfile.TemporaryDirectory() as temporary:
            runner = self.runner(Path(temporary))
            native = {"queries": 2, "qps": 4}
            runner.command = Mock(side_effect=[json.dumps(native), '{"passed": true}'])
            with contextlib.redirect_stdout(io.StringIO()):
                row = runner.phase("donna", "cold", 0, "direct", 33152)
            invocation = runner.command.call_args_list[0].args[0]
            self.assertIn("finite", invocation)
            self.assertNotIn("--capture-budget-bytes", invocation)
            self.assertEqual(row["resolver_total_usage_since_creation_usec"], 25)
            self.assertEqual(row["cpu_delta"]["donna"]["usage_usec"], 15)
            self.assertTrue(row["verification"]["passed"])
            self.assertEqual(runner.record["trials"], [row])
            self.assertEqual(
                json.loads((Path(temporary) / "donna-cold-0-direct.json").read_text()),
                native,
            )

    @patch("support.capture_trials.time.sleep")
    @patch("support.capture_trials.docker")
    @patch("support.capture_trials.events", return_value=[])
    def test_warm_negative_trial_freezes_preload_and_enforces_capture_budget(self, *_):
        with tempfile.TemporaryDirectory() as temporary:
            runner = self.runner(Path(temporary), negative=True)
            native = {
                "queries": 2,
                "qps": 4,
                "capture_budget_bytes": runner.args.capture_budget_bytes,
            }
            runner.command = Mock(
                side_effect=["{}", json.dumps(native), '{"passed": true}']
            )
            with contextlib.redirect_stdout(io.StringIO()):
                row = runner.phase(
                    "donna",
                    "warm",
                    2,
                    "exact",
                    33152,
                    preload="/suite/preload.json",
                    preload_logs={"leaf": ""},
                )
            freeze, native_call, verify = [
                call.args[0] for call in runner.command.call_args_list
            ]
            self.assertIn("freeze", freeze)
            self.assertIn("/suite/negative_worker.py", verify)
            self.assertIn("cycle", native_call)
            budget = native_call.index("--capture-budget-bytes")
            self.assertEqual(
                int(native_call[budget + 1]), runner.args.capture_budget_bytes
            )
            self.assertIn("preload_log_checkpoints", row)
            self.assertEqual(row["capture"], "donna-warm-2-exact.rcc")
            self.assertEqual(row["expected_response_flags"], 33152)

    @patch("support.capture_trials.time.sleep")
    @patch("support.capture_trials.docker")
    @patch("support.capture_trials.events", return_value=[])
    def test_verification_failure_retains_packets_without_publishing_trial(
        self, _, docker, __
    ):
        with tempfile.TemporaryDirectory() as temporary:
            runner = self.runner(Path(temporary))
            runner.command = Mock(
                side_effect=['{"queries": 2, "qps": 4}', AssertionError("bad response")]
            )
            with self.assertRaisesRegex(AssertionError, "bad response"):
                runner.phase("donna", "warm", 0, "direct", 33152)
            self.assertEqual(runner.record["trials"], [])
            paths = [str(call.args[-1]) for call in docker.call_args_list]
            self.assertTrue(any(path.endswith(".failed.capture") for path in paths))

    @patch("support.capture_trials.subprocess.run")
    def test_failed_command_is_recorded_and_rejected(self, run):
        runner = self.runner(Path("unused"))
        run.return_value = subprocess.CompletedProcess(
            ["failed"], 7, stdout="failure details"
        )
        with self.assertRaisesRegex(AssertionError, "failure details"):
            runner.command(["failed"])
        self.assertEqual(
            runner.record["raw_commands"],
            [{"argv": ["failed"], "exit_code": 7, "output": "failure details"}],
        )


if __name__ == "__main__":
    unittest.main()
