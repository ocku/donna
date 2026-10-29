"""Runtime and source identities must describe the code that the lab executes."""

import contextlib
import hashlib
import importlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from support import daemon
from support.capture_trials import CaptureTrials
from support.evidence import write_record
from support.provenance import harness_hashes, harness_sources


class SourceIdentityTests(unittest.TestCase):
    def test_local_relative_import_cycles_and_explicit_fixture_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pkg").mkdir()
            sources = {
                "driver.py": "import json\nimport third_party\nfrom pkg import entry\n",
                "pkg/__init__.py": "",
                "pkg/entry.py": "from . import helper\n",
                "pkg/helper.py": "import driver\nVALUE = 1\n",
                "zone.db": "explicit non-Python fixture\n",
            }
            for name, text in sources.items():
                (root / name).write_text(text)
            files = harness_sources(root, ["driver.py", "zone.db"])
            self.assertEqual(files, sorted(sources))
            before = harness_hashes(root, files)
            (root / "pkg/helper.py").write_text("import driver\nVALUE = 2\n")
            after = harness_hashes(root, ["driver.py", "zone.db"])
            self.assertNotEqual(before["pkg/helper.py"], after["pkg/helper.py"])
            self.assertEqual(before["driver.py"], after["driver.py"])

    def test_flat_probe_imports_are_bound_and_expanded_files_can_be_archived(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "python").mkdir()
            (root / "driver.py").write_text("import verifier\n")
            (root / "python/verifier.py").write_text("CHECK = True\n")
            sources = harness_sources(root, ["driver.py"])
            expected = harness_hashes(root, sources)
            capsule = root / "capsule"
            for name in sources:
                target = capsule / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((root / name).read_bytes())
            for name, digest in expected.items():
                self.assertEqual(
                    hashlib.sha256((capsule / name).read_bytes()).hexdigest(), digest
                )
            self.assertIn("python/verifier.py", expected)

    def test_missing_or_outside_inputs_fail_before_publishing_a_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                harness_sources(root, ["absent.py"])
            with self.assertRaises(ValueError):
                harness_sources(root, [root.parent / "outside.py"])


class RuntimeIdentityTests(unittest.TestCase):
    def test_cli_image_preflight_is_isolated_and_rejects_old_library_images(self):
        with patch.object(daemon, "docker", return_value="donna 0.1.0") as run:
            daemon.require_cli("candidate-image")
        run.assert_called_once_with(
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            daemon.DAEMON_BINARY,
            "candidate-image",
            "--version",
            capture=True,
        )
        for result in ("other application", RuntimeError("missing binary")):
            with self.subTest(result=result):
                options = (
                    {"side_effect": result}
                    if isinstance(result, Exception)
                    else {"return_value": result}
                )
                with patch.object(daemon, "docker", **options):
                    with self.assertRaisesRegex(RuntimeError, "shipped Donna CLI"):
                        daemon.require_cli("legacy-image")

    def test_hashed_binary_is_the_exact_absolute_program_launched(self):
        commands = []
        daemon.create_recursive(
            "candidate",
            "image",
            "network",
            "192.0.2.1",
            "192.0.2.2:53",
            "192.0.2.0/24",
            run=lambda *args: commands.append(args),
        )
        create = commands[0]
        executable = create[create.index("image") + 1]
        self.assertTrue(Path(executable).is_absolute())
        record = {}
        with patch.object(
            daemon, "docker", return_value="a" * 64 + "  binary\n"
        ) as run:
            daemon.record_runtime_identity(record, "donna", "candidate")
            daemon.record_runtime_identity(record, "donna", "candidate")
            daemon.record_runtime_identity(record, "bind", "peer")
        run.assert_called_once_with(
            "exec", "candidate", "sha256sum", executable, capture=True
        )
        self.assertEqual(record, {"donna_binary_sha256": "a" * 64})
        self.assertEqual(daemon.resolver_port("donna"), daemon.RECURSIVE_PORT)
        self.assertEqual(daemon.resolver_port("bind"), 53)

    @patch("support.capture_trials.time.sleep")
    @patch("support.capture_trials.docker")
    @patch("support.capture_trials.events", return_value=[])
    def test_warm_only_trial_records_runtime_identity_before_native_measurement(
        self, *_
    ):
        with tempfile.TemporaryDirectory() as temporary:
            lab = Mock()
            lab.authority_logs.return_value = {"leaf": ""}
            lab.snapshots.return_value = {"donna": {"usage_usec": 1}}
            record = {"raw_commands": [], "trials": []}
            runner = CaptureTrials(
                SimpleNamespace(seconds=1), lab, record, Path(temporary)
            )

            def command(argv):
                self.assertEqual(record["donna_binary_sha256"], "b" * 64)
                return json.dumps({"queries": 1, "qps": 1})

            runner.command = command
            with patch.object(
                daemon, "docker", return_value="b" * 64 + "  binary\n"
            ) as identity:
                with contextlib.redirect_stdout(io.StringIO()):
                    runner.phase("donna", "warm", 0, "direct", 33152)
            identity.assert_called_once()
            self.assertEqual(len(record["trials"]), 1)


class CandidateDefaultsTests(unittest.TestCase):
    def test_signed_live_drivers_select_cli_image_and_preflight_before_lab_creation(
        self,
    ):
        shared = [
            "--output",
            "result.json",
            "--donna-source-manifest",
            "manifest.json",
            "--donna-source-archive",
            "source.tar.gz",
        ]
        commands = {
            "negative_discovery": shared + ["--baseline-report", "old.json"],
            "negative_compare": shared
            + ["--baseline-report", "old.json", "--discovery-report", "discovery.json"],
            "recursive_compare": shared,
        }
        for name, arguments in commands.items():
            with self.subTest(driver=name):
                module = importlib.import_module("benchmarks." + name)
                captured = []

                def identity(image):
                    captured.append(image)
                    return "sha256:immutable-runtime"

                with (
                    patch.object(sys, "argv", [name, *arguments]),
                    patch.object(module, "identity", side_effect=identity),
                    patch.object(
                        module,
                        "require_cli",
                        side_effect=RuntimeError("preflight stopped"),
                    ) as preflight,
                    patch.object(module, "Lab") as lab,
                ):
                    with self.assertRaisesRegex(RuntimeError, "preflight stopped"):
                        module.main.__wrapped__()
                self.assertIn(daemon.CLI_IMAGE, captured)
                preflight.assert_called_once_with("sha256:immutable-runtime")
                lab.assert_not_called()

    def test_live_candidate_cannot_borrow_historical_source_metadata(self):
        commands = {
            "negative_discovery": ["--baseline-report", "old.json"],
            "negative_compare": [
                "--baseline-report",
                "old.json",
                "--discovery-report",
                "discovery.json",
            ],
            "recursive_compare": [],
        }
        for name, arguments in commands.items():
            with self.subTest(driver=name):
                module = importlib.import_module("benchmarks." + name)
                errors = io.StringIO()
                with (
                    patch.object(
                        sys, "argv", [name, "--output", "result.json", *arguments]
                    ),
                    contextlib.redirect_stderr(errors),
                    patch.object(module, "identity") as identity,
                ):
                    with self.assertRaises(SystemExit) as stopped:
                        module.main.__wrapped__()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn("--donna-source-manifest", errors.getvalue())
                self.assertIn("--donna-source-archive", errors.getvalue())
                identity.assert_not_called()


class EvidenceWriterTests(unittest.TestCase):
    def test_both_sequence_layouts_preserve_json_and_create_the_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            for key in ("rows", "trials"):
                record = {"complete": True, key: [{"item": 1}, {"item": 2}]}
                path = Path(temporary) / key / "result.json"
                write_record(path, record, sequence_key=key)
                self.assertEqual(json.loads(path.read_text()), record)
                self.assertIn('    {"item": 1},\n    {"item": 2}', path.read_text())


if __name__ == "__main__":
    unittest.main()
