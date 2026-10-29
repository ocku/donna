"""Fault-inject a synthetic capsule, or a temporary copy of an explicit corpus."""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from service_memory_replay import verify
from test_fixtures.memory import write_capsule

CAPSULE_ROOT = None


class ReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="donna-memory-oracle-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name) / "capsule"
        source = CAPSULE_ROOT or os.environ.get("DONNA_SERVICE_MEMORY_CAPSULE")
        if source is None:
            write_capsule(cls.root)
        else:
            shutil.copytree(source, cls.root)
        cls.path = cls.root / "result.json"
        cls.original = cls.path.read_bytes()
        cls.record = json.loads(cls.original)

    def tearDown(self):
        self.path.write_bytes(self.original)

    def reject(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        self.path.write_text(json.dumps(record))
        with self.assertRaises((AssertionError, KeyError, ValueError)):
            verify(self.root)

    def test_complete_corpus(self):
        self.assertEqual(verify(self.root)["exact_warm_replies"], 276480)

    def test_matrix_identity_and_warm_counts(self):
        self.reject(lambda r: r["rows"].pop())
        self.reject(
            lambda r: r["rows"][1].update(container_id=r["rows"][0]["container_id"])
        )
        self.reject(lambda r: r["rows"][0]["workload"].update(exact_bodies=30719))
        self.reject(lambda r: r["rows"][0]["workload"]["rows"][0].update(stdout="{}"))

    def test_accounting_observer_and_summary(self):
        def sample(r):
            return r["rows"][0]["warm"][0]

        self.reject(
            lambda r: sample(r)["observer"].update(cgroup=sample(r)["service_cgroup"])
        )
        self.reject(lambda r: sample(r)["process_totals"].update(pss_bytes=1))
        self.reject(lambda r: sample(r)["cgroup_after"]["events"].update(oom_kill=1))
        self.reject(
            lambda r: r["summary"]["donna"]["warm"]["rss_bytes"].update(median=1)
        )

    def test_sources_and_logging(self):
        self.reject(lambda r: r.update(native_binary_sha256="0" * 64))
        self.reject(lambda r: r["rows"][0]["logging"].update(after_sha256="0" * 64))

    def test_import_preserves_command_line_arguments(self):
        code = (
            "import sys; sys.argv = ['runner', 'unchanged']; "
            "import service_memory_replay_test; "
            "assert sys.argv == ['runner', 'unchanged']"
        )
        run = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_explicit_corpus_is_copied_before_fault_injection(self):
        with tempfile.TemporaryDirectory(prefix="donna-memory-source-") as temporary:
            source = Path(temporary) / "source"
            shutil.copytree(self.root, source)
            original = {
                path.relative_to(source): path.read_bytes()
                for path in source.rglob("*")
                if path.is_file()
            }
            run = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    str(source),
                    "ReplayTest.test_sources_and_logging",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(
                original,
                {
                    path.relative_to(source): path.read_bytes()
                    for path in source.rglob("*")
                    if path.is_file()
                },
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "capsule",
        nargs="?",
        type=Path,
        help="copy and fault-inject an existing measured capsule",
    )
    options, remaining = parser.parse_known_args()
    CAPSULE_ROOT = options.capsule
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
