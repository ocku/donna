"""Frozen adapter dependencies and cleanup ownership survive build failures."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from support.paths import ROOT

spec = importlib.util.spec_from_file_location(
    "adapter_build", ROOT / "examples/adapters/remote/engine_build.py"
)
adapter_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter_build)


class AdapterBuildTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = self.directory / "repo"
        for name in (
            "crates", "src", "vendor", "examples/adapters/remote",
            "examples/interop/docker", "examples/interop/python",
            "examples/interop/fixtures",
        ):
            (self.repo / name).mkdir(parents=True, exist_ok=True)
        for name in ("Cargo.toml", "Cargo.lock"):
            (self.repo / name).write_text("fixture\n")
        self.oracle = self.repo / "examples/interop/python/recursive_evidence.py"
        self.oracle.write_text("frozen oracle\n")
        (self.repo / "examples/interop/docker/Peers.Dockerfile").write_text("FROM fixture\n")

    def test_oracle_and_helper_sources_are_frozen_with_the_application(self):
        context, manifest, _ = adapter_build.freeze(self.repo, self.directory / "frozen")
        self.oracle.write_text("later worktree edit\n")
        oracle = "examples/interop/python/recursive_evidence.py"
        helper = "examples/interop/docker/Peers.Dockerfile"
        self.assertIn(oracle, manifest)
        self.assertIn(helper, manifest)
        self.assertEqual((context / oracle).read_text(), "frozen oracle\n")

    def test_owned_image_tags_are_registered_before_either_build_can_fail(self):
        for failing_build in (1, 2):
            with self.subTest(failing_build=failing_build):
                owned = []
                builds = []

                def run(*args):
                    if args[0] == "build":
                        tag = args[args.index("-t") + 1]
                        self.assertIn(tag, owned)
                        self.assertIn("--force-rm", args)
                        builds.append(tag)
                        if len(builds) == failing_build:
                            raise RuntimeError("injected build failure")
                        return ""
                    return json.dumps([{"Id": "fixture-builder"}])

                with self.assertRaisesRegex(RuntimeError, "injected build failure"):
                    adapter_build.build(
                        self.repo,
                        self.directory / f"failed-{failing_build}",
                        run,
                        "fixture",
                        owned,
                    )
                self.assertEqual(len(builds), failing_build)
                self.assertEqual(set(owned), {"fixture:local", "fixture-builder:local"})


if __name__ == "__main__":
    unittest.main()
