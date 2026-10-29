"""Run standalone oracle tests with explicit host or Linux-native prerequisites."""

import argparse
import shutil
import sys
import unittest

from support.paths import SUITE

NATIVE_MODULES = frozenset(
    {
        "batched_capture_test",
        "batched_load_test",
        "capture_budget_test",
        "clock_capture_test",
        "diversity_load_test",
    }
)
NATIVE_BINARIES = (
    "batched_load",
    "batched_load_clock_delay",
    "clock_snapshot_test",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("host", "native", "all"), default="host")
    parser.add_argument(
        "--list", action="store_true", help="list selected test modules"
    )
    args = parser.parse_args()
    modules = sorted(path.stem for path in (SUITE / "python").glob("*_test.py"))
    if args.scope == "host":
        modules = [name for name in modules if name not in NATIVE_MODULES]
    elif args.scope == "native":
        modules = [name for name in modules if name in NATIVE_MODULES]
    if args.scope != "native":
        modules.append("engine_verify_test")
    if args.list:
        print("\n".join(modules))
        return
    if args.scope != "host":
        missing = [name for name in NATIVE_BINARIES if shutil.which(name) is None]
        if missing:
            parser.error(
                "native scope requires executables on PATH: " + ", ".join(missing)
            )
    # Production containers copy server_cpu.py into /suite. The host keeps its
    # single implementation in support; both layouts resolve the same module.
    sys.path[:0] = [
        str(SUITE / "python"),
        str(SUITE / "support"),
        str(SUITE.parent / "adapters" / "remote"),
    ]
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
