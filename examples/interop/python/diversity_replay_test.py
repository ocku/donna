"""Fail-closed completeness, arithmetic and source binding of diversity evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from diversity_fixture import digest, fixture
from diversity_load_test import reference
from diversity_replay import check
from server_cpu import difference


class ReplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.root.joinpath("fixture.db").write_text(fixture())
        cls.root.joinpath("harness").mkdir()
        cls.root.joinpath("harness/example.py").write_bytes(b"checked source")
        cls.root.joinpath("batched_load").write_bytes(b"checked binary")
        cls.root.joinpath("source-manifest.json").write_text("{}")
        refs = {}
        for role in ("current", "knot", "hickory"):
            for phase in ("pre", "post"):
                name = f"{role}-{phase}"
                path = cls.root / (name + ".json")
                path.write_text(json.dumps(reference()))
                refs[name] = digest(path.read_bytes())
        sample = reference()
        before = dict(
            hz=100,
            processes={"1:123": dict(comm="listeners", user_ticks=0, system_ticks=0)},
        )
        after = dict(
            hz=100,
            processes={"1:123": dict(comm="listeners", user_ticks=10, system_ticks=0)},
        )
        rows = []
        for trial in range(2):
            for role in ("current", "knot", "hickory"):
                for mode, body in (("finite", True), ("cycle", True), ("cycle", False)):
                    count = 768 if mode == "finite" else 1536
                    native = dict(
                        queries=count,
                        sent=count,
                        lost=0,
                        qps=count / 2,
                        elapsed_seconds=2,
                        timed_cpu_seconds=1,
                        timed_cpu_percent=50,
                        min_us=1,
                        mean_us=2,
                        max_us=3,
                        response_body_verified=body,
                        outstanding=32,
                    )
                    rows.append(
                        dict(
                            **native,
                            native_output=json.dumps(native),
                            trial=trial,
                            role=role,
                            input_mode=mode,
                            population=768,
                            query_pool_sha256=sample["query_pool_sha256"],
                            response_pool_sha256=sample["response_pool_sha256"],
                            server_cpu=difference(before, after, count),
                        )
                    )
        log = {
            role: dict(bytes=0, sha256=digest(b""))
            for role in ("current", "knot", "hickory")
        }
        cls.record = dict(
            harness_sha256={"example.py": digest(b"checked source")},
            native_binary_sha256=digest(b"checked binary"),
            complete=True,
            population=768,
            repeats=2,
            images={role: "sha256:test" for role in log},
            source_manifest_sha256=digest(b"{}"),
            source_manifest={},
            rows=rows,
            references=refs,
            restarts=[
                dict(trial=t, processes={role: f"{role}-{t}" for role in log})
                for t in range(2)
            ],
            logging=[
                dict(phase=phase, before=log, after=log)
                for phase in ("preflight", "trial-0", "trial-1", "postflight")
            ],
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def replay(self, record):
        self.root.joinpath("result.json").write_text(json.dumps(record))
        return check(self.root)

    def test_complete_matrix_replays_without_network(self):
        row = self.replay(self.record)
        self.assertEqual(row["trials"], 18)
        self.assertEqual(row["strict_trials"], 12)
        self.assertEqual(row["semantic_packets"], 4608)

    def test_incomplete_or_falsified_metrics_and_identity_fail(self):
        for fault in (
            "empty",
            "duplicate",
            "native",
            "qps",
            "cpu",
            "restart",
            "logs",
            "source",
            "refs",
            "repeat-zero",
            "harness",
            "binary",
            "native-empty",
            "native-partial",
        ):
            with self.subTest(fault=fault):
                record = copy.deepcopy(self.record)
                if fault == "empty":
                    record["rows"].clear()
                elif fault == "duplicate":
                    record["rows"][-1] = record["rows"][0]
                elif fault in ("native-empty", "native-partial"):
                    native = json.loads(record["rows"][0]["native_output"])
                    native = (
                        {}
                        if fault == "native-empty"
                        else {k: v for k, v in native.items() if k != "qps"}
                    )
                    record["rows"][0]["native_output"] = json.dumps(native)
                elif fault == "native":
                    record["rows"][0]["qps"] += 1
                elif fault == "qps":
                    row = record["rows"][0]
                    row["qps"] += 1
                    native = json.loads(row["native_output"])
                    native["qps"] = row["qps"]
                    row["native_output"] = json.dumps(native)
                elif fault == "cpu":
                    record["rows"][0]["server_cpu"]["total_ns_per_query"] += 1
                elif fault == "restart":
                    record["restarts"][1]["processes"] = record["restarts"][0][
                        "processes"
                    ]
                elif fault == "logs":
                    record["logging"].pop()
                elif fault == "source":
                    record["source_manifest_sha256"] = "0" * 64
                elif fault == "refs":
                    record["references"].pop("knot-post")
                elif fault == "harness":
                    record["harness_sha256"]["example.py"] = "0" * 64
                elif fault == "binary":
                    record["native_binary_sha256"] = "0" * 64
                else:
                    record["repeats"] = 0
                with self.assertRaises(Exception):
                    self.replay(record)


if __name__ == "__main__":
    unittest.main()
