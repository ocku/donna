"""Synthetic accounting fixtures; not a live service RAM measurement."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import service_memory as memory
import service_memory_fixture as fixture
import struct
import ipaddress


def stat(pid, comm, start=100, threads=1):
    fields = ["0"] * 20
    fields[0], fields[1], fields[17], fields[19] = "S", "1", str(threads), str(start)
    return f"{pid} ({comm}) " + " ".join(fields)


def rollup(rss, pss):
    return (
        "00400000-00800000 ---p 00000000 00:00 0 [rollup]\n"
        f"Rss: {rss} kB\nPss: {pss} kB\n"
        f"Private_Clean: {rss // 5} kB\nPrivate_Dirty: {rss // 10} kB\n"
        f"Shared_Clean: {rss * 4 // 10} kB\nShared_Dirty: {rss * 3 // 10} kB\n"
        "Swap: 0 kB\nPss_Anon: 1 kB\n"
    )


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.proc, self.groups = root / "proc", root / "cgroups"
        for name, pids in [
            ("target", "1"),
            ("target/workers", "8"),
            ("observer", "12"),
        ]:
            group = self.groups / name
            group.mkdir(parents=True)
            for filename, value in {
                "cgroup.procs": pids,
                "memory.current": "123456",
                "memory.peak": "234567",
                "memory.max": "268435456",
                "memory.stat": "anon 100000\nfile 20000\nkernel 3456\n",
                "memory.events": "oom 0\noom_kill 0\n",
            }.items():
                (group / filename).write_text(value)
        for pid, name, group, rss, pss, threads in [
            (1, "manager", "target", 100, 60, 1),
            (8, "worker ) sample", "target/workers", 200, 100, 17),
            (12, "observer", "observer", 999, 888, 1),
        ]:
            path = self.proc / str(pid)
            path.mkdir(parents=True)
            (path / "stat").write_text(stat(pid, name, threads=threads))
            (path / "cgroup").write_text("0::/" + group + "\n")
            (path / "smaps_rollup").write_text(rollup(rss, pss))
            (path / "ns").mkdir()
            (path / "ns/pid").symlink_to("pid:[123]")
            (path / "ns/cgroup").symlink_to(
                "cgroup:[789]" if pid == 12 else "cgroup:[456]"
            )
            (path / "exe").symlink_to("/usr/bin/" + ("worker" if pid == 8 else name))

    def test_process_units_sharing_roles_and_observer_exclusion(self):
        result = memory.sample(
            self.proc, self.groups, 1, 12, {"manager": "manager", "worker": "workers"}
        )
        self.assertEqual([r["pid"] for r in result["processes"]], [1, 8])
        self.assertEqual(result["process_totals"]["rss_bytes"], 300 * 1024)
        self.assertEqual(result["process_totals"]["pss_bytes"], 160 * 1024)
        self.assertEqual(
            result["process_totals_by_role"]["manager"]["rss_bytes"], 100 * 1024
        )
        self.assertEqual(
            result["process_totals_by_role"]["workers"]["rss_bytes"], 200 * 1024
        )
        self.assertEqual(result["processes"][1]["threads"], 17)
        self.assertEqual(result["cgroup_after"]["current_bytes"], 123456)
        self.assertEqual(result["observer"]["process_metrics"]["rss_bytes"], 999 * 1024)
        self.assertFalse(result["observer"]["charged_to_service"])
        self.assertLessEqual(
            result["started_monotonic_ns"], result["ended_monotonic_ns"]
        )

    def test_same_or_descendant_observer_cgroup_is_not_subtracted_or_mislabeled(self):
        for path in ["/target", "/target/observer"]:
            (self.proc / "12/cgroup").write_text("0::" + path)
            with self.subTest(path=path), self.assertRaises(memory.InvalidSample):
                memory.sample(self.proc, self.groups, 1, 12)

    def test_missing_smaps_and_wrong_units_fail_without_vmrss_fallback(self):
        original = self.proc / "8/smaps_rollup"
        for value in [
            rollup(200, 100).replace("Rss:", "NotRss:"),
            rollup(200, 100).replace("200 kB", "200 MB"),
            rollup(200, 100) + "Pss: 1 kB\n",
        ]:
            original.write_text(value)
            with self.subTest(value=value), self.assertRaises(memory.InvalidSample):
                memory.sample(self.proc, self.groups, 1, 12)

    def test_cgroup_membership_and_pid_reuse_are_detected(self):
        original = memory.text
        seen = 0

        def read(path, *args, **kwargs):
            nonlocal seen
            value = original(path, *args, **kwargs)
            if Path(path) == self.proc / "8/stat":
                seen += 1
                if seen == 2:
                    return stat(8, "replacement", start=999, threads=17)
            return value

        with (
            patch.object(memory, "text", side_effect=read),
            self.assertRaises(memory.InvalidSample),
        ):
            memory.sample(self.proc, self.groups, 1, 12)
        (self.groups / "target/cgroup.procs").write_text("1 12")
        with self.assertRaises(memory.InvalidSample):
            memory.sample(self.proc, self.groups, 1, 12)

    def test_literal_paths_and_stat_fields_are_validated(self):
        parsed = memory.process_stat(
            stat(8, "a strange ) process", start=987, threads=17)
        )
        self.assertEqual(
            (parsed["pid"], parsed["comm"], parsed["start_ticks"], parsed["threads"]),
            (8, "a strange ) process", 987, 17),
        )
        for bad in [
            "cpu:/x",
            "0::/../target",
            "0::/a/./b",
            "0:://target",
            "0::/a\n0::/b",
        ]:
            with self.subTest(value=bad), self.assertRaises(memory.InvalidSample):
                memory.unified_path(bad)
        for value in ["-1", "1.5", "max", ""]:
            with self.subTest(value=value), self.assertRaises(memory.InvalidSample):
                memory.number(value)

    def test_shared_fixture_and_query_working_set_are_exact(self):
        zone, framed, cases = fixture.fixture()
        self.assertEqual(len(cases), 768)
        self.assertEqual(len({case["owner_index"] for case in cases}), 256)
        self.assertEqual(
            len([line for line in zone.splitlines() if line.startswith(b"owner-")]),
            12288,
        )
        self.assertEqual({case["kind"] for case in cases}, {"A", "AAAA", "TXT"})
        cursor = 0
        for case in cases:
            length = int.from_bytes(framed[cursor : cursor + 2], "big")
            cursor += 2
            packet = framed[cursor : cursor + length]
            cursor += length
            self.assertEqual(struct.unpack("!6H", packet[:12]), (0xBEEF, 0, 1, 0, 0, 1))
            at, labels = 12, []
            while packet[at]:
                size = packet[at]
                self.assertLessEqual(size, 63)
                labels.append(packet[at + 1 : at + 1 + size])
                at += size + 1
            at += 1
            self.assertEqual(b".".join(labels).decode("ascii") + ".", case["name"])
            self.assertEqual(
                struct.unpack("!2H", packet[at : at + 4]),
                ({"A": 1, "AAAA": 28, "TXT": 16}[case["kind"]], 1),
            )
            self.assertEqual(packet[at + 4 :], bytes.fromhex("00002904d0000000000000"))
            self.assertIn(
                f"{case['name']} IN {case['kind']} {case['expected']}\n".encode(), zone
            )
            if case["kind"] == "A":
                self.assertEqual(
                    ipaddress.IPv4Address(case["expected"]).packed,
                    bytes(
                        [198, 18, case["owner_index"] // 256, case["owner_index"] % 256]
                    ),
                )
            elif case["kind"] == "AAAA":
                self.assertEqual(
                    int(ipaddress.IPv6Address(case["expected"])),
                    int(ipaddress.IPv6Address("2001:db8::")) + case["owner_index"] + 1,
                )
        self.assertEqual(cursor, len(framed))
        self.assertEqual(fixture.fixture()[:2], (zone, framed))


if __name__ == "__main__":
    unittest.main()
