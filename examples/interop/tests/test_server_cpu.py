import unittest

from support.server_cpu import parse_processes, difference


def stat(pid, name, user, system, start=99):
    values = ["S"] + ["0"] * 40
    values[11], values[12], values[19] = str(user), str(system), str(start)
    return f"{pid} ({name}) " + " ".join(values)


class ServerCpuTests(unittest.TestCase):
    def test_all_server_processes_and_worker_names_are_counted(self):
        text = "\n".join(
            [
                stat(1, "nsd: main", 1, 2),
                stat(2, "nsd: server 1", 3, 4),
                stat(3, "cat", 500, 500),
                "cpu 1 2 3 4",
            ]
        )
        processes = parse_processes(text)
        self.assertEqual(len(processes), 2)
        self.assertEqual(sum(p["user_ticks"] for p in processes.values()), 4)
        hickory = parse_processes(stat(4, "hickory-dns", 8, 9))
        self.assertEqual(hickory["4:99"]["user_ticks"], 8)

    def test_cpu_delta_and_tick_quantization_use_completed_queries(self):
        before = {"hz": 100, "processes": parse_processes(stat(1, "listeners", 2, 4))}
        after = {"hz": 100, "processes": parse_processes(stat(1, "listeners", 12, 24))}
        result = difference(before, after, 100_000)
        self.assertEqual(result["total_ns_per_query"], 3000)
        self.assertEqual(result["quantization_ns_per_query"], 100)
        self.assertEqual(result["rounding_bound_ns_per_query"], 200)

    def test_process_restart_clock_changes_and_invalid_counts_are_rejected(self):
        before = {"hz": 100, "processes": parse_processes(stat(1, "listeners", 2, 4))}
        variants = [
            {
                "hz": 100,
                "processes": parse_processes(stat(1, "listeners", 12, 24, start=100)),
            },
            {"hz": 1000, "processes": before["processes"]},
            {"hz": 100, "processes": parse_processes(stat(1, "listeners", 1, 4))},
        ]
        for after in variants:
            with self.assertRaises(ValueError):
                difference(before, after, 100)
        before_workers = {
            "hz": 100,
            "processes": parse_processes(
                stat(1, "nsd", 10, 4) + "\n" + stat(2, "nsd: worker", 1, 1)
            ),
        }
        after_workers = {
            "hz": 100,
            "processes": parse_processes(
                stat(1, "nsd", 9, 4) + "\n" + stat(2, "nsd: worker", 3, 1)
            ),
        }
        with self.assertRaises(ValueError):
            difference(before_workers, after_workers, 100)
        with self.assertRaises(ValueError):
            difference(before, before, 0)

    def test_missing_or_malformed_server_processes_cannot_report_zero_cost(self):
        for text in ["", stat(1, "cat", 5, 5), "1 (listeners) R 0"]:
            with self.assertRaises(ValueError):
                parse_processes(text)


if __name__ == "__main__":
    unittest.main()
