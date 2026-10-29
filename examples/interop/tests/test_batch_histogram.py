"""Counter conservation gates must reject corrupted diagnostic evidence."""

import copy
import unittest

from benchmarks.batch_histogram import difference, validate_counts


class HistogramGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = (
            "rx_calls",
            "rx_would_block",
            "rx_interrupted",
            "prepared",
            "sync_some",
            "sync_none",
            "first_attempt",
            "first_sent",
            "first_would_block",
            "first_error",
            "first_expired",
            "send_committed",
            "send_error",
            "deferred",
            "deferred_ready",
            "deferred_pending",
        )
        before = {
            "rx": [0] * 17,
            "dispatch": [0] * 17,
            "send": [0] * 17,
            "counts": dict.fromkeys(names, 0),
        }
        after = copy.deepcopy(before)
        after["rx"][2] = 32
        after["dispatch"][1] = after["send"][1] = 32
        after["counts"].update(
            rx_calls=32,
            prepared=64,
            sync_some=64,
            first_attempt=32,
            first_sent=32,
            send_committed=32,
        )
        cls.rows = [
            dict(
                role="profile",
                outstanding=32,
                before=before,
                after=after,
                delta=difference(before, after),
                native={"queries": 64},
            )
        ]

    def test_valid_counter_sample(self):
        row = self.rows[0]
        validate_counts(
            difference(row["before"], row["after"]), row["native"]["queries"]
        )

    def test_eleven_counter_faults_cannot_pass_conservation(self):
        row = next(
            r for r in self.rows if r["role"] == "profile" and r["outstanding"] == 32
        )
        for fault in range(11):
            delta = copy.deepcopy(row["delta"])
            if fault < 3:
                delta[("rx", "dispatch", "send")[fault]][1] += 1
            else:
                key = (
                    "prepared",
                    "sync_some",
                    "rx_calls",
                    "first_sent",
                    "send_error",
                    "first_would_block",
                    "deferred",
                    "first_expired",
                )[fault - 3]
                delta["counts"][key] += 1
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                validate_counts(delta, row["native"]["queries"])

    def test_counter_reset_and_wrong_histogram_width_are_rejected(self):
        row = next(r for r in self.rows if r["role"] == "profile")
        for fault in ("reset", "width"):
            before, after = copy.deepcopy(row["before"]), copy.deepcopy(row["after"])
            if fault == "reset":
                after["counts"]["rx_calls"] = before["counts"]["rx_calls"] - 1
            else:
                after["rx"].append(0)
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                difference(before, after)


if __name__ == "__main__":
    unittest.main()
