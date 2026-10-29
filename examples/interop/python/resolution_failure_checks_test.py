"""Fault injection for failure-cache evidence gates; standard library only."""

import unittest
from resolution_failure_checks import traffic_matches, validate

NAME = "servfail.example.test."


class FailureGateTests(unittest.TestCase):
    def reply(self, cd=False, answer=(), rcode=2):
        return {
            "rcode": rcode,
            "flags": 0x180 | (0x10 if cd else 0),
            "answer": list(answer),
        }

    def test_valid_failure_and_cd(self):
        for cd in (False, True):
            validate(NAME, "A", cd, 2, self.reply(cd))

    def test_rejects_wrong_rcode_or_invented_data(self):
        for response in (
            self.reply(rcode=0),
            self.reply(answer=[(NAME, "A", "IN", "192.0.2.90")]),
        ):
            with self.assertRaises(AssertionError):
                validate(NAME, "A", False, 2, response)

    def test_flags_and_cd_must_match_client(self):
        for flags in (
            0x80,
            0x100,
            0x180 | 0x400,
            0x180 | 0x20,
            0x180 | 0x200,
            0x180 | 0x10,
        ):
            response = self.reply()
            response["flags"] = flags
            with self.assertRaises(AssertionError):
                validate(NAME, "A", False, 2, response)

    def test_recovery_and_qtype_data_are_exact(self):
        validate(
            NAME,
            "A",
            False,
            0,
            self.reply(answer=[(NAME, "A", "IN", "192.0.2.90")], rcode=0),
        )
        validate(
            NAME,
            "AAAA",
            False,
            0,
            self.reply(answer=[(NAME, "AAAA", "IN", "2001:db8::90")], rcode=0),
        )
        for answer in (
            [],
            [(NAME, "A", "CH", "192.0.2.90")],
            [(NAME, "A", "IN", "192.0.2.80")],
            [("other.test.", "A", "IN", "192.0.2.90")],
        ):
            with self.assertRaises(AssertionError):
                validate(NAME, "A", False, 0, self.reply(answer=answer, rcode=0))

    def test_reuse_requires_zero_traffic_and_cold_requires_new_traffic(self):
        before = {NAME + "/A": 1}
        self.assertTrue(traffic_matches(before, before, NAME, True))
        self.assertFalse(traffic_matches(before, before, NAME, False))
        after = {NAME + "/A": 2}
        self.assertFalse(traffic_matches(before, after, NAME, True))
        self.assertTrue(traffic_matches(before, after, NAME, False))
        self.assertFalse(traffic_matches(before, {NAME + "/A": 0}, NAME, False))


if __name__ == "__main__":
    unittest.main()
