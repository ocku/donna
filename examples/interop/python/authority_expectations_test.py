"""Fault injection for authority gates; standard library only, no network."""

import argparse
import unittest

from authority_expectations import APEX, CASES, validate
from upstream_authority import endpoint


def reply_for(case):
    return {
        "rcode": case.rcode,
        "aa": not case.referral,
        "tc": False,
        "answer": list(case.answer),
        "soas": [(APEX, "IN", 30, 30)] if case.negative else [],
        "nameservers": [("cut.example.test.", "IN", "ns.cut.example.test.")]
        if case.referral
        else [],
        "additional": [("ns.cut.example.test.", "IN", "A", "192.0.2.54")]
        if case.referral
        else [],
    }


class AuthorityExpectationTests(unittest.TestCase):
    def test_accept_each_expected_shape(self):
        for case in CASES:
            with self.subTest(case=case):
                validate(case, reply_for(case))

    def rejects(self, case, key, value):
        reply = reply_for(case)
        reply[key] = value
        with self.assertRaises(AssertionError):
            validate(case, reply)

    def test_ent_is_not_nxdomain(self):
        case = next(c for c in CASES if c.name == "branch.example.test.")
        self.rejects(case, "rcode", 3)

    def test_closest_encloser_blocks_apex_wildcard(self):
        for case in CASES:
            if case.negative and not case.answer:
                with self.subTest(case=case):
                    self.rejects(case, "answer", [(case.name, "A", "192.0.2.80")])

    def test_cname_negative_keeps_alias_and_terminal_rcode(self):
        for case in CASES:
            if case.negative and case.answer:
                with self.subTest(case=case):
                    self.rejects(case, "answer", [])
                    self.rejects(
                        case,
                        "answer",
                        [("*.alias.example.test.", "CNAME", case.answer[0][2])],
                    )
                    self.rejects(case, "rcode", 3 if case.rcode == 0 else 0)

    def test_negative_soa_and_ttl_are_mandatory(self):
        for case in CASES:
            if not case.negative:
                continue
            for soas in (
                [],
                [("other.test.", "IN", 30, 30)],
                [(APEX, "CH", 30, 30)],
                [(APEX, "IN", 300, 30)],
                [(APEX, "IN", 30, 300)],
                [(APEX, "IN", 30, 30)] * 2,
            ):
                with self.subTest(case=case, soas=soas):
                    self.rejects(case, "soas", soas)

    def test_positive_cname_query_does_not_follow_target(self):
        case = next(c for c in CASES if c.qtype == "CNAME")
        self.rejects(case, "rcode", 3)
        self.rejects(case, "answer", [])

    def test_positive_data_owner_value_and_completeness(self):
        case = CASES[0]
        for answer in (
            [],
            [("*.example.test.", "A", "192.0.2.80")],
            [(case.name, "A", "192.0.2.99")],
            list(case.answer) * 2,
        ):
            self.rejects(case, "answer", answer)

    def test_authority_and_truncation(self):
        for case in CASES:
            self.rejects(case, "aa", case.referral)
            self.rejects(case, "tc", True)

    def test_referral_requires_cut_ns_glue_and_no_negative_soa(self):
        for case in CASES:
            if not case.referral:
                continue
            self.rejects(case, "nameservers", [])
            self.rejects(case, "nameservers", [(APEX, "IN", "ns.example.test.")])
            self.rejects(case, "additional", [])
            self.rejects(
                case, "additional", [("ns.cut.example.test.", "IN", "A", "192.0.2.99")]
            )
            self.rejects(case, "soas", [(APEX, "IN", 30, 30)])

    def test_endpoint_validation(self):
        self.assertEqual(endpoint("bind=127.0.0.1:53"), ("bind", "127.0.0.1", 53))
        self.assertEqual(endpoint("v6=[::1]:5300"), ("v6", "::1", 5300))
        for value in ("host", "=host:53", "bind=:53", "bind=host:0", "bind=host:65536"):
            with self.assertRaises(argparse.ArgumentTypeError):
                endpoint(value)


if __name__ == "__main__":
    unittest.main()
