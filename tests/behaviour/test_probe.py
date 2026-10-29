"""Fault injection for the independent authority oracle; no DNS dependency."""

import unittest
from probe import APEX, cases, records, validate


def expected(case, rd=False):
    return dict(
        rcode=case.rcode,
        qr=True,
        tc=False,
        aa=case.kind != "referral",
        rd=rd,
        ra=False,
        answer=records(case.answer),
        soas=[(APEX, "IN", 30, 30)] if case.kind == "negative" else [],
        authority=records("cut.example.test. 300 IN NS ns.cut.example.test.")
        if case.kind == "referral"
        else [],
        additional=records("ns.cut.example.test. 300 IN A 192.0.2.54")
        if case.kind == "referral"
        else [],
    )


class OracleTests(unittest.TestCase):
    def reject(self, case, field, value):
        reply = expected(case)
        reply[field] = value

        with self.assertRaises(ValueError):
            validate(case, reply, False)

    def test_all_shapes_and_rd_values(self):
        self.assertEqual(len({c.id for c in cases()}), len(cases()))

        for case in cases():
            for rd in (False, True):
                with self.subTest(case=case.id, rd=rd):
                    validate(case, expected(case, rd), rd)

    def test_missing_extra_and_wrong_answers(self):
        for case in cases():
            if not case.answer:
                continue

            self.reject(case, "answer", [])
            self.reject(case, "answer", records(case.answer) * 2)
            self.reject(
                case, "answer", records("wrong.example.test. 300 IN A 192.0.2.99")
            )

    def test_wrong_alias_ttl(self):
        for case in cases():
            if "CNAME" not in case.answer:
                continue

            self.reject(case, "answer", records(case.answer.replace(" 300 ", " 301 ")))

    def test_negative_scope_class_ttl_and_minimum(self):
        for case in cases():
            if case.kind != "negative":
                continue

            for soa in (
                [],
                [("other.test.", "IN", 30, 30)],
                [(APEX, "CH", 30, 30)],
                [(APEX, "IN", 300, 30)],
                [(APEX, "IN", 30, 300)],
            ):
                self.reject(case, "soas", soa)

            self.reject(
                case, "rcode", "NOERROR" if case.rcode == "NXDOMAIN" else "NXDOMAIN"
            )

    def test_flags(self):
        for case in cases():
            for key, value in (
                ("qr", False),
                ("tc", True),
                ("aa", case.kind == "referral"),
                ("rd", True),
                ("ra", True),
            ):
                self.reject(case, key, value)

    def test_referral_requires_ns_and_glue(self):
        case = next(c for c in cases() if c.kind == "referral")

        self.reject(case, "authority", [])
        self.reject(case, "additional", [])
        self.reject(case, "soas", [(APEX, "IN", 30, 30)])

    def test_positive_must_not_claim_negative_soa(self):
        case = cases()[0]

        self.reject(case, "soas", [(APEX, "IN", 30, 30)])


if __name__ == "__main__":
    unittest.main()
