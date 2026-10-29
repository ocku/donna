"""Fault injection for observable recursive gates; no Docker/dependencies."""

import unittest

from recursive_cache_checks import total, validate


class RecursiveGateTests(unittest.TestCase):
    def response(self, answers=(), rcode=3):
        return {
            "rcode": rcode,
            "flags": 0x180,
            "answer": list(answers),
            "classes": [1],
            "soas": [("example.test.", 6, 6)],
        }

    def test_valid_positive_negative_and_alias(self):
        validate("A", 3, [], self.response())
        cname = [("alias.example.test.", "CNAME", "missing.example.test.")]
        validate("A", 3, cname, self.response(cname))
        validate("CNAME", 0, cname, self.response(cname, 0))
        positive = [("name.example.test.", "A", "192.0.2.80")]
        validate("A", 0, positive, self.response(positive, 0))

    def reject(self, key, value):
        response = self.response()
        response[key] = value
        with self.assertRaises(AssertionError):
            validate("A", 3, [], response)

    def test_terminal_rcode_and_extra_answer(self):
        self.reject("rcode", 0)
        self.reject("answer", [("name.example.test.", "A", "192.0.2.80")])

    def test_recursive_control_flags(self):
        for flags in (0x80, 0x100, 0x180 | 0x400, 0x180 | 0x200, 0x180 | 0x20):
            self.reject("flags", flags)

    def test_negative_soa_scope_and_lifetime(self):
        for soas in (
            [],
            [("other.test.", 6, 6)],
            [("example.test.", 7, 6)],
            [("example.test.", -1, 6)],
            [("example.test.", 3, 3)],
            [("example.test.", 6, 6)] * 2,
        ):
            self.reject("soas", soas)
        self.reject("classes", [3])

    def test_cname_owner_and_terminal_are_not_interchangeable(self):
        expected = [("alias.example.test.", "CNAME", "missing.example.test.")]
        for actual in (
            [],
            [("missing.example.test.", "CNAME", "alias.example.test.")],
            expected * 2,
        ):
            with self.assertRaises(AssertionError):
                validate("A", 3, expected, self.response(actual))

    def test_cname_nodata_requires_negative_soa(self):
        cname = [("alias.example.test.", "CNAME", "nodata.example.test.")]
        response = self.response(cname, 0)
        response["soas"] = []
        with self.assertRaises(AssertionError):
            validate("A", 0, cname, response)
        validate("CNAME", 0, cname, response)

    def test_counter_uses_exact_name_and_all_types(self):
        snapshot = {
            "name.test./A": 2,
            "name.test./AAAA": 1,
            "xname.test./A": 99,
            "name.test.other./A": 99,
        }
        self.assertEqual(total(snapshot, "name.test."), 3)
        self.assertEqual(total(snapshot, "missing.test."), 0)


if __name__ == "__main__":
    unittest.main()
