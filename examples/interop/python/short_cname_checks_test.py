import unittest

from short_cname_checks import validate, validate_transition


class ShortCnameChecks(unittest.TestCase):
    def test_rejects_poisoned_alias_and_invalid_negative(self):
        response = {
            "rcode": 3,
            "flags": 0x180,
            "answer": [("alias.", "CNAME", "old.")],
            "classes": [1, 1],
            "soas": [("example.test.", 8, 12)],
        }
        validate(response, 3, [("alias.", "CNAME", "old.")])
        for key, value in (
            ("rcode", 0),
            ("answer", [("alias.", "CNAME", "new.")]),
            ("flags", 0x1A0),
            ("classes", [3]),
            ("soas", [("example.test.", 0, 12)]),
            ("soas", [("other.test.", 8, 12)]),
        ):
            broken = dict(response, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                validate(broken, 3, [("alias.", "CNAME", "old.")])

    def test_rejects_missing_refresh_and_terminal_requery(self):
        before = {"alias": 1, "old": 1}
        after = {"alias": 2, "old": 1}
        validate_transition(before, after, 1)
        for first, second, last in (
            ({"alias": 0, "old": 1}, after, 1),
            (before, before, 1),
            (before, after, 2),
        ):
            with (
                self.subTest(first=first, second=second, last=last),
                self.assertRaises(AssertionError),
            ):
                validate_transition(first, second, last)

    def test_rejects_wrong_replacement_answer(self):
        answer = [("alias.", "CNAME", "new."), ("new.", "A", "192.0.2.101")]
        response = {
            "rcode": 0,
            "flags": 0x180,
            "answer": answer,
            "classes": [1, 1],
            "soas": [],
        }
        validate(response, 0, answer)
        for changed in (
            [("alias.", "CNAME", "old.")],
            [("alias.", "CNAME", "new."), ("new.", "A", "192.0.2.1")],
        ):
            with self.subTest(answer=changed), self.assertRaises(AssertionError):
                validate(dict(response, answer=changed), 0, answer)


if __name__ == "__main__":
    unittest.main()
