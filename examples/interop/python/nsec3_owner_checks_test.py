"""Fault injection for metadata-owner gates; standard library only."""

import unittest
from nsec3_owner_checks import expected_rcode, validate

NAME = "hash.example.test."


def response(rcode=3, answer=(), signatures=()):
    return {
        "rcode": rcode,
        "aa": True,
        "tc": False,
        "answer": list(answer),
        "soas": [("example.test.", "IN", 30, 30)],
        "signatures": list(signatures),
    }


class MetadataGateTests(unittest.TestCase):
    def test_metadata_and_ordinary_descendant_have_distinct_existence(self):
        validate("metadata", "owner", "A", NAME, response())
        validate("descendant", "owner", "A", NAME, response(0))
        with self.assertRaises(AssertionError):
            validate("metadata", "owner", "A", NAME, response(0))
        with self.assertRaises(AssertionError):
            validate("descendant", "owner", "A", NAME, response(3))
        self.assertEqual(expected_rcode("descendant", "below"), 3)

    def test_missing_or_wrong_negative_soa_is_rejected(self):
        for soas in (
            [],
            [("other.test.", "IN", 30, 30)],
            [("example.test.", "CH", 30, 30)],
            [("example.test.", "IN", 300, 30)],
        ):
            value = response()
            value["soas"] = soas
            with self.assertRaises(AssertionError):
                validate("metadata", "owner", "A", NAME, value)

    def test_explicit_metadata_answers_do_not_establish_hidden_owner(self):
        with self.assertRaises(AssertionError):
            validate(
                "metadata",
                "owner",
                "NSEC3",
                NAME,
                response(3, [(NAME, "NSEC3", "IN", "denial metadata")]),
            )

    def test_wildcard_must_expand_through_hidden_metadata_owner(self):
        good = response(0, [(NAME, "A", "IN", "192.0.2.89")])
        validate("wildcard", "owner", "A", NAME, good)
        with self.assertRaises(AssertionError):
            validate("wildcard", "owner", "A", NAME, response(0))
        with self.assertRaises(AssertionError):
            validate("wildcard", "below", "A", NAME, response(3))

    def test_wrong_wildcard_metadata_and_signature_sources_are_rejected(self):
        with self.assertRaises(AssertionError):
            validate(
                "wildcard",
                "owner",
                "NSEC3",
                NAME,
                response(0, [(NAME, "NSEC3", "IN", "metadata")]),
            )
        with self.assertRaises(AssertionError):
            validate(
                "wildcard",
                "owner",
                "RRSIG",
                NAME,
                response(0, [(NAME, "RRSIG", "IN", "metadata")], [(50, 3)]),
            )

    def test_flags_and_ordinary_owner_data_are_preserved(self):
        for key, value in (("aa", False), ("tc", True)):
            bad = response()
            bad[key] = value
            with self.assertRaises(AssertionError):
                validate("metadata", "owner", "A", NAME, bad)
        with self.assertRaises(AssertionError):
            validate("owner", "owner", "A", NAME, response(0))


if __name__ == "__main__":
    unittest.main()
