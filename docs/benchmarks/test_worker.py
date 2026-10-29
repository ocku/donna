"""Fault injection for the documentation benchmark's semantic gates."""

import unittest

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from documentation_worker import query, verify


class SemanticGates(unittest.TestCase):
    def response(self, case, recursive=False):
        q = query(case)
        r = dns.message.make_response(q)
        r.flags |= dns.flags.RA if recursive else dns.flags.AA
        if case == "negative":
            r.set_rcode(dns.rcode.NXDOMAIN)
            r.authority.append(
                dns.rrset.from_text(
                    "example.test.",
                    30,
                    "IN",
                    "SOA",
                    "ns.example.test. hostmaster.example.test. 1 60 60 60 30",
                )
            )
        elif case == "wildcard":
            r.answer.append(
                dns.rrset.from_text(
                    "m.wild.example.test.", 300, "IN", "TXT", '"wildcard"'
                )
            )
        else:
            if case == "cname":
                r.answer.append(
                    dns.rrset.from_text(
                        "alias.example.test.", 300, "IN", "CNAME", "www.example.test."
                    )
                )
            r.answer.append(
                dns.rrset.from_text("www.example.test.", 300, "IN", "A", "192.0.2.80")
            )
        return q, r

    def test_expected_responses(self):
        for recursive in (False, True):
            for case in ("positive", "negative", "wildcard", "cname"):
                q, r = self.response(case, recursive)
                verify(q, r, case, recursive)

    def test_wrong_address(self):
        q, r = self.response("positive")
        r.answer[0] = dns.rrset.from_text(
            "www.example.test.", 300, "IN", "A", "192.0.2.81"
        )
        with self.assertRaises(AssertionError):
            verify(q, r, "positive", False)

    def test_extra_answer(self):
        q, r = self.response("positive")
        r.answer.append(
            dns.rrset.from_text("extra.example.test.", 300, "IN", "A", "192.0.2.80")
        )
        with self.assertRaises(AssertionError):
            verify(q, r, "positive", False)

    def test_wrong_negative_zone(self):
        q, r = self.response("negative")
        r.authority[0].name = dns.name.from_text("test.")
        with self.assertRaises(AssertionError):
            verify(q, r, "negative", False)

    def test_wrong_wildcard_owner(self):
        q, r = self.response("wildcard")
        r.answer[0].name = dns.name.from_text("*.wild.example.test.")
        with self.assertRaises(AssertionError):
            verify(q, r, "wildcard", False)

    def test_wrong_cname_target(self):
        q, r = self.response("cname", True)
        r.answer[0] = dns.rrset.from_text(
            "alias.example.test.", 300, "IN", "CNAME", "other.example.test."
        )
        with self.assertRaises(AssertionError):
            verify(q, r, "cname", True)

    def test_incorrect_flags_and_rcode(self):
        for flag in (dns.flags.AA, dns.flags.RA, dns.flags.AD, dns.flags.TC):
            q, r = self.response("positive")
            r.flags ^= flag
            with self.assertRaises(AssertionError):
                verify(q, r, "positive", False)
        q, r = self.response("negative")
        r.set_rcode(0)
        with self.assertRaises(AssertionError):
            verify(q, r, "negative", False)


if __name__ == "__main__":
    unittest.main()
