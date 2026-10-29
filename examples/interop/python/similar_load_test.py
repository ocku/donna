"""Reject plausible but incorrect authoritative benchmark preflight answers."""

import unittest

import dns.flags
import dns.message
import dns.rrset

from similar_load import query_for, shape


class SimilarShapeTest(unittest.TestCase):
    def response(self, kind="positive"):
        name, rtype = (
            ("m.wild.example.test.", "A")
            if kind == "wildcard-nodata"
            else ("m.wild.example.test.", "TXT")
            if kind == "wildcard"
            else ("www.example.test.", "A")
        )
        query = query_for("unsigned", name, rtype)
        reply = dns.message.make_response(query)
        reply.flags |= dns.flags.AA
        if kind == "positive":
            reply.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "192.0.2.80"))
        elif kind == "wildcard":
            reply.answer.append(
                dns.rrset.from_text(name, 60, "IN", "TXT", '"wildcard"')
            )
        else:
            reply.authority.append(
                dns.rrset.from_text(
                    "example.test.",
                    30,
                    "IN",
                    "SOA",
                    "ns.example.test. hostmaster.example.test. 1 60 60 60 30",
                )
            )
        return query, reply

    def test_valid_fixtures(self):
        for kind in ("positive", "wildcard", "nodata", "wildcard-nodata"):
            with self.subTest(kind=kind):
                query, reply = self.response(kind)
                shape(query, reply, kind, 0)

    def test_wrong_answer_owner(self):
        for kind in ("positive", "wildcard"):
            with self.subTest(kind=kind):
                query, reply = self.response(kind)
                reply.answer[0].name = dns.name.from_text("other.example.test.")
                with self.assertRaises(AssertionError):
                    shape(query, reply, kind, 0)

    def test_extra_answer_rrset(self):
        query, reply = self.response()
        reply.answer.append(
            dns.rrset.from_text("other.example.test.", 60, "IN", "A", "192.0.2.99")
        )
        with self.assertRaises(AssertionError):
            shape(query, reply, "positive", 0)

    def test_extra_answer_record(self):
        query, reply = self.response()
        reply.answer[0] = dns.rrset.from_text(
            query.question[0].name, 60, "IN", "A", "192.0.2.80", "192.0.2.99"
        )
        with self.assertRaises(AssertionError):
            shape(query, reply, "positive", 0)

    def test_wrong_soa_scope(self):
        query, reply = self.response("nodata")
        reply.authority[0].name = dns.name.from_text("unrelated.test.")
        with self.assertRaises(AssertionError):
            shape(query, reply, "nodata", 0)

    def test_duplicate_soa(self):
        query, reply = self.response("nodata")
        reply.authority.append(reply.authority[0])
        with self.assertRaises(AssertionError):
            shape(query, reply, "nodata", 0)


if __name__ == "__main__":
    unittest.main()
