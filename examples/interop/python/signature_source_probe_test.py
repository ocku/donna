"""Fault-inject the signature-source matrix oracle against its signed fixture."""

from types import SimpleNamespace
import unittest

import dns.name
import dns.rdatatype
import dns.rrset

from signature_source_probe import APEX, answer_shape, inspect, proof_valid
from test_fixtures.signed import signature_sources


class SignatureSourceProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zone = signature_sources()
        cls.keys = {APEX: cls.zone.get_rdataset(APEX, dns.rdatatype.DNSKEY)}
        cls.owner = dns.name.from_text("www.example.test.")
        cls.source = "www.example.test."
        cls.data = cls.zone.get_rdataset(cls.owner, dns.rdatatype.A)
        cls.sigs = cls.zone.get_rdataset(
            cls.owner, dns.rdatatype.RRSIG, covers=dns.rdatatype.A
        )
        ancestor = dns.name.from_text("*.example.test.")
        cls.wrong = cls.zone.get_rdataset(
            ancestor, dns.rdatatype.RRSIG, covers=dns.rdatatype.A
        )

    def check(self, signatures):
        data = dns.rrset.from_rdata_list(self.owner, self.data.ttl, list(self.data))
        sigs = dns.rrset.from_rdata_list(self.owner, self.sigs.ttl, signatures)
        return inspect(
            self.zone, self.keys, SimpleNamespace(answer=[data, sigs]), self.source, "A"
        )

    def test_valid_pair(self):
        passed, details, expected = self.check(list(self.sigs))
        self.assertTrue(passed)
        self.assertEqual(expected, 2)
        self.assertEqual({item["algorithm"] for item in details}, {13, 15})
        self.assertTrue(all(item["valid"] for item in details))

    def test_missing_signature_fails(self):
        self.assertFalse(self.check(list(self.sigs)[:1])[0])

    def test_ancestor_signature_fails_and_does_not_validate(self):
        passed, details, _ = self.check(list(self.sigs) + list(self.wrong))
        self.assertFalse(passed)
        self.assertEqual(
            sum(not item["source_match"] and not item["valid"] for item in details), 2
        )

    def test_modified_signature_fails(self):
        sig = list(self.sigs)[0]
        modified = sig.replace(signature=b"\x00" * len(sig.signature))
        passed, details, _ = self.check([modified, list(self.sigs)[1]])
        self.assertFalse(passed)
        self.assertTrue(any(item["valid"] is False for item in details))

    def test_missing_next_closer_proof_fails(self):
        data = dns.rrset.from_rdata_list(self.owner, self.data.ttl, list(self.data))
        sigs = dns.rrset.from_rdata_list(self.owner, self.sigs.ttl, list(self.sigs))
        reply = SimpleNamespace(answer=[data, sigs], authority=[])
        self.assertFalse(
            proof_valid(
                reply, self.keys, "m.wild.example.test.", "*.wild.example.test.", True
            )
        )

    def test_wrong_answer_type_fails_shape_gate(self):
        data = dns.rrset.from_rdata_list(self.owner, self.data.ttl, list(self.data))
        self.assertFalse(answer_shape(SimpleNamespace(answer=[data]), "TXT"))


if __name__ == "__main__":
    unittest.main()
