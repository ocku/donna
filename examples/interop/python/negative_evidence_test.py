"""Fault injection against independently signed synthetic negative replies."""

import copy
import unittest

import dns.dnssec
import dns.flags
import dns.message
import dns.rdatatype
import dns.rrset

from negative_evidence import NegativeVerifier
from negative_refresh import NegativeRefreshes
from recursive_evidence import authenticated_keys
from test_fixtures.negative import negative_record


class NegativeEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = negative_record()

    def row(self, mode, scenario="descendant", step=0, role="model"):
        return next(
            row
            for row in self.record["observations"]
            if (row["mode"], row["role"], row["scenario"], row["step"])
            == (mode, role, scenario, step)
        )

    def verifier(self, mode, capture):
        return NegativeVerifier(self.record["public"][mode], capture["checked_at"])

    def test_seed_repeat_and_new_descendant_proofs_both_modes(self):
        for mode in ("nsec", "nsec3"):
            seed = self.row(mode)["capture"]
            v = self.verifier(mode, seed)
            for step in range(3):
                row = self.row(mode, step=step)
                v.verify(row["case"], row["capture"])
            self.assertEqual(v.responses, 3)
            self.assertEqual(v.math_operations, len(v.math))

    def test_missing_wildcard_or_closest_encloser_proof_cannot_pass(self):
        for mode in ("nsec", "nsec3"):
            row = self.row(mode)
            capture = copy.deepcopy(row["capture"])
            v = self.verifier(mode, capture)
            message = dns.message.from_wire(bytes.fromhex(capture["response"]))
            _, _, closest = v.oracle.expected(row["case"])
            if mode == "nsec":
                owner = closest
            else:
                record = next(
                    rr for rr in message.authority if rr.rdtype == dns.rdatatype.NSEC3
                )[0]
                digest = dns.dnssec.nsec3_hash(
                    closest, record.salt, record.iterations, record.algorithm
                )
                owner = dns.name.from_text(digest + ".example.test.")
            message.authority = [rr for rr in message.authority if rr.name != owner]
            capture["response"] = message.to_wire().hex()
            with self.assertRaises(AssertionError):
                v.verify(row["case"], capture)

    def test_signature_ad_cd_question_and_ttl_faults_fail(self):
        for mode in ("nsec", "nsec3"):
            row = self.row(mode)
            for fault in ("signature", "ad", "cd", "question", "ttl"):
                capture = copy.deepcopy(row["capture"])
                message = dns.message.from_wire(bytes.fromhex(capture["response"]))
                if fault == "signature":
                    index = next(
                        i
                        for i, rr in enumerate(message.authority)
                        if rr.rdtype == dns.rdatatype.RRSIG
                    )
                    rr = message.authority[index]
                    sig = rr[0]
                    message.authority[index] = dns.rrset.from_rdata(
                        rr.name,
                        rr.ttl,
                        sig.replace(
                            signature=bytes([sig.signature[0] ^ 1]) + sig.signature[1:]
                        ),
                    )
                elif fault == "ad":
                    message.flags &= ~dns.flags.AD
                elif fault == "cd":
                    message.flags |= dns.flags.CD
                elif fault == "question":
                    message.question[0].name = dns.name.from_text("wrong.example.test.")
                else:
                    next(
                        rr for rr in message.authority if rr.rdtype == dns.rdatatype.SOA
                    ).ttl = 6
                capture["response"] = message.to_wire().hex()
                with self.assertRaises(Exception):
                    self.verifier(mode, capture).verify(row["case"], capture)

    def test_expired_ttl_zero_and_one_fail_without_new_authority_witness(self):
        for ttl in (0, 1):
            row = self.row("nsec")
            capture = copy.deepcopy(row["capture"])
            v = self.verifier("nsec", capture)
            v.verify(row["case"], capture)
            message = dns.message.from_wire(bytes.fromhex(capture["response"]))
            for rr in message.authority:
                rr.ttl = ttl
            capture.update(
                response=message.to_wire().hex(),
                checked_at=capture["checked_at"] + 60,
                received_monotonic_ns=capture["received_monotonic_ns"] + 60_000_000_000,
            )
            with self.assertRaisesRegex(
                AssertionError, "after observed negative deadline"
            ):
                v.verify(row["case"], capture)

    def test_relevant_refresh_is_fixed_and_survives_older_inflight_reply(self):
        row = self.row("nsec")
        original = row["capture"]
        v = self.verifier("nsec", original)
        v.verify(row["case"], original)
        fresh = copy.deepcopy(original)
        fresh.update(
            checked_at=original["checked_at"] + 60,
            received_monotonic_ns=original["received_monotonic_ns"] + 60_000_000_000,
        )
        event = dict(
            checked_at=fresh["checked_at"] - 0.01,
            name=row["case"]["name"],
            rtype=row["case"]["rtype"],
        )
        v.refreshes = NegativeRefreshes(v.oracle, [event], [row["case"]])
        v.verify(row["case"], fresh)
        old = copy.deepcopy(fresh)
        message = dns.message.from_wire(bytes.fromhex(old["response"]))
        for rr in message.authority:
            rr.ttl = 0
        old["response"] = message.to_wire().hex()
        v.verify(row["case"], old)
        v.verify(row["case"], fresh)
        old.update(
            checked_at=fresh["checked_at"] + 10,
            received_monotonic_ns=fresh["received_monotonic_ns"] + 10_000_000_000,
        )
        with self.assertRaisesRegex(AssertionError, "after observed negative deadline"):
            v.verify(row["case"], old)

    def test_bogus_ds_and_unsigned_authority_ns_under_ad_remain_rejected(self):
        row = self.row("nsec")
        with self.assertRaisesRegex(AssertionError, "DS does not match"):
            authenticated_keys(
                self.record["public"]["nsec"], row["capture"]["checked_at"], bad=True
            )
        for mode in ("nsec", "nsec3"):
            cached = self.row(mode, step=1, role="unsigned-authority-model")
            with self.assertRaises(AssertionError):
                self.verifier(mode, cached["capture"]).verify(
                    cached["case"], cached["capture"]
                )


if __name__ == "__main__":
    unittest.main()
