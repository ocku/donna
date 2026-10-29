"""Verify public-only DNSSEC/TTL gates against frozen signed DNAME material."""

import copy
import unittest

import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset

from recursive_evidence import Verifier, zones, rrset
from recursive_refresh import Refreshes, events
from test_fixtures.signed import recursive_chain


class EvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public = recursive_chain()
        leaf = zones(cls.public)["leaf"]
        signatures = [
            item
            for zone in zones(cls.public).values()
            for _, dataset in zone.iterate_rdatasets()
            if dataset.rdtype == dns.rdatatype.RRSIG
            for item in dataset
        ]
        cls.when = max(item.inception for item in signatures) + 600
        assert cls.when < min(item.expiration for item in signatures)
        cls.case = dict(
            kind="dname",
            name="p0000.old.example.test.",
            rtype="A",
            target="p0000.dest.example.test.",
            value="192.0.2.80",
        )
        query = dns.message.make_query(
            cls.case["name"], "A", want_dnssec=True, payload=1232
        )
        query.id = 0xBEEF
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA | dns.flags.AD
        response.use_edns(0, ednsflags=dns.flags.DO, payload=1232)
        for owner, kind in [
            ("old.example.test.", dns.rdatatype.DNAME),
            ("p0000.dest.example.test.", dns.rdatatype.A),
        ]:
            name = dns.name.from_text(owner)
            response.answer += [
                rrset(leaf, name, kind),
                rrset(leaf, name, dns.rdatatype.RRSIG, kind),
            ]
        response.answer.append(
            dns.rrset.from_text(
                cls.case["name"], 300, "IN", "CNAME", cls.case["target"]
            )
        )
        cls.capture = dict(
            query=query.to_wire().hex(),
            response=response.to_wire().hex(),
            checked_at=cls.when,
            received_monotonic_ns=1_000_000_000_000,
        )

    def test_valid_public_chain_and_synthesized_alias(self):
        verifier = Verifier(self.public, self.when)
        verifier.verify(self.case, self.capture)
        self.assertEqual(verifier.summary()["signed_rrsets"], 2)
        self.assertEqual(verifier.summary()["unique_math_verifications"], 2)

    def test_math_reuse_still_checks_per_reply_ttl_and_receive_time(self):
        verifier = Verifier(self.public, self.when)
        verifier.verify(self.case, self.capture)
        second = copy.deepcopy(self.capture)
        response = dns.message.from_wire(bytes.fromhex(second["response"]))
        for rr in response.answer:
            rr.ttl -= 1
        second.update(
            response=response.to_wire().hex(),
            checked_at=self.when + 1,
            received_monotonic_ns=1_001_000_000_000,
        )
        verifier.verify(self.case, second)
        self.assertEqual(verifier.summary()["responses"], 2)
        self.assertEqual(verifier.summary()["unique_math_verifications"], 2)
        stale = dict(
            self.capture,
            checked_at=self.when + 5,
            received_monotonic_ns=1_005_000_000_000,
        )
        with self.assertRaises(AssertionError):
            verifier.verify(self.case, stale)

    def test_expired_deadlines_cannot_keep_ttl_one_alive_indefinitely(self):
        for ttl in (0, 1):
            verifier = Verifier(self.public, self.when)
            verifier.verify(self.case, self.capture)
            capture = copy.deepcopy(self.capture)
            response = dns.message.from_wire(bytes.fromhex(capture["response"]))
            for rr in response.answer:
                rr.ttl = ttl
            capture.update(
                response=response.to_wire().hex(),
                checked_at=self.when + 360,
                received_monotonic_ns=1_360_000_000_000,
            )
            with self.assertRaisesRegex(
                AssertionError, "after observed cache deadline"
            ):
                verifier.verify(self.case, capture)
        verifier = Verifier(self.public, self.when)
        verifier.verify(self.case, self.capture)
        capture = copy.deepcopy(self.capture)
        response = dns.message.from_wire(bytes.fromhex(capture["response"]))
        for rr in response.answer:
            rr.ttl = 0
        capture.update(
            response=response.to_wire().hex(),
            checked_at=self.when + 300.5,
            received_monotonic_ns=1_300_500_000_000,
        )
        verifier.verify(self.case, capture)  # Bounded in-flight TTL0 grace.

    def test_renewal_requires_matching_owner_type_and_prior_upstream_timestamp(self):
        capture = dict(
            self.capture,
            checked_at=self.when + 360,
            received_monotonic_ns=1_360_000_000_000,
        )
        witnesses = [
            dict(
                checked_at=self.when + 359.99, name="old.example.test.", rtype="DNAME"
            ),
            dict(checked_at=self.when + 359.99, name=self.case["target"], rtype="A"),
        ]
        for fault in (
            "none",
            "wrong-owner",
            "wrong-type",
            "future",
            "no-source",
            "no-target",
        ):
            altered = copy.deepcopy(witnesses)
            if fault == "wrong-owner":
                altered[0]["name"] = "other.example.test."
            elif fault == "wrong-type":
                altered[0]["rtype"] = "AAAA"
            elif fault == "future":
                altered[0]["checked_at"] = self.when + 361
            elif fault == "no-source":
                altered = altered[1:]
            elif fault == "no-target":
                altered = altered[:1]
            verifier = Verifier(self.public, self.when, refreshes=Refreshes(altered))
            verifier.verify(self.case, self.capture)
            if fault == "none":
                verifier.verify(self.case, capture)
                old = copy.deepcopy(capture)
                response = dns.message.from_wire(bytes.fromhex(old["response"]))
                for rr in response.answer:
                    rr.ttl = 0
                old["response"] = response.to_wire().hex()
                verifier.verify(self.case, old)  # An older in-flight generation.
                verifier.verify(self.case, capture)
                stale = dict(
                    old,
                    checked_at=self.when + 700,
                    received_monotonic_ns=1_700_000_000_000,
                )
                with self.assertRaisesRegex(
                    AssertionError, "after observed cache deadline"
                ):
                    verifier.verify(self.case, stale)
            else:
                with self.assertRaises(AssertionError):
                    verifier.verify(self.case, capture)

    def test_authority_witnesses_require_exact_log_prefix_address_and_owner(self):
        before = {"leaf": "startup\n"}
        line = "29-Oct-2026 00:00:01.123 client @0x1 172.29.53.74#1234 (old.example.test): query: old.example.test IN DNAME -E (172.29.53.72)\n"
        rows = events(before, {"leaf": "startup\n" + line}, "172.29.53.74")
        self.assertEqual(
            [(row["name"], row["rtype"]) for row in rows],
            [("old.example.test.", "DNAME")],
        )
        self.assertEqual(
            events(before, {"leaf": "startup\n" + line}, "172.29.53.75"), []
        )
        with self.assertRaises(AssertionError):
            events(before, {"leaf": line}, "172.29.53.74")

    def test_data_signature_synthesized_target_ttl_ad_cd_and_anchor_faults_fail(self):
        for fault in (
            "value",
            "missing-signature",
            "signature",
            "cname",
            "ttl",
            "ad",
            "cd",
            "anchor",
            "expired",
            "question",
        ):
            with self.subTest(fault=fault):
                capture, public = (
                    copy.deepcopy(self.capture),
                    copy.deepcopy(self.public),
                )
                response = dns.message.from_wire(bytes.fromhex(capture["response"]))
                if fault == "value":
                    index = next(
                        i
                        for i, rr in enumerate(response.answer)
                        if rr.rdtype == dns.rdatatype.A
                    )
                    rr = response.answer[index]
                    response.answer[index] = dns.rrset.from_text(
                        rr.name, rr.ttl, "IN", "A", "192.0.2.81"
                    )
                elif fault == "missing-signature":
                    response.answer = [
                        rr
                        for rr in response.answer
                        if not (
                            rr.rdtype == dns.rdatatype.RRSIG
                            and rr.covers == dns.rdatatype.DNAME
                        )
                    ]
                elif fault == "signature":
                    index = next(
                        i
                        for i, rr in enumerate(response.answer)
                        if rr.rdtype == dns.rdatatype.RRSIG
                    )
                    rr = response.answer[index]
                    words = rr[0].to_text().split()
                    words[-1] = ("A" if words[-1][0] != "A" else "B") + words[-1][1:]
                    response.answer[index] = dns.rrset.from_text(
                        rr.name, rr.ttl, "IN", "RRSIG", " ".join(words)
                    )
                elif fault == "cname":
                    index = next(
                        i
                        for i, rr in enumerate(response.answer)
                        if rr.rdtype == dns.rdatatype.CNAME
                    )
                    rr = response.answer[index]
                    response.answer[index] = dns.rrset.from_text(
                        rr.name, rr.ttl, "IN", "CNAME", "wrong.example.test."
                    )
                elif fault == "ttl":
                    response.answer[0].ttl = 301
                elif fault == "ad":
                    response.flags &= ~dns.flags.AD
                elif fault == "cd":
                    response.flags |= dns.flags.CD
                elif fault == "anchor":
                    words = public["anchors"].split()
                    words[-1] = ("A" if words[-1][0] != "A" else "B") + words[-1][1:]
                    public["anchors"] = " ".join(words)
                elif fault == "question":
                    query = dns.message.from_wire(bytes.fromhex(capture["query"]))
                    query.question[0].name = dns.name.from_text("wrong.example.test.")
                    response.question = copy.deepcopy(query.question)
                    capture["query"] = query.to_wire().hex()
                else:
                    capture["checked_at"] += 172800
                capture["response"] = response.to_wire().hex()
                with self.assertRaises(Exception):
                    Verifier(public, self.when).verify(self.case, capture)


if __name__ == "__main__":
    unittest.main()
