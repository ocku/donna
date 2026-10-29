"""Staggered negative admissions and global/query proof-aging fault models."""

import copy
import unittest

import dns.message

from negative_evidence import NegativeVerifier
from negative_proof_bank import freeze
from negative_refresh import NegativeRefreshes
from test_fixtures.negative import negative_record


class ProofBankTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        record = negative_record()
        cls.public = record["public"]["nsec"]
        rows = [
            row
            for row in record["observations"]
            if (row["mode"], row["role"], row["scenario"])
            == ("nsec", "model", "descendant")
        ]
        cls.original = [rows[0]["capture"], rows[2]["capture"]]
        cls.when = cls.original[0]["checked_at"]

    def packet(self, index, seconds, ttl):
        capture = copy.deepcopy(self.original[index])
        message = dns.message.from_wire(bytes.fromhex(capture["response"]))
        for rr in message.authority:
            rr.ttl = ttl
        capture.update(
            response=message.to_wire().hex(),
            checked_at=self.when + seconds,
            received_monotonic_ns=100_000_000_000 + round(seconds * 1e9),
        )
        return capture

    def witness(self, index, seconds, **changes):
        case = self.original[index]["case"]
        return dict(
            checked_at=self.when + seconds,
            name=case["name"],
            rtype=case["rtype"],
            **changes,
        )

    def verify(self, bank, capture):
        verifier = NegativeVerifier(
            self.public,
            capture["checked_at"],
            deadlines=bank["deadlines"],
            frozen=True,
            require_seed=True,
        )
        verifier.verify(capture["case"], capture)

    def test_staggered_independent_queries_do_not_share_earliest_admission(self):
        first, second = self.packet(0, 0, 2), self.packet(1, 1, 5)
        bank = freeze(self.public, [first, second], [self.witness(1, 0.999)])
        self.assertEqual(len(bank["deadlines"]), 3)
        self.verify(bank, self.packet(1, 2, 3))  # Independently aged exact entry.
        self.verify(bank, self.packet(0, 2, 0))  # Older exact entry, no renewal.
        self.verify(bank, self.packet(0, 2, 3))  # Legitimate global proof reuse.

    def test_cached_only_preload_cannot_renew_existing_proof(self):
        with self.assertRaises(AssertionError):
            freeze(self.public, [self.packet(0, 0, 2), self.packet(1, 1, 5)], [])
        bank = freeze(self.public, [self.packet(0, 0, 2), self.packet(1, 1, 1)], [])
        self.assertTrue(
            all(deadline == 102_000_000_000 for deadline in bank["deadlines"].values())
        )

    def test_constant_five_at_own_age_one_point_seven_and_two_is_rejected(self):
        bank = freeze(self.public, [self.packet(0, 0, 5)], [])
        for age in (1.7, 2):
            capture = self.packet(0, age, 5)
            capture["clock_uncertainty_seconds"] = 0.050002
            with self.assertRaisesRegex(AssertionError, "TTL exceeded"):
                self.verify(bank, capture)
        self.verify(bank, self.packet(0, 1.7, 3))

    def test_receiving_more_cached_packets_never_advances_frozen_bank(self):
        bank = freeze(self.public, [self.packet(0, 0, 5)], [])
        verifier = NegativeVerifier(
            self.public,
            self.when,
            deadlines=bank["deadlines"],
            frozen=True,
            require_seed=True,
        )
        original = dict(verifier.deadlines)
        for age, ttl in ((0.5, 4), (1, 4), (1.5, 3), (2, 3)):
            capture = self.packet(0, age, ttl)
            verifier.verify(capture["case"], capture)
        self.assertEqual(verifier.deadlines, original)

    def test_ttl_zero_inflight_grace_is_separate_from_positive_ttl(self):
        bank = freeze(self.public, [self.packet(0, 0, 5)], [])
        self.verify(bank, self.packet(0, 5.5, 0))
        for age, ttl in ((5.5, 1), (6.01, 0), (60, 1)):
            with self.assertRaises(AssertionError):
                self.verify(bank, self.packet(0, age, ttl))

    def test_unrelated_future_or_positive_query_witness_cannot_renew(self):
        initial = self.packet(0, 0, 5)
        for event in (
            dict(checked_at=self.when + 1, name="unrelated.example.test.", rtype="A"),
            self.witness(1, 10),
            dict(checked_at=self.when + 1, name="example.test.", rtype="DNSKEY"),
        ):
            bank = freeze(self.public, [initial], [])
            verifier = NegativeVerifier(
                self.public,
                self.when,
                deadlines=bank["deadlines"],
                frozen=True,
                require_seed=True,
            )
            verifier.refreshes = NegativeRefreshes(
                verifier.oracle, [event], [self.original[1]["case"]]
            )
            capture = self.packet(1, 1.7, 5)
            with self.assertRaises(AssertionError):
                verifier.verify(capture["case"], capture)

    def test_wall_rollback_cannot_move_monotonic_deadline_across_phases(self):
        first, second = self.packet(0, 0, 2), self.packet(1, 1, 1)
        second["checked_at"] -= 0.649
        with self.assertRaisesRegex(AssertionError, "clock offsets are discontinuous"):
            freeze(self.public, [first, second], [])


if __name__ == "__main__":
    unittest.main()
