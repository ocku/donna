"""Fault tests for DNAME response expectations and received wire inspection."""

import struct
import unittest

from dname_authority_probe import cases, uncompressed_dname_targets, validate


def packet(target):
    header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    return header + b"\0" + struct.pack("!HHIH", 39, 1, 120, len(target)) + target


class GateTests(unittest.TestCase):
    def test_rejects_compressed_or_malformed_dname_rdata(self):
        self.assertEqual(uncompressed_dname_targets(packet(b"\x01a\0")), 1)
        for target in (b"\xc0\x0c", b"\x01a", b"\0\x00", b"\x40"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                uncompressed_dname_targets(packet(target))

    def test_rejects_truncated_packet(self):
        wire = packet(b"\x01a\0")
        for length in range(len(wire)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                uncompressed_dname_targets(wire[:length])

    def test_requires_complete_dname_chain_and_ttl(self):
        case = next(case for case in cases() if case[0] == "local-a")
        valid = {"rcode": 0, "aa": True, "tc": False, "answer": case[4], "soa": []}
        validate(case, valid)
        for broken in (
            dict(valid, answer=case[4][1:]),
            dict(valid, answer=case[4][:2]),
            dict(valid, answer=[(a, b, c, 0) for a, b, c, _ in case[4]]),
            dict(valid, aa=False),
            dict(valid, tc=True),
            dict(valid, rcode=3),
        ):
            with self.subTest(broken=broken), self.assertRaises(AssertionError):
                validate(case, broken)

    def test_requires_yxdomain_and_dname_on_overflow(self):
        case = next(case for case in cases() if case[0] == "overflow")
        valid = {"rcode": 6, "aa": True, "tc": False, "answer": case[4], "soa": []}
        validate(case, valid)
        for broken in (dict(valid, rcode=0), dict(valid, answer=[])):
            with self.subTest(broken=broken), self.assertRaises(AssertionError):
                validate(case, broken)


if __name__ == "__main__":
    unittest.main()
