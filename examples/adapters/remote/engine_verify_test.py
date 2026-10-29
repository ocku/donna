"""Faults against signed oracle models or an explicitly selected reply corpus."""

import copy
import json
import os
from pathlib import Path
import unittest

import dns.message
import dns.name
import dns.rdata
import dns.rdatatype

from engine_verify import verify
from engine_model import record


class VerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get("DONNA_ENGINE_CORPUS")
        cls.original = json.loads(Path(selected).read_text()) if selected else record()

    def rejects(self, data):
        with self.assertRaises(Exception):
            verify(data["public"], data["runs"])

    def test_complete_signed_scenario_matrix(self):
        result = verify(self.original["public"], self.original["runs"])
        self.assertEqual(result["replies"], 73)

    def test_expiry_refresh_requires_a_matching_completed_acquisition(self):
        data = copy.deepcopy(self.original)
        lines = data["runs"][0]["output"].splitlines()
        data["runs"][0]["output"] = "\n".join(
            line for line in lines if not line.startswith("UPSTREAM expiry-after ")
        )
        self.rejects(data)

    def test_duplicate_label_missing_run_and_duplicate_identity_rejected(self):
        for fault in (
            "duplicate-label",
            "missing-run",
            "duplicate-identity",
            "missing-exit",
            "missing-container",
            "empty-container",
        ):
            data = copy.deepcopy(self.original)
            if fault == "missing-run":
                data["runs"].pop()
            elif fault == "duplicate-identity":
                data["runs"][3]["container"] = data["runs"][0]["container"]
            elif fault == "missing-exit":
                data["runs"][0].pop("exit_code")
            elif fault == "missing-container":
                data["runs"][0].pop("container")
            elif fault == "empty-container":
                data["runs"][0]["container"] = ""
            else:
                lines = data["runs"][0]["output"].splitlines()
                original = next(
                    line for line in lines if line.startswith("REPLY provider-first-a ")
                )
                position = next(
                    i
                    for i, line in enumerate(lines)
                    if line.startswith("REPLY provider-first-aaaa ")
                )
                lines[position] = original
                data["runs"][0]["output"] = "\n".join(lines)
            with self.subTest(fault=fault):
                self.rejects(data)

    def test_data_signature_ad_and_expired_ttl_faults_rejected(self):
        for fault in ("data", "signature", "ad", "question", "expired-ttl"):
            data = copy.deepcopy(self.original)
            lines = data["runs"][0]["output"].splitlines()
            position = next(
                i
                for i, line in enumerate(lines)
                if line.startswith("REPLY provider-repeat-a ")
            )
            fields = lines[position].split()
            reply = dns.message.from_wire(bytes.fromhex(fields[-1]))
            if fault == "ad":
                reply.flags &= ~dns.flags.AD
            elif fault == "question":
                reply.question[0].name = dns.name.from_text("wrong.example.test.")
            elif fault == "data":
                rr = next(rr for rr in reply.answer if rr.rdtype == dns.rdatatype.A)
                rr.clear()
                rr.add(dns.rdata.from_text(rr.rdclass, rr.rdtype, "192.0.2.99"))
            elif fault == "signature":
                rr = next(rr for rr in reply.answer if rr.rdtype == dns.rdatatype.RRSIG)
                sig = rr[0]
                rr.clear()
                rr.add(
                    sig.replace(
                        signature=bytes([sig.signature[0] ^ 1]) + sig.signature[1:]
                    )
                )
            else:
                fields[2] = str(int(fields[2]) + 400_000_000_000)
                fields[3] = str(int(fields[3]) + 400_000_000_000)
                for rr in reply.answer:
                    rr.ttl = 1
            fields[-1] = reply.to_wire().hex()
            lines[position] = " ".join(fields)
            data["runs"][0]["output"] = "\n".join(lines)
            with self.subTest(fault=fault):
                self.rejects(data)

    def test_good_ds_cannot_replace_required_served_bogus_witness(self):
        data = copy.deepcopy(self.original)
        lines = data["runs"][0]["output"].splitlines()
        position = next(
            i for i, line in enumerate(lines) if line.startswith("DS-WITNESS ")
        )
        fields = lines[position].split()
        reply = dns.message.from_wire(bytes.fromhex(fields[-1]))
        from recursive_evidence import zones, rrset

        tld = zones(data["public"])["tld"]
        owner = dns.name.from_text("example.test.")
        reply.answer = [
            rrset(tld, owner, dns.rdatatype.DS),
            rrset(tld, owner, dns.rdatatype.RRSIG, dns.rdatatype.DS),
        ]
        fields[-1] = reply.to_wire().hex()
        lines[position] = " ".join(fields)
        data["runs"][0]["output"] = "\n".join(lines)
        self.rejects(data)


if __name__ == "__main__":
    unittest.main()
