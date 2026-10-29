"""Independent signed-negative packet, proof and receive-deadline checks."""

import math
import hashlib
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdatatype

from recursive_evidence import Verifier, APEX, rrset, record_key
from negative_denial import Denial


class NegativeVerifier(Verifier):
    def __init__(
        self,
        public,
        checked_at,
        deadlines=None,
        trusted=True,
        frozen=False,
        require_seed=False,
    ):
        super().__init__(public, checked_at, deadlines=deadlines, trusted=trusted)
        self.oracle = Denial(self.leaf, public["denial"])
        self.insecure_cuts = set()
        self.bad_signatures = 0
        self.frozen = frozen
        self.require_seed = require_seed

    def signed(self, rr, response, capture, bad=False):
        when, mono = capture["checked_at"], capture["received_monotonic_ns"]
        uncertainty = capture.get("clock_uncertainty_seconds", 0)
        assert 0 <= uncertainty <= 0.052
        original = rrset(self.leaf, rr.name, rr.rdtype)
        assert set(rr) == set(original), "data differs from controlled signed catalog"
        signatures = [
            sig
            for sig in response.authority + response.answer
            if sig.rdtype == dns.rdatatype.RRSIG
            and sig.name == rr.name
            and sig.covers == rr.rdtype
        ]
        assert len(signatures) == 1 and signatures[0]
        identity = hashlib.sha256(
            record_key(rr).encode()
            + self.key_identity
            + b"".join(sorted(sig.to_wire(canonicalize=True) for sig in signatures[0]))
        ).hexdigest()
        upper = original.ttl
        if rr.rdtype == dns.rdatatype.SOA:
            upper = min(upper, original[0].minimum)
        for signature in signatures[0]:
            assert (
                signature.signer == APEX
                and signature.inception <= when - uncertainty
                and when + uncertainty <= signature.expiration
            )
            bound = min(
                upper, signature.original_ttl, signature.expiration - when - uncertainty
            )
            assert 0 <= rr.ttl <= math.ceil(bound) and 0 <= signatures[
                0
            ].ttl <= math.ceil(bound)
            key = identity, signature.to_wire(), self.key_identity
            if key not in self.math:
                try:
                    dns.dnssec.validate_rrsig(rr, signature, self.keys, now=when)
                except dns.dnssec.ValidationFailure:
                    assert bad and rr.rdtype in (
                        dns.rdatatype.NSEC,
                        dns.rdatatype.NSEC3,
                    )
                    self.bad_signatures += 1
                else:
                    self.math.add(key)
                    self.math_operations += 1
        if self.refreshes is not None:
            renewed = self.refreshes.renew(
                identity,
                rr,
                when,
                mono,
                upper,
                min(sig.expiration for sig in signatures[0]),
                self.deadlines.get(identity),
            )
            if renewed is not None:
                self.deadlines[identity] = renewed
        assert not self.require_seed or identity in self.deadlines, (
            "proof has no frozen admission or acquisition witness"
        )
        if identity in self.deadlines:
            assert mono <= self.deadlines[identity] + 1_000_000_000, (
                "received after observed negative deadline"
            )
            remaining = (self.deadlines[identity] - mono) / 1e9
            assert max(rr.ttl, signatures[0].ttl) <= math.ceil(
                max(0, remaining + uncertainty)
            ), "negative TTL exceeded observed deadline"
        if identity not in self.deadlines:
            self.deadlines[identity] = (
                mono + min(rr.ttl, signatures[0].ttl) * 1_000_000_000
            )
        elif not self.frozen:
            self.deadlines[identity] = min(
                self.deadlines[identity],
                mono + min(rr.ttl, signatures[0].ttl) * 1_000_000_000,
            )
        self.signed_rrsets += 1
        self.ttl_checks += 2

    def verify(self, case, capture, cd=False, ad=True, bad=False):
        query = dns.message.from_wire(bytes.fromhex(capture["query"]))
        response = dns.message.from_wire(bytes.fromhex(capture["response"]))
        when = capture["checked_at"]
        uncertainty = capture.get("clock_uncertainty_seconds", 0)
        assert 0 <= uncertainty <= 0.052
        if self.chain_window:
            assert (
                self.chain_window[0] <= when - uncertainty
                and when + uncertainty <= self.chain_window[1]
            ), "chain signature expired at receive"
        name = dns.name.from_text(case["name"])
        qtype = dns.rdatatype.from_text(case["rtype"])
        assert len(query.question) == 1 and query.question[0].name == name
        assert query.question[0].rdtype == qtype and query.question[0].rdclass == 1
        assert (
            query.opcode() == 0
            and not query.flags & dns.flags.QR
            and query.flags & dns.flags.RD
        )
        assert (
            bool(query.flags & dns.flags.CD) == cd
            and query.edns == 0
            and query.ednsflags & dns.flags.DO
        )
        assert (
            query.is_response(response)
            and response.flags & dns.flags.RD
            and response.flags & dns.flags.RA
        )
        assert not response.flags & (dns.flags.AA | dns.flags.TC)
        assert (
            bool(response.flags & dns.flags.CD) == cd
            and bool(response.flags & dns.flags.AD) == ad
        )
        assert (
            response.edns == 0
            and response.ednsflags & dns.flags.DO
            and not response.additional
        )
        if case["kind"] in ("positive", "insecure-positive"):
            data = [rr for rr in response.answer if rr.rdtype != dns.rdatatype.RRSIG]
            assert response.rcode() == 0 and len(data) == 1 and len(data[0]) == 1
            assert (
                data[0].name == name
                and data[0].rdtype == qtype
                and data[0].rdclass == 1
                and data[0][0].to_text() == case["value"]
            )
            if case["kind"] == "insecure-positive":
                assert not ad and any(
                    name.is_subdomain(cut) for cut in self.insecure_cuts
                )
                assert not response.authority and all(
                    rr.rdtype != dns.rdatatype.RRSIG for rr in response.answer
                )
                assert 0 <= data[0].ttl <= 300
            else:
                self.signed(data[0], response, capture)
                assert all(
                    rr.name == name and rr.covers == qtype
                    for rr in response.answer
                    if rr.rdtype == dns.rdatatype.RRSIG
                )
        else:
            self.oracle.verify(case, response)
            soas = [rr for rr in response.authority if rr.rdtype == dns.rdatatype.SOA]
            assert len(soas) == 1 and soas[0].name == APEX and len(soas[0]) == 1
            assert all(
                rr.rdtype
                in (
                    dns.rdatatype.SOA,
                    dns.rdatatype.NSEC,
                    dns.rdatatype.NSEC3,
                    dns.rdatatype.RRSIG,
                )
                and rr.rdclass == 1
                for rr in response.authority
            )
            signed = set()
            for rr in response.authority:
                if rr.rdtype == dns.rdatatype.RRSIG:
                    continue
                self.signed(rr, response, capture, bad)
                signed.add((rr.name, rr.rdtype))
            assert all(
                (rr.name, rr.covers) in signed
                for rr in response.authority
                if rr.rdtype == dns.rdatatype.RRSIG
            )
            if case["kind"] == "ds-nodata":
                self.insecure_cuts.add(name)
        if bad:
            assert self.bad_signatures > 0, (
                "deliberately corrupted signature was not returned"
            )
        self.responses += 1
        return dict(
            flags=response.flags,
            rcode=response.rcode(),
            response_bytes=len(bytes.fromhex(capture["response"])),
        )
