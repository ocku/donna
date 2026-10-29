"""Independent public-chain, signed-answer and monotonic cache-lifetime checks."""

import hashlib
import math
import struct

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone

APEX = dns.name.from_text("example.test.")


def rrset(zone, owner, kind, covers=0):
    dataset = zone.get_rdataset(owner, kind, covers=covers)
    assert dataset is not None, (owner, kind, covers)
    return dns.rrset.from_rdata_list(owner, dataset.ttl, list(dataset))


def zones(public, bad=False):
    return {
        name: dns.zone.from_text(
            public["bad_tld"] if bad and name == "tld" else text,
            origin=public["origins"][name],
            relativize=False,
        )
        for name, text in public["zones"].items()
    }


def authenticated_keys(public, checked_at, bad=False):
    parsed = zones(public, bad)
    root = dns.name.root
    anchors = dns.zone.from_text(
        public["anchors"], origin=root, relativize=False, check_origin=False
    )
    trusted = {root: rrset(anchors, root, dns.rdatatype.DNSKEY)}
    parent = None
    for name in ("root", "tld", "leaf"):
        zone = parsed[name]
        origin = dns.name.from_text(public["origins"][name])
        keys = rrset(zone, origin, dns.rdatatype.DNSKEY)
        if parent is not None:
            parent_zone, parent_keys = parent
            ds = rrset(parent_zone, origin, dns.rdatatype.DS)
            sig = rrset(parent_zone, origin, dns.rdatatype.RRSIG, dns.rdatatype.DS)
            dns.dnssec.validate(ds, sig, parent_keys, now=checked_at)
            matches = [
                key
                for key in keys
                if any(item == dns.dnssec.make_ds(origin, key, "SHA256") for item in ds)
            ]
            assert matches, "authenticated DS does not match leaf DNSKEY"
            trusted = {origin: dns.rdataset.from_rdata_list(keys.ttl, matches)}
        dns.dnssec.validate(
            keys,
            rrset(zone, origin, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY),
            trusted,
            now=checked_at,
        )
        parent = zone, {origin: keys}
    return parent[1]


def record_key(rr):
    data = rr.name.canonicalize().to_wire() + struct.pack("!HH", rr.rdclass, rr.rdtype)
    for item in sorted(record.to_wire(canonicalize=True) for record in rr):
        data += len(item).to_bytes(2, "big") + item
    return hashlib.sha256(data).hexdigest()


class Verifier:
    def __init__(
        self, public, checked_at, deadlines=None, trusted=True, refreshes=None
    ):
        self.public = public
        self.leaf = zones(public)["leaf"]
        self.keys = (
            authenticated_keys(public, checked_at)
            if trusted
            else {APEX: rrset(self.leaf, APEX, dns.rdatatype.DNSKEY)}
        )
        chain = zones(public)
        signatures = []
        if trusted:
            for name in ("root", "tld", "leaf"):
                origin = dns.name.from_text(public["origins"][name])
                signatures.extend(
                    rrset(
                        chain[name], origin, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY
                    )
                )
            for parent, child in (("root", "tld"), ("tld", "leaf")):
                origin = dns.name.from_text(public["origins"][child])
                signatures.extend(
                    rrset(chain[parent], origin, dns.rdatatype.RRSIG, dns.rdatatype.DS)
                )
        self.chain_window = (
            (
                max(sig.inception for sig in signatures),
                min(sig.expiration for sig in signatures),
            )
            if signatures
            else None
        )
        self.key_identity = hashlib.sha256(
            b"".join(sorted(item.to_wire() for item in self.keys[APEX]))
        ).digest()
        self.deadlines = dict(deadlines or {})
        self.refreshes = refreshes
        self.math = set()
        self.responses = self.signed_rrsets = self.math_operations = self.ttl_checks = 0

    def verify(self, case, capture, cd=False, ad=True, enforce_deadlines=True):
        query = dns.message.from_wire(bytes.fromhex(capture["query"]))
        response = dns.message.from_wire(bytes.fromhex(capture["response"]))
        when, monotonic_ns = capture["checked_at"], capture["received_monotonic_ns"]
        uncertainty = capture.get("clock_uncertainty_seconds", 0)
        assert 0 <= uncertainty <= 0.052
        if self.chain_window is not None:
            assert (
                self.chain_window[0] <= when - uncertainty
                and when + uncertainty <= self.chain_window[1]
            ), "public authentication chain expired at receive time"
        assert len(query.question) == 1 and query.question[
            0
        ].name == dns.name.from_text(case["name"])
        assert (
            query.question[0].rdtype == dns.rdatatype.from_text(case["rtype"])
            and query.question[0].rdclass == 1
        )
        assert (
            not query.flags & dns.flags.QR
            and query.opcode() == 0
            and query.flags & dns.flags.RD
        )
        assert query.edns == 0 and query.ednsflags & dns.flags.DO
        assert query.is_response(response) and response.rcode() == 0
        assert response.flags & dns.flags.RA and response.flags & dns.flags.RD
        assert not response.flags & (dns.flags.AA | dns.flags.TC)
        assert bool(response.flags & dns.flags.CD) == cd
        if ad is not None:
            assert bool(response.flags & dns.flags.AD) == ad
        assert response.edns == 0 and response.ednsflags & dns.flags.DO
        assert not response.authority and not response.additional
        data = [rr for rr in response.answer if rr.rdtype != dns.rdatatype.RRSIG]
        expected = {(case["target"], case["rtype"], case["value"])}
        source = None
        if case["kind"] == "dname":
            owner = (
                "shortold.example.test."
                if case["name"].endswith(".shortold.example.test.")
                else "old.example.test."
            )
            target = (
                "shortdest.example.test."
                if owner.startswith("shortold.")
                else "dest.example.test."
            )
            expected |= {
                (owner, "DNAME", target),
                (case["name"], "CNAME", case["target"]),
            }
            source = next((rr for rr in data if rr.rdtype == dns.rdatatype.DNAME), None)
            assert source is not None and len(source) == 1
        observed = {
            (rr.name.to_text(), dns.rdatatype.to_text(rr.rdtype), item.to_text())
            for rr in data
            for item in rr
        }
        assert observed == expected and all(
            rr.rdclass == 1 and len(rr) == 1 for rr in data
        )
        signed_keys = set()
        for rr in data:
            if case["kind"] == "dname" and rr.rdtype == dns.rdatatype.CNAME:
                assert rr.ttl <= source.ttl
                assert rr[0].target == rr.name.relativize(source.name).concatenate(
                    source[0].target
                )
                assert not any(
                    sig.covers == dns.rdatatype.CNAME and sig.name == rr.name
                    for sig in response.answer
                    if sig.rdtype == dns.rdatatype.RRSIG
                )
                self.ttl_checks += 1
                continue
            original = rrset(self.leaf, rr.name, rr.rdtype)
            assert set(rr) == set(original), (
                "answer data not in controlled public authority"
            )
            signatures = [
                sig
                for sig in response.answer
                if sig.rdtype == dns.rdatatype.RRSIG
                and sig.name == rr.name
                and sig.covers == rr.rdtype
            ]
            assert len(signatures) == 1 and signatures[0]
            identity = record_key(rr)
            for signature in signatures[0]:
                assert signature.signer == APEX
                assert (
                    signature.inception <= when - uncertainty
                    and when + uncertainty <= signature.expiration
                )
                upper = min(
                    original.ttl,
                    signature.original_ttl,
                    signature.expiration - when - uncertainty,
                )
                assert 0 <= rr.ttl <= math.ceil(upper)
                assert 0 <= signatures[0].ttl <= math.ceil(upper)
                math_key = identity, signature.to_wire(), self.key_identity
                if math_key not in self.math:
                    dns.dnssec.validate_rrsig(rr, signature, self.keys, now=when)
                    self.math.add(math_key)
                    self.math_operations += 1
            if self.refreshes is not None:
                renewed = self.refreshes.renew(
                    identity,
                    rr,
                    case,
                    when,
                    monotonic_ns,
                    original.ttl,
                    min(sig.expiration for sig in signatures[0]),
                    self.deadlines.get(identity),
                )
                if renewed is not None:
                    self.deadlines[identity] = renewed
            if enforce_deadlines and identity in self.deadlines:
                # A bounded receive grace covers integer TTL rounding and an
                # in-flight TTL0 reply. It never permits indefinite stale use.
                assert monotonic_ns <= self.deadlines[identity] + 1_000_000_000, (
                    "received after observed cache deadline"
                )
                remaining = max(0, (self.deadlines[identity] - monotonic_ns) / 1e9)
                assert max(rr.ttl, signatures[0].ttl) <= math.ceil(remaining) + 1, (
                    "cache TTL exceeds observed admission deadline"
                )
            self.deadlines[identity] = min(
                self.deadlines.get(identity, 2**63),
                monotonic_ns + min(rr.ttl, signatures[0].ttl) * 1_000_000_000,
            )
            self.ttl_checks += 2
            self.signed_rrsets += 1
            signed_keys.add((rr.name, rr.rdtype))
        assert all(
            (sig.name, sig.covers) in signed_keys
            for sig in response.answer
            if sig.rdtype == dns.rdatatype.RRSIG
        )
        self.responses += 1
        return dict(
            flags=response.flags,
            ad=bool(response.flags & dns.flags.AD),
            rcode=response.rcode(),
            signed_rrsets=len(signed_keys),
        )

    def summary(self):
        return dict(
            responses=self.responses,
            signed_rrsets=self.signed_rrsets,
            unique_math_verifications=self.math_operations,
            ttl_checks=self.ttl_checks,
            deadlines=self.deadlines,
        )
