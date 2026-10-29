"""Verify signatures and denial witnesses from independent signed local zones."""

import base64
import itertools
import json
from pathlib import Path
import sys

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

APEX = dns.name.from_text("example.test.")


def covers(owner, next_name, candidate):
    if owner < next_name:
        return owner < candidate < next_name
    return candidate > owner or candidate < next_name


def witnesses(response, kind):
    return [
        (rrset.name, item)
        for rrset in response.authority
        if rrset.rdtype == kind
        for item in rrset
    ]


def nsec3_hash(name, record):
    return dns.dnssec.nsec3_hash(name, record.salt, record.iterations, record.algorithm)


def nsec3_matches(records, name):
    return any(
        owner.labels[0].decode().upper() == nsec3_hash(name, item)
        for owner, item in records
    )


def nsec3_covers(records, name, optout=False):
    for owner, item in records:
        start = owner.labels[0].decode().upper()
        end = base64.b32hexencode(item.next).decode().rstrip("=")
        hashed = nsec3_hash(name, item)
        if covers(start, end, hashed) and (not optout or item.flags & 1):
            return True
    return False


def verify_signatures(response, keys, now=None):
    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NS):
                continue  # Parent-side referral NS is intentionally unsigned.
            signatures = next(
                (
                    candidate
                    for candidate in section
                    if candidate.name == rrset.name
                    and candidate.rdtype == dns.rdatatype.RRSIG
                    and candidate.covers == rrset.rdtype
                ),
                None,
            )
            assert signatures is not None, f"missing RRSIG: {rrset.name} {rrset.rdtype}"
            dns.dnssec.validate(rrset, signatures, keys, now=now)


def verify_denial(response, mode, name, kind):
    wildcard = dns.name.from_text("*.wild.example.test.")
    closest = dns.name.from_text("wild.example.test.")
    # m.wild and q.wild are next-closer names for the two expansions.
    next_closer = dns.name.Name(name.labels[-5:])
    if kind == "wildcard-nodata":
        assert not response.answer and response.rcode() == 0
        if mode == "nsec":
            records = witnesses(response, dns.rdatatype.NSEC)
            assert any(owner == wildcard for owner, _ in records), (
                "missing wildcard NODATA NSEC"
            )
            assert any(covers(owner, item.next, name) for owner, item in records), (
                "missing NSEC proving expanded QNAME does not exist"
            )
        else:
            records = witnesses(response, dns.rdatatype.NSEC3)
            assert nsec3_matches(records, wildcard), "missing wildcard matching NSEC3"
            assert nsec3_matches(records, closest), "missing closest-encloser NSEC3"
            assert nsec3_covers(records, next_closer), (
                "missing next-closer covering NSEC3"
            )
    elif kind == "unsigned-delegation":
        if mode == "nsec":
            records = witnesses(response, dns.rdatatype.NSEC)
            assert any(owner == name for owner, _ in records), "missing delegation NSEC"
        else:
            records = witnesses(response, dns.rdatatype.NSEC3)
            assert nsec3_matches(records, name) or (
                nsec3_matches(records, APEX)
                and nsec3_covers(records, name, optout=True)
            ), "incomplete opt-out delegation denial"
    elif kind in ("empty-nodata", "alias-empty-nodata"):
        if kind == "alias-empty-nodata":
            name = dns.name.from_text("empty.example.test.")
        assert response.rcode() == 0
        if mode == "nsec":
            records = witnesses(response, dns.rdatatype.NSEC)
            assert any(
                covers(owner, item.next, name) and item.next.is_subdomain(name)
                for owner, item in records
            ), "missing empty-nonterminal covering NSEC"
        else:
            assert nsec3_matches(witnesses(response, dns.rdatatype.NSEC3), name), (
                "missing empty-nonterminal matching NSEC3"
            )


def main():
    from probe import PROTOCOLS, exchange

    mode = sys.argv[1]
    key_query = dns.message.make_query(APEX, "DNSKEY", want_dnssec=True)
    key_response = dns.query.tcp(key_query, "172.29.53.24", timeout=3)
    keys = {
        APEX: next(r for r in key_response.answer if r.rdtype == dns.rdatatype.DNSKEY)
    }
    verify_signatures(key_response, keys)
    captures = Path("/suite/captures") / mode
    captures.mkdir(parents=True, exist_ok=True)
    (captures / "keys.wire").write_bytes(key_response.to_wire())
    cases = (
        ("m.wild.example.test.", "A", "wildcard-nodata"),
        ("p.q.wild.example.test.", "A", "wildcard-nodata"),
        ("child.example.test.", "DS", "unsigned-delegation"),
        ("child.example.test.", "A", "unsigned-delegation"),
        ("www.example.test.", "A", "positive"),
        ("alias.example.test.", "A", "positive"),
        ("m.wild.example.test.", "TXT", "positive"),
        ("missing.example.test.", "A", "negative"),
        ("empty.example.test.", "A", "empty-nodata"),
        ("deep.empty.example.test.", "AAAA", "empty-nodata"),
        ("alias-empty.example.test.", "A", "alias-empty-nodata"),
        ("missing.empty.example.test.", "A", "negative"),
    )
    failures = []
    for protocol, (text, qtype, kind) in itertools.product(PROTOCOLS, cases):
        name = dns.name.from_text(text)
        query = dns.message.make_query(name, qtype, want_dnssec=True)
        query.flags &= ~dns.flags.RD
        expected = dns.query.tcp(query, "172.29.53.24", timeout=3)
        if protocol == "udp":
            (captures / f"{text}{qtype}.wire").write_bytes(expected.to_wire())
        verify_signatures(expected, keys)
        verify_denial(expected, mode, name, kind)
        try:
            actual = exchange(query, "172.29.53.14", protocol, "/certs/cert.pem")
            verify_signatures(actual, keys)
            verify_denial(actual, mode, name, kind)
            assert actual.rcode() == expected.rcode()
            assert bool(actual.flags & dns.flags.AA) == bool(
                expected.flags & dns.flags.AA
            )
        except Exception as error:
            failures.append(
                {
                    "mode": mode,
                    "protocol": protocol,
                    "name": text,
                    "qtype": qtype,
                    "error": str(error),
                }
            )
    print(
        json.dumps(
            {
                "signed_checks": len(cases) * len(PROTOCOLS),
                "mode": mode,
                "failures": failures,
            },
            indent=2,
        ),
        flush=True,
    )
    if failures:
        raise SystemExit(f"{len(failures)} independently signed {mode} checks failed")


if __name__ == "__main__":
    main()
