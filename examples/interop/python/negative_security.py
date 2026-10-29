"""Fail-closed and CD controls for deliberately bogus signed negative fixtures."""

import dns.dnssec
import dns.flags
import dns.message
import dns.rdatatype
import dns.zone

from negative_evidence import NegativeVerifier
from recursive_evidence import authenticated_keys, rrset


def verify(public, case, capture, reason):
    query = dns.message.from_wire(bytes.fromhex(capture["query"]))
    reply = dns.message.from_wire(bytes.fromhex(capture["response"]))
    assert len(query.question) == 1 and query.question[0].name == dns.name.from_text(
        case["name"]
    )
    assert (
        query.question[0].rdtype == dns.rdatatype.from_text(case["rtype"])
        and query.question[0].rdclass == 1
    )
    assert (
        query.opcode() == 0
        and query.flags & dns.flags.RD
        and not query.flags & dns.flags.QR
    )
    assert query.edns == 0 and query.ednsflags & dns.flags.DO
    cd = bool(query.flags & dns.flags.CD)
    assert capture["cd"] is cd
    assert (
        query.is_response(reply)
        and reply.flags & dns.flags.RA
        and reply.flags & dns.flags.RD
    )
    assert bool(reply.flags & dns.flags.CD) == cd and not reply.flags & (
        dns.flags.AD | dns.flags.AA | dns.flags.TC
    )
    if reason == "bad-ds":
        try:
            authenticated_keys(public, capture["checked_at"], bad=True)
        except AssertionError as error:
            assert "DS does not match" in str(error)
        else:
            raise AssertionError("bad DS authenticated")
    else:
        assert reason == "bad-signature"
        bad = dns.zone.from_text(
            public["bad_leaf"], origin="example.test.", relativize=False
        )
        owner = dns.name.from_text(public["bad_signature"]["owner"])
        kind = public["bad_signature"]["covers"]
        keys = authenticated_keys(public, capture["checked_at"])
        try:
            dns.dnssec.validate(
                rrset(bad, owner, kind),
                rrset(bad, owner, dns.rdatatype.RRSIG, kind),
                keys,
                now=capture["checked_at"],
            )
        except dns.dnssec.ValidationFailure:
            pass
        else:
            raise AssertionError("corrupted source signature validated")
    if cd:
        verifier = NegativeVerifier(
            public, capture["checked_at"], trusted=reason != "bad-ds"
        )
        return verifier.verify(
            case, capture, cd=True, ad=False, bad=reason == "bad-signature"
        )
    assert reply.rcode() == 2 and not reply.answer
    return dict(
        flags=reply.flags,
        rcode=reply.rcode(),
        response_bytes=len(bytes.fromhex(capture["response"])),
    )
