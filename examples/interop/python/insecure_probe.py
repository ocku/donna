"""Independently validate signed DS denial and unsigned recursive responses."""

import argparse
import base64
import copy
import json
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rdataset
import dns.rrset
import dns.zone

import dname_recursive_probe as base

ROOT = dns.name.from_text(".")
PARENT = dns.name.from_text("test.")
CHILD = dns.name.from_text("example.test.")


def trusted_parent():
    root = dns.zone.from_file("/work/root/active.db", origin=ROOT, relativize=False)
    parent = dns.zone.from_file("/work/tld/active.db", origin=PARENT, relativize=False)
    anchor = dns.zone.from_file(
        "/work/anchors.zone", origin=ROOT, relativize=False, check_origin=False
    ).get_rdataset(ROOT, dns.rdatatype.DNSKEY)
    keys = base.rrset(root, ROOT, dns.rdatatype.DNSKEY)
    sigs = base.rrset(root, ROOT, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
    assert anchor, "missing root anchor"
    dns.dnssec.validate(keys, sigs, {ROOT: anchor})
    ds = base.rrset(root, PARENT, dns.rdatatype.DS)
    dns.dnssec.validate(
        ds,
        base.rrset(root, PARENT, dns.rdatatype.RRSIG, dns.rdatatype.DS),
        {ROOT: keys},
    )
    parent_keys = base.rrset(parent, PARENT, dns.rdatatype.DNSKEY)
    matched = [
        key
        for key in parent_keys
        if any(ds_item == dns.dnssec.make_ds(PARENT, key, "SHA256") for ds_item in ds)
    ]
    assert matched, "parent DS mismatch"
    dns.dnssec.validate(
        parent_keys,
        base.rrset(parent, PARENT, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY),
        {PARENT: dns.rdataset.from_rdata_list(parent_keys.ttl, matched)},
    )
    assert parent.get_rdataset(CHILD, dns.rdatatype.DS) is None, (
        "fixture contains child DS"
    )
    return {PARENT: parent_keys}


def has_type(record, rtype):
    window, offset = divmod(int(rtype), 256)
    for number, bitmap in record.windows:
        if number == window and offset // 8 < len(bitmap):
            return bool(bitmap[offset // 8] & (0x80 >> (offset % 8)))
    return False


def validate_proof(request, response, keys, mode, authenticate=True):
    assert request.is_response(response) and response.rcode() == 0
    assert response.flags & dns.flags.AA and not response.flags & dns.flags.TC
    assert not response.answer, "unexpected DS answer"
    kind = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    proofs = [rr for rr in response.authority if rr.rdtype == kind]
    assert proofs, "missing DS denial"
    for rr in proofs:
        sigs = [
            sig
            for sig in response.authority
            if sig.name == rr.name
            and sig.rdtype == dns.rdatatype.RRSIG
            and sig.covers == kind
        ]
        assert len(sigs) == 1, "missing denial signature"
        if authenticate:
            dns.dnssec.validate(rr, sigs[0], keys)
    records = [(rr.name, item) for rr in proofs for item in rr]
    if mode == "nsec":
        matches = [item for name, item in records if name == CHILD]
    elif mode == "nsec3":
        matches = [
            item
            for name, item in records
            if name.labels[0].decode().upper()
            == dns.dnssec.nsec3_hash(CHILD, item.salt, item.iterations, item.algorithm)
        ]
    else:
        matches = []
        assert any(
            name.labels[0].decode().upper()
            == dns.dnssec.nsec3_hash(PARENT, item.salt, item.iterations, item.algorithm)
            for name, item in records
        ), "missing closest encloser"
        assert any(
            item.flags & 1
            and base.covered(
                name.labels[0].decode().upper(),
                base64.b32hexencode(item.next).decode().rstrip("="),
                dns.dnssec.nsec3_hash(
                    CHILD, item.salt, item.iterations, item.algorithm
                ),
            )
            for name, item in records
        ), "missing opt-out coverage"
        return
    assert len(matches) == 1, "missing exact denial record"
    assert has_type(matches[0], dns.rdatatype.NS), "missing delegation NS bit"
    assert not any(
        has_type(matches[0], kind)
        for kind in (dns.rdatatype.DS, dns.rdatatype.SOA, dns.rdatatype.CNAME)
    ), "invalid delegation bitmap"


def parent_proof(keys, mode, bad_proof):
    request = dns.message.make_query(CHILD, "DS", want_dnssec=True, payload=1232)
    for attempt in range(30):
        try:
            response = dns.query.udp(request, "172.29.53.71", timeout=1)
            break
        except Exception:
            if attempt == 29:
                raise
            time.sleep(0.1)
    if bad_proof:
        # First check the proof shape and type bitmap, then require a genuine
        # cryptographic validation failure rather than any unrelated exception.
        validate_proof(request, response, keys, mode, authenticate=False)
        try:
            validate_proof(request, response, keys, mode)
        except dns.dnssec.ValidationFailure:
            print(
                json.dumps({"bad_parent_proof": response.to_text(), "rejected": True}),
                flush=True,
            )
            return
        raise AssertionError("tampered denial unexpectedly authenticates")
    validate_proof(request, response, keys, mode)
    for altered in ("drop-proofs", "drop-signatures"):
        broken = copy.deepcopy(response)
        if altered == "drop-proofs":
            broken.authority = [
                rr
                for rr in broken.authority
                if rr.rdtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
            ]
        else:
            broken.authority = [
                rr for rr in broken.authority if rr.rdtype != dns.rdatatype.RRSIG
            ]
        try:
            validate_proof(request, broken, keys, mode)
        except Exception:
            pass
        else:
            raise AssertionError("invalid parent proof accepted: " + altered)
    print(
        json.dumps({"parent_proof": response.to_text(), "fault_tests_passed": 2}),
        flush=True,
    )


def validate_child(request, response, rcode, expected, cd):
    assert request.is_response(response) and response.rcode() == rcode, (
        "wrong RCODE or question"
    )
    assert response.flags & dns.flags.RD and response.flags & dns.flags.RA, (
        "missing RD/RA"
    )
    assert not response.flags & (dns.flags.AD | dns.flags.AA | dns.flags.TC), (
        "unsigned child marked authentic or incomplete"
    )
    assert bool(response.flags & dns.flags.CD) == cd, "CD not preserved"
    records = [
        (
            rr.name.to_text().lower(),
            dns.rdatatype.to_text(rr.rdtype),
            item.to_text().lower(),
        )
        for rr in response.answer
        for item in rr
    ]
    assert sorted(records) == sorted(expected), f"unexpected answer: {records!r}"
    assert all(rr.rdclass == 1 for rr in response.answer + response.authority)
    if not expected:
        assert any(
            rr.rdtype == dns.rdatatype.SOA and rr.name == CHILD
            for rr in response.authority
        ), "missing child SOA"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "server", "protocol", "mode"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bad-proof", action="store_true")
    args = parser.parse_args()
    parent_proof(trusted_parent(), args.mode, args.bad_proof)
    cases = (
        (
            "positive",
            "www.example.test.",
            "A",
            0,
            [("www.example.test.", "A", "192.0.2.80")],
        ),
        (
            "alias",
            "alias.example.test.",
            "A",
            0,
            [
                ("alias.example.test.", "CNAME", "www.example.test."),
                ("www.example.test.", "A", "192.0.2.80"),
            ],
        ),
        ("nodata", "www.example.test.", "AAAA", 0, []),
        ("nxdomain", "absent.example.test.", "A", 3, []),
    )
    failed = []
    for cd in (False, True):
        for case, name, kind, rcode, answer in cases[:1] if args.bad_proof else cases:
            for repeat in (0, 1):
                request = dns.message.make_query(
                    name, kind, want_dnssec=True, payload=1232
                )
                if cd:
                    request.flags |= dns.flags.CD
                reply, error = None, None
                try:
                    reply = getattr(dns.query, args.protocol)(
                        request, args.host, port=args.port, timeout=20
                    )
                    if args.bad_proof and not cd:
                        assert request.is_response(reply) and reply.rcode() == 2, (
                            "invalid denial was not rejected"
                        )
                        assert reply.flags & dns.flags.RD and reply.flags & dns.flags.RA
                        assert not reply.answer and not reply.flags & (
                            dns.flags.AD | dns.flags.CD | dns.flags.AA | dns.flags.TC
                        )
                    else:
                        validate_child(request, reply, rcode, answer, cd)
                    if not args.bad_proof or cd:
                        broken = copy.deepcopy(reply)
                        broken.flags |= dns.flags.AD
                        try:
                            validate_child(request, broken, rcode, answer, cd)
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError(
                                "unsigned response with forged AD accepted"
                            )
                except Exception as exc:
                    error = str(exc) or repr(exc)
                    failed.append((case, cd, repeat, error))
                print(
                    json.dumps(
                        {
                            "server": args.server,
                            "protocol": args.protocol,
                            "case": case,
                            "cd": cd,
                            "repeat": repeat,
                            "bad_proof": args.bad_proof,
                            "passed": error is None,
                            "error": error,
                            "response": reply.to_text() if reply else None,
                        }
                    ),
                    flush=True,
                )
    if failed:
        raise SystemExit("insecure child failures: " + repr(failed))


if __name__ == "__main__":
    main()
