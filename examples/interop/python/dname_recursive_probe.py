"""Verify a recursive DNAME response from a signed three-zone hierarchy."""

import argparse
import base64
import copy
import json

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rdataset
import dns.rcode
import dns.rrset
import dns.zone


def cases():
    long_target = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 50, "invalid."))
    return (
        (
            "positive",
            "www.old.example.test.",
            "A",
            0,
            [
                ("old.example.test.", "DNAME", "dest.example.test."),
                ("www.old.example.test.", "CNAME", "www.dest.example.test."),
                ("www.dest.example.test.", "A", "192.0.2.80"),
            ],
        ),
        (
            "cname-query",
            "www.old.example.test.",
            "CNAME",
            0,
            [
                ("old.example.test.", "DNAME", "dest.example.test."),
                ("www.old.example.test.", "CNAME", "www.dest.example.test."),
            ],
        ),
        (
            "chain",
            "www.hop.example.test.",
            "A",
            0,
            [
                ("hop.example.test.", "DNAME", "old.example.test."),
                ("www.hop.example.test.", "CNAME", "www.old.example.test."),
                ("old.example.test.", "DNAME", "dest.example.test."),
                ("www.old.example.test.", "CNAME", "www.dest.example.test."),
                ("www.dest.example.test.", "A", "192.0.2.80"),
            ],
        ),
        (
            "cname-into-chain",
            "alias.example.test.",
            "A",
            0,
            [
                ("alias.example.test.", "CNAME", "www.hop.example.test."),
                ("hop.example.test.", "DNAME", "old.example.test."),
                ("www.hop.example.test.", "CNAME", "www.old.example.test."),
                ("old.example.test.", "DNAME", "dest.example.test."),
                ("www.old.example.test.", "CNAME", "www.dest.example.test."),
                ("www.dest.example.test.", "A", "192.0.2.80"),
            ],
        ),
        (
            "terminal-nxdomain",
            "missing.old.example.test.",
            "A",
            3,
            [
                ("old.example.test.", "DNAME", "dest.example.test."),
                ("missing.old.example.test.", "CNAME", "missing.dest.example.test."),
            ],
        ),
        (
            "overflow",
            "123.long.example.test.",
            "A",
            6,
            [("long.example.test.", "DNAME", long_target)],
        ),
    )


def rrset(zone, name, rtype, covers=0):
    data = zone.get_rdataset(name, rtype, covers=covers)
    assert data is not None, f"missing {name} {rtype}"
    return dns.rrset.from_rdata_list(name, data.ttl, list(data))


def validated_keys():
    origins = [dns.name.from_text(value) for value in (".", "test.", "example.test.")]
    zones = [
        dns.zone.from_file(f"/work/{name}/active.db", origin=origin, relativize=False)
        for name, origin in zip(("root", "tld", "leaf"), origins)
    ]
    anchors = dns.zone.from_file(
        "/work/anchors.zone", origin=origins[0], relativize=False, check_origin=False
    ).get_rdataset(origins[0], dns.rdatatype.DNSKEY)
    assert anchors, "missing root trust anchor"
    trusted = {origins[0]: anchors}
    parent_keys = None
    for index, (origin, zone) in enumerate(zip(origins, zones)):
        keys = rrset(zone, origin, dns.rdatatype.DNSKEY)
        signatures = rrset(zone, origin, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
        if index:
            parent = zones[index - 1]
            ds = rrset(parent, origin, dns.rdatatype.DS)
            ds_signatures = rrset(parent, origin, dns.rdatatype.RRSIG, dns.rdatatype.DS)
            dns.dnssec.validate(ds, ds_signatures, parent_keys)
            matching = [
                key
                for key in keys
                if any(item == dns.dnssec.make_ds(origin, key, "SHA256") for item in ds)
            ]
            assert matching, f"DS does not match {origin} DNSKEY"
            trusted = {origin: dns.rdataset.from_rdata_list(keys.ttl, matching)}
        dns.dnssec.validate(keys, signatures, trusted)
        parent_keys = {origin: keys}
    return parent_keys


def covered(start, end, candidate):
    return (
        start < candidate < end if start < end else candidate > start or candidate < end
    )


def validate_denial(reply, keys, mode):
    apex = dns.name.from_text("example.test.")
    closest = dns.name.from_text("dest.example.test.")
    target = dns.name.from_text("missing.dest.example.test.")
    wildcard = dns.name.from_text("*.dest.example.test.")
    soa = [
        rr
        for rr in reply.authority
        if rr.name == apex and rr.rdtype == dns.rdatatype.SOA
    ]
    kind = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    witnesses = [rr for rr in reply.authority if rr.rdtype == kind]
    assert len(soa) == 1 and witnesses, "missing negative SOA or denial witnesses"
    for rr in soa + witnesses:
        sigs = [
            candidate
            for candidate in reply.authority
            if candidate.name == rr.name
            and candidate.rdtype == dns.rdatatype.RRSIG
            and candidate.covers == rr.rdtype
        ]
        assert len(sigs) == 1, "missing negative proof signature"
        dns.dnssec.validate(rr, sigs[0], keys)
    records = [(rr.name, item) for rr in witnesses for item in rr]
    if mode == "nsec":
        assert any(covered(owner, item.next, target) for owner, item in records), (
            "missing NSEC name denial"
        )
        assert any(covered(owner, item.next, wildcard) for owner, item in records), (
            "missing NSEC wildcard denial"
        )
        assert any(
            item.next.is_subdomain(closest) and item.next != closest
            for _, item in records
        ), "missing closest empty-nonterminal evidence"
    else:

        def digest(name, record):
            return dns.dnssec.nsec3_hash(
                name, record.salt, record.iterations, record.algorithm
            )

        def start(owner):
            return owner.labels[0].decode().upper()

        def end(record):
            return base64.b32hexencode(record.next).decode().rstrip("=")

        assert any(start(owner) == digest(closest, item) for owner, item in records), (
            "missing closest NSEC3"
        )
        assert any(
            covered(start(owner), end(item), digest(target, item))
            for owner, item in records
        ), "missing NSEC3 name denial"
        assert any(
            covered(start(owner), end(item), digest(wildcard, item))
            for owner, item in records
        ), "missing NSEC3 wildcard denial"


def validate(case, query, reply, keys, mode):
    assert query.is_response(reply), "uncorrelated response"
    assert reply.rcode() == case[3], f"rcode {reply.rcode()} expected {case[3]}"
    assert reply.flags & dns.flags.RA and reply.flags & dns.flags.RD, "missing RA/RD"
    assert not reply.flags & (dns.flags.AA | dns.flags.TC), "unexpected AA/TC"
    # AD is a useful operational comparison, but RFC 4035 §3.2.3 uses SHOULD
    # for setting it after validation, so it is not the independent crypto gate.
    records = [
        (
            rr.name.to_text().lower(),
            dns.rdatatype.to_text(rr.rdtype),
            item.to_text().lower(),
        )
        for rr in reply.answer
        if rr.rdtype != dns.rdatatype.RRSIG
        for item in rr
    ]
    assert sorted(records) == sorted(case[4]), f"answer {records!r}"
    data = {
        (rr.name, rr.rdtype): rr
        for rr in reply.answer
        if rr.rdtype != dns.rdatatype.RRSIG
    }
    signed = set()
    for rr in reply.answer:
        if rr.rdtype != dns.rdatatype.RRSIG:
            continue
        for sig in rr:
            key = (rr.name, sig.type_covered)
            assert key in data, "unmatched signature"
            dns.dnssec.validate_rrsig(data[key], sig, keys)
            signed.add(key)
    for key, rr in data.items():
        synthesized = rr.rdtype == dns.rdatatype.CNAME and any(
            source.rdtype == dns.rdatatype.DNAME
            and rr.name != source.name
            and rr.name.is_subdomain(source.name)
            and len(source) == 1
            and len(rr) == 1
            and rr[0].target
            == rr.name.relativize(source.name).concatenate(source[0].target)
            for source in data.values()
        )
        if synthesized:
            assert key not in signed, "synthesized CNAME unexpectedly signed"
            source_ttl = next(
                source.ttl
                for source in data.values()
                if source.rdtype == dns.rdatatype.DNAME
                and rr.name.is_subdomain(source.name)
                and rr[0].target
                == rr.name.relativize(source.name).concatenate(source[0].target)
            )
            assert rr.ttl <= source_ttl, "synthesized TTL exceeds DNAME"
        else:
            assert key in signed, f"missing signature for {key}"
    if case[0] == "terminal-nxdomain":
        validate_denial(reply, keys, mode)


def fault_tests(observations, keys, mode):
    def reject(case, query, reply):
        try:
            validate(case, query, reply, keys, mode)
        except Exception:
            return
        raise AssertionError("invalid signed response passed validation")

    case, query, valid = observations["positive"]
    missing = copy.deepcopy(valid)
    missing.answer = [
        rr
        for rr in missing.answer
        if not (rr.rdtype == dns.rdatatype.RRSIG and rr.covers == dns.rdatatype.DNAME)
    ]
    reject(case, query, missing)
    altered = copy.deepcopy(valid)
    for i, rr in enumerate(altered.answer):
        if rr.rdtype == dns.rdatatype.CNAME:
            altered.answer[i] = dns.rrset.from_text(
                rr.name, rr.ttl, "IN", "CNAME", "wrong.example.test."
            )
    reject(case, query, altered)
    case, query, valid = observations["terminal-nxdomain"]
    kind = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    missing = copy.deepcopy(valid)
    missing.authority = [rr for rr in missing.authority if rr.rdtype != kind]
    reject(case, query, missing)
    missing = copy.deepcopy(valid)
    missing.authority = [
        rr
        for rr in missing.authority
        if not (rr.rdtype == dns.rdatatype.RRSIG and rr.covers == kind)
    ]
    reject(case, query, missing)
    return 4


def bad_chain_tests(args):
    try:
        validated_keys()
    except AssertionError as error:
        assert "DS does not match example.test." in str(error), (
            f"unexpected chain failure: {error}"
        )
    else:
        raise AssertionError("bad DS unexpectedly authenticates the leaf")
    apex = dns.name.from_text("example.test.")
    leaf = dns.zone.from_file("/work/leaf/active.db", origin=apex, relativize=False)
    keys = {apex: leaf.get_rdataset(apex, dns.rdatatype.DNSKEY)}
    case = next(value for value in cases() if value[0] == "positive")
    for disabled in (False, True):
        query = dns.message.make_query(case[1], case[2], want_dnssec=True, payload=1232)
        if disabled:
            query.flags |= dns.flags.CD
        reply = None
        error = None
        try:
            reply = getattr(dns.query, args.protocol)(
                query, args.host, port=args.port, timeout=20
            )
            assert query.is_response(reply), "uncorrelated response"
            assert bool(reply.flags & dns.flags.CD) == disabled, "incorrect CD"
            assert not reply.flags & dns.flags.AD, "bad chain was marked authentic"
            if disabled:
                validate(case, query, reply, keys, args.mode)
            else:
                assert reply.rcode() == dns.rcode.SERVFAIL, (
                    f"bad chain returned {reply.rcode()}"
                )
                assert not reply.answer, "bogus data returned with validation enabled"
        except Exception as exc:
            error = str(exc) or repr(exc)
        print(
            json.dumps(
                {
                    "server": args.server,
                    "protocol": args.protocol,
                    "case": "bad-ds-cd" if disabled else "bad-ds",
                    "passed": error is None,
                    "error": error,
                    "rcode": reply.rcode() if reply else None,
                    "ad": bool(reply.flags & dns.flags.AD) if reply else None,
                    "response": reply.to_text() if reply else None,
                }
            ),
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--protocol", choices=("udp", "tcp"), required=True)
    parser.add_argument("--mode", choices=("nsec", "nsec3"), required=True)
    parser.add_argument("--bad-chain", action="store_true")
    args = parser.parse_args()
    if args.bad_chain:
        bad_chain_tests(args)
        return
    keys = validated_keys()
    observations = {}
    for case in cases():
        query = dns.message.make_query(case[1], case[2], want_dnssec=True, payload=1232)
        error = None
        reply = None
        try:
            # Startup can take a moment; query timeouts are not passed as verdicts.
            reply = getattr(dns.query, args.protocol)(
                query, args.host, port=args.port, timeout=20
            )
            validate(case, query, reply, keys, args.mode)
            observations[case[0]] = (case, query, reply)
        except Exception as exc:
            error = str(exc) or repr(exc)
        print(
            json.dumps(
                {
                    "server": args.server,
                    "protocol": args.protocol,
                    "case": case[0],
                    "passed": error is None,
                    "error": error,
                    "rcode": reply.rcode() if reply else None,
                    "ad": bool(reply.flags & dns.flags.AD) if reply else None,
                    "response": reply.to_text() if reply else None,
                }
            ),
            flush=True,
        )
    if len(observations) == len(cases()):
        print(
            json.dumps(
                {
                    "server": args.server,
                    "protocol": args.protocol,
                    "fault_tests_passed": fault_tests(observations, keys, args.mode),
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
