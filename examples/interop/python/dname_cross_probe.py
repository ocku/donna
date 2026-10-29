"""Verify signed DNAME chains crossing separately delegated sibling zones."""

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
import dns.zone

import dname_recursive_probe as base


def cases():
    return (
        (
            "positive",
            "www.old.example.test.",
            "A",
            0,
            [
                ("old.example.test.", "DNAME", "dest.other.test."),
                ("www.old.example.test.", "CNAME", "www.dest.other.test."),
                ("www.dest.other.test.", "A", "192.0.2.81"),
            ],
        ),
        (
            "cname-query",
            "www.old.example.test.",
            "CNAME",
            0,
            [
                ("old.example.test.", "DNAME", "dest.other.test."),
                ("www.old.example.test.", "CNAME", "www.dest.other.test."),
            ],
        ),
        (
            "ipv6-target",
            "www.old.example.test.",
            "AAAA",
            0,
            [
                ("old.example.test.", "DNAME", "dest.other.test."),
                ("www.old.example.test.", "CNAME", "www.dest.other.test."),
                ("www.dest.other.test.", "AAAA", "2001:db8::81"),
            ],
        ),
        (
            "two-zone-chain",
            "www.bridge.example.test.",
            "A",
            0,
            [
                ("bridge.example.test.", "DNAME", "hop.other.test."),
                ("www.bridge.example.test.", "CNAME", "www.hop.other.test."),
                ("hop.other.test.", "DNAME", "dest.example.test."),
                ("www.hop.other.test.", "CNAME", "www.dest.example.test."),
                ("www.dest.example.test.", "A", "192.0.2.80"),
            ],
        ),
        (
            "terminal-nxdomain",
            "missing.old.example.test.",
            "A",
            3,
            [
                ("old.example.test.", "DNAME", "dest.other.test."),
                ("missing.old.example.test.", "CNAME", "missing.dest.other.test."),
            ],
        ),
    )


def validated_keys():
    names = {
        name: dns.name.from_text(origin)
        for name, origin in (
            ("root", "."),
            ("tld", "test."),
            ("leaf", "example.test."),
            ("other", "other.test."),
        )
    }
    zones = {
        name: dns.zone.from_file(
            f"/work/{name}/active.db", origin=origin, relativize=False
        )
        for name, origin in names.items()
    }
    anchors = dns.zone.from_file(
        "/work/anchors.zone", origin=names["root"], relativize=False, check_origin=False
    ).get_rdataset(names["root"], dns.rdatatype.DNSKEY)
    assert anchors, "missing root trust anchor"
    trusted = {names["root"]: anchors}
    all_keys = {}
    for name in ("root", "tld", "leaf", "other"):
        origin, zone = names[name], zones[name]
        keys = base.rrset(zone, origin, dns.rdatatype.DNSKEY)
        signatures = base.rrset(zone, origin, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
        if name != "root":
            parent = "root" if name == "tld" else "tld"
            ds = base.rrset(zones[parent], origin, dns.rdatatype.DS)
            ds_sigs = base.rrset(
                zones[parent], origin, dns.rdatatype.RRSIG, dns.rdatatype.DS
            )
            dns.dnssec.validate(ds, ds_sigs, {names[parent]: all_keys[names[parent]]})
            matching = [
                key
                for key in keys
                if any(item == dns.dnssec.make_ds(origin, key, "SHA256") for item in ds)
            ]
            assert matching, f"DS does not match {origin} DNSKEY"
            trusted = {origin: dns.rdataset.from_rdata_list(keys.ttl, matching)}
        dns.dnssec.validate(keys, signatures, trusted)
        all_keys[origin] = keys
    return all_keys


def validate_denial(reply, keys, mode):
    apex = dns.name.from_text("other.test.")
    closest = dns.name.from_text("dest.other.test.")
    target = dns.name.from_text("missing.dest.other.test.")
    wildcard = dns.name.from_text("*.dest.other.test.")
    soa = [
        rr
        for rr in reply.authority
        if rr.name == apex and rr.rdtype == dns.rdatatype.SOA
    ]
    kind = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    proofs = [rr for rr in reply.authority if rr.rdtype == kind]
    assert len(soa) == 1 and proofs, "missing negative SOA or denial witnesses"
    for rr in soa + proofs:
        sigs = [
            sig
            for sig in reply.authority
            if sig.name == rr.name
            and sig.rdtype == dns.rdatatype.RRSIG
            and sig.covers == rr.rdtype
        ]
        assert len(sigs) == 1, "missing negative proof signature"
        dns.dnssec.validate(rr, sigs[0], keys)
    records = [(rr.name, item) for rr in proofs for item in rr]
    if mode == "nsec":
        assert any(base.covered(owner, item.next, target) for owner, item in records), (
            "missing NSEC name denial"
        )
        assert any(
            base.covered(owner, item.next, wildcard) for owner, item in records
        ), "missing NSEC wildcard denial"
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
            base.covered(start(owner), end(item), digest(target, item))
            for owner, item in records
        ), "missing NSEC3 name denial"
        assert any(
            base.covered(start(owner), end(item), digest(wildcard, item))
            for owner, item in records
        ), "missing NSEC3 wildcard denial"


base.validate_denial = validate_denial


def query_case(args, case, keys, disabled=False, bogus=False):
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
        if bogus and not disabled:
            assert reply.rcode() == dns.rcode.SERVFAIL, (
                f"bad chain returned {reply.rcode()}"
            )
            assert not reply.answer and not reply.flags & dns.flags.AD, (
                "bogus data returned authentic"
            )
        else:
            base.validate(case, query, reply, keys, args.mode)
            if disabled and bogus:
                assert not reply.flags & dns.flags.AD, "bogus chain marked authentic"
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
    return (case, query, reply) if error is None else None


def fault_tests(observations, keys, mode):
    def reject(case, query, reply):
        try:
            base.validate(case, query, reply, keys, mode)
        except Exception:
            return
        raise AssertionError("invalid cross-zone response passed validation")

    case, query, valid = observations["two-zone-chain"]
    for owner in ("bridge.example.test.", "hop.other.test."):
        altered = copy.deepcopy(valid)
        altered.answer = [
            rr
            for rr in altered.answer
            if not (
                rr.name.to_text().lower() == owner
                and rr.rdtype == dns.rdatatype.RRSIG
                and rr.covers == dns.rdatatype.DNAME
            )
        ]
        reject(case, query, altered)
    altered = copy.deepcopy(valid)
    for index, rr in enumerate(altered.answer):
        if (
            rr.rdtype == dns.rdatatype.CNAME
            and rr.name.to_text().lower() == "www.hop.other.test."
        ):
            altered.answer[index] = dns.rrset.from_text(
                rr.name, rr.ttl, "IN", "CNAME", "wrong.example.test."
            )
    reject(case, query, altered)
    case, query, valid = observations["terminal-nxdomain"]
    altered = copy.deepcopy(valid)
    kind = dns.rdatatype.NSEC if mode == "nsec" else dns.rdatatype.NSEC3
    altered.authority = [rr for rr in altered.authority if rr.rdtype != kind]
    reject(case, query, altered)
    altered = copy.deepcopy(valid)
    altered.authority = [
        rr
        for rr in altered.authority
        if not (rr.rdtype == dns.rdatatype.RRSIG and rr.covers == kind)
    ]
    reject(case, query, altered)
    return 5


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "server", "protocol", "mode"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bad-chain", action="store_true")
    args = parser.parse_args()
    if args.bad_chain:
        try:
            validated_keys()
        except AssertionError as error:
            assert "DS does not match other.test." in str(error), error
        else:
            raise AssertionError("bad DS unexpectedly authenticates destination")
        keys = {}
        for name, origin in (("leaf", "example.test."), ("other", "other.test.")):
            apex = dns.name.from_text(origin)
            zone = dns.zone.from_file(
                f"/work/{name}/active.db", origin=apex, relativize=False
            )
            keys[apex] = zone.get_rdataset(apex, dns.rdatatype.DNSKEY)
        case = cases()[0]
        for disabled in (False, True):
            variant = ("bad-ds-cd" if disabled else "bad-ds", *case[1:])
            query_case(args, variant, keys, disabled, bogus=True)
        return
    keys = validated_keys()
    observations = {}
    for case in cases():
        observation = query_case(args, case, keys)
        if observation:
            observations[case[0]] = observation
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
