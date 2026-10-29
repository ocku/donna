"""Check RFC 5155 metadata-owner visibility with an independent DNS client."""

import argparse
from collections import Counter
import json

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.zone

from nsec3_owner_checks import expected_rcode, validate
from signed_probe import (
    nsec3_covers,
    nsec3_matches,
    nsec3_hash,
    verify_signatures,
    witnesses,
)

APEX = dns.name.from_text("example.test.")
SERVERS = (
    ("verified", "172.29.54.10", 5300),
    ("current", "172.29.54.11", 5300),
    ("bind", "172.29.54.20", 53),
    ("knot", "172.29.54.30", 53),
    ("nsd", "172.29.54.40", 53),
)


def contains_type(item, kind):
    for window, bitmap in item.windows:
        offset = (kind & 255) // 8
        if window == kind >> 8 and offset < len(bitmap):
            return bool(bitmap[offset] & (0x80 >> (kind & 7)))
    return False


def verify_proofs(reply, keys, variant, location, name, kind):
    verify_signatures(reply, keys)
    records = witnesses(reply, dns.rdatatype.NSEC3)
    params = {(item.algorithm, item.iterations, item.salt) for _, item in records}
    assert len(params) <= 1, "inconsistent NSEC3 parameters"
    if reply.rcode() == 3:
        closest = APEX if variant == "metadata" else name.parent()
        next_closer = dns.name.Name(name.labels[-len(closest.labels) - 1 :])
        wildcard = dns.name.Name((b"*",) + closest.labels)
        assert nsec3_matches(records, closest), "missing closest-encloser match"
        assert nsec3_covers(records, next_closer), "missing next-closer denial"
        assert nsec3_covers(records, wildcard), "missing wildcard denial"
    elif variant == "wildcard":
        next_closer = dns.name.Name(name.labels[-len(APEX.labels) - 1 :])
        assert nsec3_covers(records, next_closer), "missing wildcard expansion witness"
        if not reply.answer:
            wildcard = dns.name.Name((b"*",) + APEX.labels)
            assert nsec3_matches(records, APEX), (
                "wildcard NODATA lacks closest encloser"
            )
            matches = [
                item
                for owner, item in records
                if owner.labels[0].decode().upper() == nsec3_hash(wildcard, item)
            ]
            assert matches and all(
                not contains_type(item, dns.rdatatype.from_text(kind))
                and not contains_type(item, 5)
                for item in matches
            )
    elif not reply.answer and location == "owner":
        assert nsec3_matches(records, name), (
            "ordinary owner/ENT NODATA lacks matching proof"
        )


def normalized(reply):
    return {
        "rcode": reply.rcode(),
        "aa": bool(reply.flags & dns.flags.AA),
        "tc": bool(reply.flags & dns.flags.TC),
        "answer": [
            (
                rr.name.to_text().lower(),
                dns.rdatatype.to_text(rr.rdtype),
                dns.rdataclass.to_text(rr.rdclass),
                item.to_text(),
            )
            for rr in reply.answer
            for item in rr
        ],
        "soas": [
            (
                rr.name.to_text().lower(),
                dns.rdataclass.to_text(rr.rdclass),
                rr.ttl,
                item.minimum,
            )
            for rr in reply.authority
            if rr.rdtype == dns.rdatatype.SOA
            for item in rr
        ],
        "signatures": [
            (item.type_covered, item.labels)
            for rr in reply.answer
            if rr.rdtype == dns.rdatatype.RRSIG
            for item in rr
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default="/work/active.db")
    parser.add_argument(
        "--variant",
        choices=("metadata", "wildcard", "owner", "descendant"),
        default="metadata",
    )
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("positive repeat count required")
    zone = dns.zone.from_file(args.fixture, origin=APEX, relativize=False)
    params = zone.get_rdataset(APEX, dns.rdatatype.NSEC3PARAM)[0]
    keys = {APEX: zone.get_rdataset(APEX, dns.rdatatype.DNSKEY)}
    owner = dns.name.from_text(
        dns.dnssec.nsec3_hash(APEX, params.salt, params.iterations, params.algorithm),
        APEX,
    )
    assert zone.get_rdataset(owner, dns.rdatatype.NSEC3), (
        "fixture must contain selected metadata owner"
    )
    print(
        json.dumps(
            {
                "variant": args.variant,
                "metadata_owner": owner.to_text(),
                "parameters": params.to_text(),
                "repeats": args.repeats,
            }
        ),
        flush=True,
    )
    failures = []
    for label, host, port in SERVERS:
        for protocol in ("udp", "tcp"):
            for do in (False, True):
                for location, name in (
                    ("owner", owner),
                    ("below", dns.name.from_text("missing", owner)),
                ):
                    for kind in ("A", "RRSIG", "NSEC3", "ANY"):
                        query = dns.message.make_query(
                            name, kind, want_dnssec=do, payload=4096
                        )
                        query.flags &= ~dns.flags.RD
                        errors = set()
                        codes = Counter()
                        for _ in range(args.repeats):
                            reply = getattr(dns.query, protocol)(
                                query, host, port=port, timeout=5
                            )
                            assert query.is_response(reply), "uncorrelated reply"
                            codes[reply.rcode()] += 1
                            try:
                                validate(
                                    args.variant,
                                    location,
                                    kind,
                                    name.to_text(),
                                    normalized(reply),
                                )
                                assert (
                                    reply.edns == 0
                                    and bool(reply.ednsflags & dns.flags.DO) == do
                                ), "wrong EDNS/DO"
                                if do:
                                    verify_proofs(
                                        reply, keys, args.variant, location, name, kind
                                    )
                            except (
                                AssertionError,
                                dns.dnssec.ValidationFailure,
                            ) as error:
                                errors.add(str(error))
                        row = {
                            "server": label,
                            "protocol": protocol,
                            "do": do,
                            "location": location,
                            "variant": args.variant,
                            "name": name.to_text(),
                            "qtype": kind,
                            "rcode": reply.rcode(),
                            "expected_rcode": expected_rcode(args.variant, location),
                            "flags": reply.flags,
                            "answer": [rr.to_text() for rr in reply.answer],
                            "authority": [rr.to_text() for rr in reply.authority],
                            "checks": args.repeats,
                            "observed_rcodes": dict(codes),
                            "errors": sorted(errors),
                            "passed": not errors,
                        }
                        if errors:
                            failures.append(
                                {
                                    key: row[key]
                                    for key in (
                                        "server",
                                        "protocol",
                                        "do",
                                        "location",
                                        "qtype",
                                        "rcode",
                                        "errors",
                                    )
                                }
                            )
                        print(json.dumps(row), flush=True)
    print(
        json.dumps(
            {
                "result": "FAIL" if failures else "PASS",
                "variant": args.variant,
                "rows": len(SERVERS) * 32,
                "failures": failures,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
