"""Validate every finite authoritative owner after all timing has finished."""

import argparse
import json

from signed_probe import (
    APEX,
    covers,
    nsec3_covers,
    nsec3_hash,
    nsec3_matches,
    verify_signatures,
    witnesses,
)
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype


def contains_type(item, code):
    for window, bitmap in item.windows:
        byte = (code % 256) // 8
        if window == code // 256 and byte < len(bitmap):
            return bool(bitmap[byte] & (0x80 >> (code % 8)))
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("nsec", "nsec3"), required=True)
    parser.add_argument("--population", type=int, required=True)
    parser.add_argument("--repeats", type=int, required=True)
    args = parser.parse_args()
    assert 1 <= args.population <= 2048 and args.repeats >= 1
    key_query = dns.message.make_query(APEX, "DNSKEY", want_dnssec=True)
    key_response = dns.query.udp(key_query, "172.29.53.24", port=53, timeout=3)
    keys = {
        APEX: next(
            rr for rr in key_response.answer if rr.rdtype == dns.rdatatype.DNSKEY
        )
    }
    verify_signatures(key_response, keys)
    for server, host, port in [
        ("donna", "172.29.53.14", 5300),
        ("bind", "172.29.53.24", 53),
    ]:
        count = 0
        for kind in ("positive", "negative", "nodata", "wildcard"):
            for repeat in range(args.repeats):
                for i in range(args.population):
                    owner = (
                        f"fresh-{repeat}-{i}.wild.example.test."
                        if kind == "wildcard"
                        else f"fresh-{kind}-{repeat}-{i}.example.test."
                    )
                    name = dns.name.from_text(owner)
                    query = dns.message.make_query(
                        name,
                        "TXT" if kind == "wildcard" else "A",
                        want_dnssec=True,
                        payload=1232,
                    )
                    query.flags &= ~dns.flags.RD
                    reply = dns.query.udp(query, host, port=port, timeout=3)
                    assert query.is_response(reply) and reply.rcode() == (
                        3 if kind == "negative" else 0
                    )
                    assert reply.flags & dns.flags.AA and not reply.flags & (
                        dns.flags.TC | dns.flags.RA | dns.flags.AD
                    )
                    assert (
                        reply.edns == 0
                        and reply.ednsflags & dns.flags.DO
                        and len(reply.to_wire()) <= 1232
                    )
                    verify_signatures(reply, keys)
                    if kind == "positive":
                        assert any(
                            rr.rdtype == dns.rdatatype.A
                            and rr.name == name
                            and rr[0].address == "192.0.2.80"
                            for rr in reply.answer
                        )
                    elif kind == "wildcard":
                        assert any(
                            rr.rdtype == dns.rdatatype.TXT and rr.name == name
                            for rr in reply.answer
                        )
                        assert any(
                            rr.rdtype == dns.rdatatype.RRSIG
                            and rr.name == name
                            and rr.covers == dns.rdatatype.TXT
                            and all(sig.labels == 3 for sig in rr)
                            for rr in reply.answer
                        ), "wildcard RRSIG Labels must authenticate wild.example.test."

                    else:
                        assert not reply.answer and any(
                            rr.rdtype == dns.rdatatype.SOA for rr in reply.authority
                        )
                    if kind != "positive":
                        records = witnesses(
                            reply,
                            dns.rdatatype.NSEC
                            if args.mode == "nsec"
                            else dns.rdatatype.NSEC3,
                        )
                        if kind == "nodata":
                            matched = [
                                item
                                for owner, item in records
                                if (
                                    owner == name
                                    if args.mode == "nsec"
                                    else owner.labels[0].decode().upper()
                                    == nsec3_hash(name, item)
                                )
                            ]
                            assert matched and all(
                                not contains_type(item, 1)
                                and not contains_type(item, 5)
                                for item in matched
                            )
                        elif args.mode == "nsec":
                            assert any(
                                covers(owner, item.next, name)
                                for owner, item in records
                            )
                            if kind == "negative":
                                wildcard = dns.name.from_text("*.example.test.")
                                assert any(
                                    covers(owner, item.next, wildcard)
                                    for owner, item in records
                                )
                        else:
                            closest = (
                                dns.name.from_text("wild.example.test.")
                                if kind == "wildcard"
                                else APEX
                            )
                            # For a positive wildcard answer, RRSIG Labels
                            # authenticates the wildcard's closest encloser;
                            # RFC 5155 7.2.6 requires the next-closer covering RR.
                            assert nsec3_covers(records, name), (
                                server,
                                kind,
                                owner,
                                "missing covering proof",
                            )
                            if kind == "negative":
                                assert nsec3_matches(records, closest), (
                                    server,
                                    kind,
                                    owner,
                                    "missing closest encloser",
                                )
                            if kind == "negative":
                                assert nsec3_covers(
                                    records, dns.name.from_text("*.example.test.")
                                )
                    count += 1
        print(
            json.dumps(
                {
                    "verification": "all finite authoritative owners checked after timing; signatures and denial witnesses",
                    "server": server,
                    "mode": args.mode,
                    "owners": count,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
