"""Independently verify recursive CNAME-to-NODATA replies outside timed traffic."""

import argparse
import json

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from signed_probe import APEX, verify_denial, verify_signatures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("nsec", "nsec3", "nsec3-secure"), required=True
    )
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    args = parser.parse_args()
    key_query = dns.message.make_query(APEX, "DNSKEY", want_dnssec=True, payload=1232)
    key_reply = dns.query.tcp(key_query, "172.29.53.24", timeout=3)
    assert key_query.is_response(key_reply) and key_reply.rcode() == 0
    keys = {
        APEX: next(rr for rr in key_reply.answer if rr.rdtype == dns.rdatatype.DNSKEY)
    }
    verify_signatures(key_reply, keys)
    alias = dns.name.from_text("alias-empty.example.test.")
    target = dns.name.from_text("empty.example.test.")
    checks = 0
    for server, host, port in (
        ("donna", "172.29.53.61", 5301),
        ("bind", "172.29.53.60", 53),
    ):
        # Exercise both early borrowing and popularity-gated template renders
        # before timing; the production preparation threshold is 32 selections.
        for _ in range(36):
            query = dns.message.make_query(alias, "A", want_dnssec=True, payload=1232)
            reply = dns.query.udp(query, host, port=port, timeout=8)
            assert query.is_response(reply) and reply.rcode() == 0, (
                server,
                reply.to_text(),
            )
            assert (
                reply.flags == dns.flags.QR | dns.flags.RD | dns.flags.RA | dns.flags.AD
            ), (server, reply.to_text())
            assert reply.edns == 0 and reply.ednsflags & dns.flags.DO
            aliases = [rr for rr in reply.answer if rr.rdtype == dns.rdatatype.CNAME]
            assert (
                len(aliases) == 1 and aliases[0].name == alias and len(aliases[0]) == 1
            )
            assert aliases[0][0].target == target
            assert not any(rr.rdtype == dns.rdatatype.A for rr in reply.answer)
            soas = [rr for rr in reply.authority if rr.rdtype == dns.rdatatype.SOA]
            assert len(soas) == 1 and soas[0].name == APEX
            assert all(soas[0].ttl <= rr.minimum for rr in soas[0])
            verify_signatures(reply, keys)
            for section in (reply.answer, reply.authority):
                for rrset in section:
                    if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.NS):
                        continue
                    signatures = next(
                        rr
                        for rr in section
                        if rr.name == rrset.name
                        and rr.rdtype == dns.rdatatype.RRSIG
                        and rr.covers == rrset.rdtype
                    )
                    assert all(
                        rrset.ttl <= signature.original_ttl for signature in signatures
                    )
            verify_denial(reply, args.mode, alias, "alias-empty-nodata")
            checks += 1
    print(
        json.dumps(
            {
                "verification": "independent recursive CNAME/NODATA signatures and required witnesses",
                "mode": args.mode,
                "phase": args.phase,
                "checks": checks,
                "queries_per_server": 36,
                "scope": "separate control traffic, not measured load",
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
