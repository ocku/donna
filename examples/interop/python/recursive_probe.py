"""Follow independent BIND root/TLD/authority delegations, then hit Donna's cache."""

import os
import dns.edns
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

host = os.environ.get("RECURSIVE_HOST", "172.29.53.11")

# RFC 6975 signals are advisory, including registry values reserved or unknown
# to this implementation. Use fresh names so each case exercises forwarding.
for protocol in ("udp", "tcp"):
    for code in (5, 6, 7):
        for index, value in enumerate((b"\x00", b"\xff", b"\x00\x08\xff\x08", b"")):
            query = dns.message.make_query(
                f"signal-{protocol}-{code}-{index}.wild.example.test.",
                "TXT",
                use_edns=0,
                want_dnssec=True,
                options=[dns.edns.GenericOption(code, value)],
            )
            response = getattr(dns.query, protocol)(query, host, port=5301, timeout=10)
            assert response.rcode() == dns.rcode.NOERROR, response.to_text()
            assert response.answer[0][0].strings == (b"wildcard",)
            assert response.edns == 0 and response.ednsflags & dns.flags.DO
            assert not any(option.otype in (5, 6, 7) for option in response.options)
    print(
        f"PASS recursive {protocol}: reserved DAU/DHU/N3U values accepted", flush=True
    )

for protocol in ("udp", "tcp"):
    for name, kind, rcode in (
        ("www.example.test.", "A", 0),
        ("alias.example.test.", "A", 0),
        ("missing.example.test.", "A", dns.rcode.NXDOMAIN),
        ("text.example.test.", "A", dns.rcode.NOERROR),
    ):
        query = dns.message.make_query(name, kind, use_edns=0)
        for _ in range(2):
            response = getattr(dns.query, protocol)(query, host, port=5301, timeout=10)
            assert response.rcode() == rcode, response.to_text()
            assert response.flags & dns.flags.RA and response.flags & dns.flags.RD
            assert not response.flags & dns.flags.AA
            if name in ("missing.example.test.", "text.example.test."):
                assert not response.answer, response.to_text()
                soa = [
                    rrset
                    for rrset in response.authority
                    if rrset.rdtype == dns.rdatatype.SOA
                ]
                assert len(soa) == 1 and soa[0].name.to_text() == "example.test.", (
                    response.to_text()
                )
                assert 0 <= soa[0].ttl <= 30, response.to_text()
    query.flags &= ~dns.flags.RD
    response = getattr(dns.query, protocol)(query, host, port=5301, timeout=3)
    assert response.rcode() == dns.rcode.REFUSED
    print(
        f"PASS recursive {protocol}: referral traversal, aliases, negative cache, RD refusal",
        flush=True,
    )

# Every client control-flag combination, including first lookup and cache reuse.
# This example deliberately has no trust anchors: AD must therefore stay clear.
for protocol in ("udp", "tcp"):
    for mask in range(16):
        rd, cd, ad, do = (bool(mask & (1 << bit)) for bit in range(4))
        query = dns.message.make_query(
            f"flags-{protocol}-{mask}.wild.example.test.",
            "TXT",
            use_edns=0,
            want_dnssec=do,
        )
        query.flags = (
            (dns.flags.RD if rd else 0)
            | (dns.flags.CD if cd else 0)
            | (dns.flags.AD if ad else 0)
        )
        for _ in range(2):
            response = getattr(dns.query, protocol)(query, host, port=5301, timeout=10)
            assert response.rcode() == (
                dns.rcode.NOERROR if rd else dns.rcode.REFUSED
            ), response.to_text()
            assert bool(response.flags & dns.flags.RD) == rd
            assert bool(response.flags & dns.flags.CD) == cd, (
                "recursive CD must copy client choice"
            )
            assert bool(response.ednsflags & dns.flags.DO) == do
            assert response.flags & dns.flags.RA
            assert not response.flags & (dns.flags.AA | dns.flags.AD | dns.flags.TC)
            if rd:
                assert response.answer and response.answer[0][0].strings == (
                    b"wildcard",
                )
    print(
        f"PASS recursive {protocol}: 16 RD/CD/AD/DO combinations, cold and repeated queries",
        flush=True,
    )
