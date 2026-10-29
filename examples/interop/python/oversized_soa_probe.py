"""Observe cached handling of a deliberately malformed negative SOA TTL."""

import json
import time
from urllib.request import Request, urlopen

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
from recursive_cache_checks import total

AUTHORITY = "http://172.29.55.20:8053"
SERVERS = (("donna", "172.29.55.10", 5301), ("bind", "172.29.55.11", 53))


def counts():
    with urlopen(AUTHORITY + "/counts", timeout=3) as response:
        return json.load(response)


def sample(label, host, port, protocol, name, stage):
    before = counts()
    request = dns.message.make_query(name, "A", use_edns=0)
    reply = getattr(dns.query, protocol)(request, host, port=port, timeout=8)
    assert request.is_response(reply), "uncorrelated response"
    assert reply.flags & dns.flags.RD and reply.flags & dns.flags.RA
    assert not reply.flags & (dns.flags.AA | dns.flags.TC | dns.flags.AD)
    answers = [
        (rr.name.to_text(), item.to_text()) for rr in reply.answer for item in rr
    ]
    soas = [
        (rr.name.to_text(), rr.ttl, item.minimum)
        for rr in reply.authority
        if rr.rdtype == dns.rdatatype.SOA
        for item in rr
    ]
    if reply.rcode() == dns.rcode.NXDOMAIN:
        assert not answers and len(soas) == 1
        assert soas[0][0] == "example.test." and soas[0][2] == 6
        assert 0 <= soas[0][1] <= 20
    else:
        assert reply.rcode() == dns.rcode.NOERROR and answers == [(name, "192.0.2.99")]
    after = counts()
    result = {
        "server": label,
        "protocol": protocol,
        "stage": stage,
        "rcode": dns.rcode.to_text(reply.rcode()),
        "soas": soas,
        "answers": answers,
        "upstream_before": total(before, name),
        "upstream_after": total(after, name),
    }
    print(json.dumps(result), flush=True)
    return result


def main():
    # Establish the malformed input independently of both recursive servers.
    name = "oversized-soa-direct.example.test."
    for protocol in ("udp", "tcp"):
        request = dns.message.make_query(name, "A", use_edns=0)
        reply = getattr(dns.query, protocol)(
            request, "172.29.55.20", port=53, timeout=8
        )
        assert request.is_response(reply) and reply.flags & dns.flags.AA
        assert reply.rcode() == dns.rcode.NXDOMAIN and not reply.answer
        assert (
            len(reply.authority) == 1 and reply.authority[0].rdtype == dns.rdatatype.SOA
        )
        soa = reply.authority[0]
        assert (
            soa.name.to_text() == "example.test."
            and soa.ttl == 20
            and soa[0].minimum == 6
        )
        print(
            json.dumps(
                {
                    "server": "authority",
                    "protocol": protocol,
                    "stage": "direct",
                    "rcode": "NXDOMAIN",
                    "soa_ttl": soa.ttl,
                    "minimum": soa[0].minimum,
                }
            ),
            flush=True,
        )
    cases = [
        (label, host, port, protocol, f"oversized-soa-{label}-{protocol}.example.test.")
        for label, host, port in SERVERS
        for protocol in ("udp", "tcp")
    ]
    for case in cases:
        row = sample(*case, "cold")
        assert (
            row["rcode"] == "NXDOMAIN"
            and row["upstream_after"] > row["upstream_before"]
        )
    with urlopen(Request(AUTHORITY + "/advance", method="POST"), timeout=3):
        pass
    time.sleep(1.2)
    for case in cases:
        row = sample(*case, "warm")
        assert (
            row["rcode"] == "NXDOMAIN"
            and row["upstream_after"] == row["upstream_before"]
        )
        if case[0] == "donna":
            assert row["soas"][0][1] <= 6, (
                "Donna returned an overlong cached negative TTL"
            )
    time.sleep(6)
    for case in cases:
        row = sample(*case, "after-minimum")
        if case[0] == "donna":
            assert (
                row["rcode"] == "NOERROR"
                and row["upstream_after"] > row["upstream_before"]
            ), "Donna reused the negative beyond SOA.MINIMUM"
    print(
        json.dumps(
            {
                "result": "PASS",
                "resolver_rows": len(cases) * 3,
                "direct_authority_rows": 2,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
