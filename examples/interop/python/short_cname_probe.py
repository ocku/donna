"""Compare expired aliases against a longer-lived negative terminal cache."""

import json
import time
from urllib.request import Request, urlopen

import dns.message
import dns.query
import dns.rdatatype
from recursive_cache_checks import total
from short_cname_checks import validate, validate_transition

AUTHORITY = "http://172.29.55.20:8053"
SERVERS = (("donna", "172.29.55.10", 5301), ("bind", "172.29.55.11", 53))


def counts():
    with urlopen(AUTHORITY + "/counts", timeout=3) as response:
        return json.load(response)


def query(host, port, protocol, name, kind, expected_rcode, expected_answer):
    request = dns.message.make_query(name, kind, use_edns=0)
    reply = getattr(dns.query, protocol)(request, host, port=port, timeout=8)
    assert request.is_response(reply), "uncorrelated response"
    answer = [
        (rr.name.to_text(), dns.rdatatype.to_text(rr.rdtype), item.to_text())
        for rr in reply.answer
        for item in rr
    ]
    soas = [
        (rr.name.to_text(), rr.ttl, item.minimum)
        for rr in reply.authority
        if rr.rdtype == dns.rdatatype.SOA
        for item in rr
    ]
    validate(
        {
            "rcode": reply.rcode(),
            "flags": reply.flags,
            "answer": answer,
            "classes": [rr.rdclass for rr in reply.answer + reply.authority],
            "soas": soas,
        },
        expected_rcode,
        expected_answer,
    )
    print(
        json.dumps(
            {
                "transaction": name,
                "qtype": kind,
                "transport": protocol,
                "server": host,
                "flags": reply.flags,
                "rcode": reply.rcode(),
                "answer": [rr.to_text() for rr in reply.answer],
                "authority": [rr.to_text() for rr in reply.authority],
            }
        ),
        flush=True,
    )
    return reply


def main():
    cases = []
    for label, host, port in SERVERS:
        for protocol in ("udp", "tcp"):
            suffix = f"{label}-{protocol}.example.test."
            alias, old, new = (
                prefix + suffix for prefix in ("short-alias-", "old-", "new-")
            )
            before = counts()
            cold = query(host, port, protocol, alias, "A", 3, [(alias, "CNAME", old)])
            assert 0 < cold.answer[0].ttl <= 2, "unexpected authority alias TTL"
            first = counts()
            assert total(first, alias) > total(before, alias), (
                "cold alias not sent upstream"
            )
            query(host, port, protocol, alias, "A", 3, [(alias, "CNAME", old)])
            assert total(counts(), alias) == total(first, alias), (
                "alias not cached before expiry"
            )
            cases.append((label, host, port, protocol, alias, old, new))
    with urlopen(Request(AUTHORITY + "/advance", method="POST"), timeout=3):
        pass
    time.sleep(3.2)
    for label, host, port, protocol, alias, old, new in cases:
        before = counts()
        query(
            host,
            port,
            protocol,
            alias,
            "A",
            0,
            [(alias, "CNAME", new), (new, "A", "192.0.2.101")],
        )
        after = counts()
        query(host, port, protocol, old, "A", 3, [])
        final_old = total(counts(), old)
        validate_transition(
            {"alias": total(before, alias), "old": total(before, old)},
            {"alias": total(after, alias), "old": total(after, old)},
            final_old,
        )
        print(
            json.dumps(
                {
                    "server": label,
                    "protocol": protocol,
                    "check": "expired-alias-changed-target",
                    "upstream_before": {n: total(before, n) for n in (alias, old, new)},
                    "upstream_after": {n: total(after, n) for n in (alias, old, new)},
                    "upstream_after_old": final_old,
                }
            ),
            flush=True,
        )
    print(
        json.dumps(
            {"result": "PASS", "rows": len(cases), "authority_counts": counts()}
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
