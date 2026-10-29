"""RFC 2308 cache scope/expiry checks with independent upstream counters."""

import json
import time
from urllib.request import Request, urlopen

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
from recursive_cache_checks import total, validate

AUTHORITY = "http://172.29.55.20:8053"
SERVERS = (("donna", "172.29.55.10", 5301), ("bind", "172.29.55.11", 53))
ZONE = "example.test."
TRANSACTIONS = 0


def counts():
    with urlopen(AUTHORITY + "/counts", timeout=3) as response:
        return json.load(response)


def query(host, port, protocol, name, kind, rcode, answers):
    global TRANSACTIONS
    request = dns.message.make_query(name, kind, use_edns=0)
    reply = getattr(dns.query, protocol)(request, host, port=port, timeout=8)
    TRANSACTIONS += 1
    assert request.is_response(reply), "uncorrelated reply"
    actual = [
        (rr.name.to_text(), dns.rdatatype.to_text(rr.rdtype), item.to_text())
        for rr in reply.answer
        for item in rr
    ]
    validate(
        kind,
        rcode,
        answers,
        {
            "rcode": reply.rcode(),
            "flags": reply.flags,
            "answer": actual,
            "classes": [rr.rdclass for rr in reply.answer + reply.authority],
            "soas": [
                (rr.name.to_text(), rr.ttl, item.minimum)
                for rr in reply.authority
                if rr.rdtype == dns.rdatatype.SOA
                for item in rr
            ],
        },
    )
    print(
        json.dumps(
            {
                "transaction": TRANSACTIONS,
                "host": host,
                "protocol": protocol,
                "name": name,
                "qtype": kind,
                "rcode": reply.rcode(),
                "flags": reply.flags,
                "answer": [rr.to_text() for rr in reply.answer],
                "authority": [rr.to_text() for rr in reply.authority],
            }
        ),
        flush=True,
    )
    return reply


def emit(label, protocol, check, before, after, names):
    print(
        json.dumps(
            {
                "server": label,
                "protocol": protocol,
                "check": check,
                "upstream_before": {n: total(before, n) for n in names},
                "upstream_after": {n: total(after, n) for n in names},
            }
        ),
        flush=True,
    )


def main():
    cases = []
    for label, host, port in SERVERS:
        for protocol in ("udp", "tcp"):
            suffix = f"{label}-{protocol}.{ZONE}"
            positive, missing, nodata = (
                kind + "-" + suffix for kind in ("positive", "missing", "nodata")
            )
            before = counts()
            initial = query(
                host, port, protocol, positive, "A", 0, [(positive, "A", "192.0.2.80")]
            )
            first = counts()
            assert total(first, positive) > total(before, positive), (
                "cold answer did not reach authority"
            )
            query(
                host, port, protocol, positive, "A", 0, [(positive, "A", "192.0.2.80")]
            )
            assert total(counts(), positive) == total(first, positive), (
                "positive warm query reached authority"
            )
            negative_initial = query(host, port, protocol, missing, "A", 3, [])
            nx = counts()
            assert total(nx, missing) > total(before, missing)
            query(host, port, protocol, missing, "AAAA", 3, [])
            assert total(counts(), missing) == total(nx, missing), (
                "NXDOMAIN not reused across QTYPE"
            )
            query(host, port, protocol, nodata, "A", 0, [])
            nd = counts()
            query(host, port, protocol, nodata, "A", 0, [])
            assert total(counts(), nodata) == total(nd, nodata), (
                "NODATA warm lookup reached authority"
            )
            query(
                host,
                port,
                protocol,
                nodata,
                "AAAA",
                0,
                [(nodata, "AAAA", "2001:db8::80")],
            )
            assert total(counts(), nodata) > total(nd, nodata), (
                "NODATA incorrectly reused across QTYPE"
            )
            emit(
                label,
                protocol,
                "positive-and-negative-key-scope",
                before,
                counts(),
                (positive, missing, nodata),
            )
            for terminal_kind in ("missing", "nodata"):
                terminal = terminal_kind + "-alias-" + suffix
                alias = "alias-" + terminal
                cname = [(alias, "CNAME", terminal)]
                query(
                    host,
                    port,
                    protocol,
                    alias,
                    "A",
                    3 if terminal_kind == "missing" else 0,
                    cname,
                )
                alias_first = counts()
                query(
                    host,
                    port,
                    protocol,
                    alias,
                    "A",
                    3 if terminal_kind == "missing" else 0,
                    cname,
                )
                query(host, port, protocol, alias, "CNAME", 0, cname)
                assert total(counts(), alias) == total(alias_first, alias), (
                    "CNAME owner poisoned or not cached"
                )
                if terminal_kind == "missing":
                    query(host, port, protocol, terminal, "AAAA", 3, [])
                    assert total(counts(), terminal) == total(alias_first, terminal), (
                        "terminal NXDOMAIN lost"
                    )
                else:
                    query(
                        host,
                        port,
                        protocol,
                        terminal,
                        "AAAA",
                        0,
                        [(terminal, "AAAA", "2001:db8::80")],
                    )
                    assert total(counts(), terminal) > total(alias_first, terminal), (
                        "terminal NODATA poisoned AAAA"
                    )
                emit(
                    label,
                    protocol,
                    f"cname-terminal-{terminal_kind}-scope",
                    alias_first,
                    counts(),
                    (alias, terminal),
                )
            cases.append(
                (
                    label,
                    host,
                    port,
                    protocol,
                    positive,
                    missing,
                    initial.answer[0].ttl,
                    negative_initial.authority[0].ttl,
                )
            )
    time.sleep(1.2)
    for label, host, port, protocol, positive, missing, ttl, negative_ttl in cases:
        before = counts()
        reply = query(
            host, port, protocol, positive, "A", 0, [(positive, "A", "192.0.2.80")]
        )
        assert reply.answer[0].ttl < ttl, "cached positive TTL did not decrement"
        assert total(counts(), positive) == total(before, positive)
        negative_reply = query(host, port, protocol, missing, "A", 3, [])
        assert negative_reply.authority[0].ttl < negative_ttl, (
            "cached negative TTL did not decrement"
        )
        assert total(counts(), missing) == total(before, missing)
        emit(
            label,
            protocol,
            "ttl-decrements-without-upstream",
            before,
            counts(),
            (positive, missing),
        )
    with urlopen(Request(AUTHORITY + "/advance", method="POST"), timeout=3):
        pass
    time.sleep(6.2)
    for label, host, port, protocol, positive, missing, _, _ in cases:
        before = counts()
        query(host, port, protocol, positive, "A", 0, [(positive, "A", "192.0.2.81")])
        query(host, port, protocol, missing, "A", 0, [(missing, "A", "192.0.2.99")])
        after = counts()
        assert all(total(after, n) > total(before, n) for n in (positive, missing)), (
            "expired data reused"
        )
        emit(
            label,
            protocol,
            "expired-positive-and-negative-reacquired",
            before,
            after,
            (positive, missing),
        )
        terminal = "missing-alias-" + f"{label}-{protocol}.{ZONE}"
        alias = "alias-" + terminal
        before = counts()
        query(
            host,
            port,
            protocol,
            alias,
            "A",
            0,
            [(alias, "CNAME", terminal), (terminal, "A", "192.0.2.99")],
        )
        after = counts()
        assert total(after, alias) == total(before, alias), (
            "live CNAME was not retained"
        )
        assert total(after, terminal) > total(before, terminal), (
            "expired CNAME terminal negative reused"
        )
        emit(
            label,
            protocol,
            "live-cname-expired-negative-terminal",
            before,
            after,
            (alias, terminal),
        )
    print(
        json.dumps(
            {
                "result": "PASS",
                "rows": len(cases) * 6,
                "client_transactions": TRANSACTIONS,
                "authority_counts": counts(),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
