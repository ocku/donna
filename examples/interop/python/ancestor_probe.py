"""Observe ancestor traffic across fresh names, keeping leaf traffic separate."""

import argparse
import json
import time
from urllib.request import Request, urlopen
import dns.flags
import dns.message
import dns.query

SERVERS = (("donna", "172.29.56.10", 5301), ("bind", "172.29.56.11", 53))


def counts():
    result = {}
    for role, address in (("root", 20), ("tld", 21), ("leaf", 22)):
        with urlopen(f"http://172.29.56.{address}:8053/counts", timeout=3) as stream:
            result[role] = json.load(stream)
    return result


def query(host, port, name, kind="A", expected=0, cd=False):
    q = dns.message.make_query(name, kind)
    if cd:
        q.flags |= dns.flags.CD
    r = dns.query.udp(q, host, port=port, timeout=15)
    assert q.is_response(r) and r.rcode() == expected, r.to_text()
    assert not r.flags & dns.flags.AA
    return {
        "rcode": r.rcode(),
        "answer": [rr.to_text() for rr in r.answer],
        "authority": [rr.to_text() for rr in r.authority],
    }


def delta(before, after):
    return {
        role: sum(after[role].values()) - sum(before[role].values()) for role in before
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ns-failure-cache", action="store_true")
    args = parser.parse_args()
    for role, address, name, origin in (
        ("root", 20, "ns.root.", "."),
        ("tld", 21, "ns.test.", "test."),
        ("leaf", 22, "ns.example.test.", "example.test."),
    ):
        q = dns.message.make_query(name, "AAAA")
        r = dns.query.udp(q, f"172.29.56.{address}", timeout=3)
        assert q.is_response(r) and r.rcode() == 0 and r.flags & dns.flags.AA
        assert not r.answer and len(r.authority) == 1
        assert r.authority[0].name.to_text() == origin and r.authority[0].ttl == 30
        assert r.authority[0][0].minimum == 30
        print(
            json.dumps(
                {
                    "authority": role,
                    "check": "valid-NS-address-AAAA-NODATA",
                    "response": r.to_text(),
                    "passed": True,
                }
            ),
            flush=True,
        )
    for _, host, port in SERVERS:
        query(host, port, "cached.example.test.")
        query(host, port, "ok.healthy.test.")
    with urlopen(Request("http://172.29.56.22:8053/fail", method="POST")):
        pass
    failures = []
    for label, host, port in SERVERS:
        query(host, port, f"cold-{label}.example.test.", expected=2)
        start = time.monotonic()
        for index in range(3):
            before = counts()
            response = query(
                host, port, f"fresh-{index}-{label}.example.test.", expected=2
            )
            after = counts()
            traffic = delta(before, after)
            elapsed = time.monotonic() - start
            passed = traffic["root"] == traffic["tld"] == 0 and (
                not args.ns_failure_cache or traffic["leaf"] == 1
            )
            row = {
                "server": label,
                "check": "fresh-name-avoids-ancestor-refresh",
                "index": index,
                "ns_failure_cache_required": args.ns_failure_cache,
                "delta": traffic,
                "before": before,
                "after": after,
                "response": response,
                "seconds_after_cold": elapsed,
                "passed": passed,
            }
            if elapsed >= 1:
                raise RuntimeError("observation left one-second failure window")
            if not passed:
                failures.append(row)
            print(json.dumps(row), flush=True)
        for name in ("cached.example.test.", "ok.healthy.test."):
            response = query(host, port, name)
            assert response["answer"]
        query(host, port, "example.test.", "DS")
    print(
        json.dumps(
            {
                "result": "FAIL" if failures else "PASS",
                "failures": failures,
                "scope": "unsigned lame-zone ancestor refresh across fresh names; cached/sibling positives and parent-side DS controls",
            }
        ),
        flush=True,
    )
    if failures:
        raise SystemExit("cross-name ancestor refresh gates failed")


if __name__ == "__main__":
    main()
