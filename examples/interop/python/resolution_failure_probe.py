"""Observe failure-cache traffic independently of resolver implementation."""

import json
import time
from urllib.request import Request, urlopen

import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype

from recursive_cache_checks import total
from resolution_failure_checks import traffic_matches, validate
from recursive_cache_probe import AUTHORITY, SERVERS, ZONE, counts


FAILURES = []


def query(host, port, protocol, name, kind="A", cd=False, expected=2):
    request = dns.message.make_query(name, kind, use_edns=0)
    if cd:
        request.flags |= dns.flags.CD
    reply = getattr(dns.query, protocol)(request, host, port=port, timeout=12)
    assert request.is_response(reply)
    validate(
        name,
        kind,
        cd,
        expected,
        {
            "rcode": reply.rcode(),
            "flags": reply.flags,
            "answer": [
                (
                    rr.name.to_text(),
                    dns.rdatatype.to_text(rr.rdtype),
                    dns.rdataclass.to_text(rr.rdclass),
                    item.to_text(),
                )
                for rr in reply.answer
                for item in rr
            ],
        },
    )
    return reply


def record(label, protocol, name, check, before, after, expected_delta_zero):
    passed = traffic_matches(before, after, name, expected_delta_zero)
    row = {
        "server": label,
        "protocol": protocol,
        "name": name,
        "check": check,
        "upstream_before": total(before, name),
        "upstream_after": total(after, name),
        "passed": passed,
    }
    if not passed:
        FAILURES.append(row)
    print(json.dumps(row), flush=True)


def main():
    cases = []
    for label, host, port in SERVERS:
        for protocol in ("udp", "tcp"):
            for fault in ("servfail", "refused"):
                name = f"{fault}-{label}-{protocol}.{ZONE}"
                before = counts()
                query(host, port, protocol, name)
                cold = counts()
                record(
                    label,
                    protocol,
                    name,
                    "cold-failure-reaches-authority",
                    before,
                    cold,
                    False,
                )
                query(host, port, protocol, name)
                record(
                    label,
                    protocol,
                    name,
                    "immediate-failure-reuses-cache",
                    cold,
                    counts(),
                    True,
                )
                time.sleep(0.5)
                before = counts()
                query(host, port, protocol, name)
                record(
                    label,
                    protocol,
                    name,
                    "failure-still-suppressed-after-half-second",
                    before,
                    counts(),
                    True,
                )
                before = counts()
                query(host, port, protocol, name, "AAAA", expected=0)
                record(
                    label,
                    protocol,
                    name,
                    "failure-does-not-poison-other-qtype",
                    before,
                    counts(),
                    False,
                )
                query(host, port, protocol, name, cd=True)
                before = counts()
                query(host, port, protocol, name, cd=True)
                record(
                    label,
                    protocol,
                    name,
                    "repeated-cd-failure-reuses-cache",
                    before,
                    counts(),
                    True,
                )
                cases.append((label, host, port, protocol, name))
    with urlopen(Request(AUTHORITY + "/advance", method="POST"), timeout=3):
        pass
    # Default Donna failure lifetime is locally configured, independent of
    # received TTLs. This bounded gate permits up to five seconds plus margin.
    time.sleep(6.2)
    for label, host, port, protocol, name in cases:
        before = counts()
        query(host, port, protocol, name, expected=0)
        record(
            label,
            protocol,
            name,
            "expired-failure-reacquires-recovered-data",
            before,
            counts(),
            False,
        )
    print(
        json.dumps(
            {
                "result": "FAIL" if FAILURES else "PASS",
                "failures": FAILURES,
                "authority_counts": counts(),
            }
        ),
        flush=True,
    )
    if FAILURES:
        raise SystemExit("resolution-failure cache gate failed")


if __name__ == "__main__":
    main()
