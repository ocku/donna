"""Check DNAME overflow and the full upstream extended RCODE."""

import json

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype


def query(host, port, name, tcp):
    request = dns.message.make_query(name, "A", use_edns=0, payload=1232)
    request.flags |= dns.flags.RD
    send = dns.query.tcp if tcp else dns.query.udp
    return send(request, host, port=port, timeout=10)


def run():
    failures = []
    # Independently decode the exact authority wire before testing the
    # recursive peers. Each case has a separate DNAME owner so that BIND's
    # cached ancestor cannot mask the malformed response for a later query.
    for tcp in (False, True):
        for case, expected in (("valid", 6), ("bad", 22)):
            protocol = "tcp" if tcp else "udp"
            name = f"{case}-{protocol}.{case}-{protocol}.example.test."
            response = query("172.29.56.20", 53, name, tcp)
            row = {
                "server": "authority",
                "transport": protocol,
                "case": case,
                "rcode": response.rcode(),
                "wire_hex": response.to_wire().hex(),
                "passed": response.rcode() == expected and response.edns == 0,
            }
            print(json.dumps(row), flush=True)
            if not row["passed"]:
                failures.append(row)
    for host, port, server in (
        ("172.29.56.10", 5301, "donna"),
        ("172.29.56.11", 53, "bind"),
    ):
        for tcp in (False, True):
            for case, expected in (
                ("valid", dns.rcode.YXDOMAIN),
                ("bad", dns.rcode.SERVFAIL),
            ):
                protocol = "tcp" if tcp else "udp"
                response = query(
                    host,
                    port,
                    f"{case}-{protocol}.{case}-{protocol}.example.test.",
                    tcp,
                )
                dnames = [
                    rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNAME
                ]
                passed = response.rcode() == expected and (
                    len(dnames) == 1 if case == "valid" else not dnames
                )
                row = {
                    "server": server,
                    "transport": protocol,
                    "case": case,
                    "rcode": response.rcode(),
                    "dname_rrsets": len(dnames),
                    "wire_hex": response.to_wire().hex(),
                    "passed": passed,
                }
                print(json.dumps(row), flush=True)
                if not passed:
                    failures.append(row)
    return failures


if __name__ == "__main__":
    failures = run()
    print(
        json.dumps({"result": "FAIL" if failures else "PASS", "failures": failures}),
        flush=True,
    )
    if failures:
        raise SystemExit(1)
