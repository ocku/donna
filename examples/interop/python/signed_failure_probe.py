"""One independently correlated signed-chain failure or CD-bypass transaction."""

import argparse
import json
import socket
import time

import dns.flags
import dns.message
import dns.query
import dns.rdatatype


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cd", action="store_true")
    args = parser.parse_args()
    deadline = time.monotonic() + 12
    while True:
        try:
            with socket.create_connection((args.host, args.port), timeout=0.2):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    query = dns.message.make_query(
        "www.example.test.", "A", want_dnssec=True, payload=1232
    )
    if args.cd:
        query.flags |= dns.flags.CD
    reply = dns.query.udp(query, args.host, port=args.port, timeout=12)
    assert query.is_response(reply)
    assert reply.rcode() == (0 if args.cd else 2), reply.to_text()
    assert reply.flags & dns.flags.RA and reply.flags & dns.flags.RD
    assert not reply.flags & (dns.flags.AA | dns.flags.AD | dns.flags.TC)
    assert bool(reply.flags & dns.flags.CD) == args.cd
    if args.cd:
        answers = [rr for rr in reply.answer if rr.rdtype == dns.rdatatype.A]
        assert len(answers) == 1 and answers[0].name.to_text() == "www.example.test."
        assert [item.address for item in answers[0]] == ["192.0.2.80"]
    print(
        json.dumps(
            {
                "cd": args.cd,
                "flags": reply.flags,
                "rcode": reply.rcode(),
                "answer": [rr.to_text() for rr in reply.answer],
                "authority": [rr.to_text() for rr in reply.authority],
            }
        )
    )


if __name__ == "__main__":
    main()
