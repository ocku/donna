"""Independent unsigned response gate outside the native histogram load."""

import argparse
import json
from pathlib import Path

from similar_load import CASES, query_for, received_packet, shape


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("case", choices=("positive", "wildcard", "negative"))
    parser.add_argument("--post", action="store_true")
    args = parser.parse_args()
    address, port = args.address.rsplit(":", 1)
    case, owner, rtype, rcode = next(row for row in CASES if row[0] == args.case)
    query = query_for("unsigned", owner, rtype)
    for _ in range(1 if args.post else 40):
        reply, wire = received_packet(query, (address, int(port)))
        shape(query, reply, case, rcode)
    if args.post:
        assert wire == Path("/tmp/batch-expected.wire").read_bytes()
    else:
        Path("/tmp/batch-query.wire").write_bytes(query.to_wire())
        Path("/tmp/batch-expected.wire").write_bytes(wire)
    print(
        json.dumps(
            {
                "flags": reply.flags,
                "query_wire_hex": query.to_wire().hex(),
                "response_wire_hex": wire.hex(),
                "verified": 1 if args.post else 40,
            }
        )
    )


if __name__ == "__main__":
    main()
