"""RFC 2931 SIG(0) interoperability using PyNaCl and independent wire framing."""

import argparse
import socket
import struct
import time

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.update
from nacl.signing import SigningKey

KEY = SigningKey(bytes([51]) * 32)
SIGNER = dns.name.from_text("sig0-key.example.test.").to_wire()
KEY_DATA = struct.pack("!HBB", 0, 3, 15) + bytes(KEY.verify_key)
CHECKSUM = sum(
    value << (8 if index % 2 == 0 else 0) for index, value in enumerate(KEY_DATA)
)
KEY_TAG = (CHECKSUM + (CHECKSUM >> 16)) & 65535


def sign(message):
    wire = message.to_wire()
    now = int(time.time())
    metadata = (
        struct.pack("!HBBIIIH", 0, 15, 0, 0, now + 120, now - 30, KEY_TAG) + SIGNER
    )
    signature = KEY.sign(metadata + wire).signature
    record = (
        b"\0"
        + struct.pack("!HHIH", 24, 255, 0, len(metadata) + 64)
        + metadata
        + signature
    )
    count = struct.unpack_from("!H", wire, 10)[0]
    return wire[:10] + struct.pack("!H", count + 1) + wire[12:] + record


def records(wire):
    _, _, qd, an, ns, ar = struct.unpack_from("!6H", wire)
    offset = 12
    for _ in range(qd):
        _, length = dns.name.from_wire(wire, offset)
        offset += length + 4
    result = []
    for index in range(an + ns + ar):
        start = offset
        _, length = dns.name.from_wire(wire, offset)
        offset += length
        kind, rclass, ttl, size = struct.unpack_from("!HHIH", wire, offset)
        offset += 10
        if index >= an + ns:
            result.append((start, kind, rclass, ttl, wire[offset : offset + size]))
        offset += size
    assert offset == len(wire)
    return result


def verify(wire, request):
    start, kind, rclass, ttl, data = records(wire)[-1]
    assert (kind, rclass, ttl) == (24, 255, 0)
    covered, algorithm, labels, original_ttl, expiration, inception, tag = (
        struct.unpack_from("!HBBIIIH", data)
    )
    assert (covered, algorithm, labels, original_ttl, tag) == (0, 15, 0, 0, KEY_TAG)
    assert inception <= time.time() <= expiration
    signer, length = dns.name.from_wire(data, 18)
    assert signer.to_wire() == SIGNER
    metadata = data[: 18 + length]
    signature = data[18 + length :]
    count = struct.unpack_from("!H", wire, 10)[0]
    unsigned = wire[:10] + struct.pack("!H", count - 1) + wire[12:start]
    KEY.verify_key.verify(metadata + request + unsigned, signature)
    return dns.message.from_wire(unsigned)


def receive_exact(connection, length):
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError("short DNS response")
        result += part
    return result


def exchange(host, port, wire, tcp):
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    ) as connection:
        connection.settimeout(5)
        connection.connect((host, port))
        if tcp:
            connection.sendall(struct.pack("!H", len(wire)) + wire)
            size = struct.unpack("!H", receive_exact(connection, 2))[0]
            return receive_exact(connection, size)
        connection.send(wire)
        return connection.recv(65535)


def run(host, port):
    for tcp in (False, True):
        query = dns.message.make_query("www.example.test.", "A")
        request = sign(query)
        answer = verify(exchange(host, port, request, tcp), request)
        assert answer.rcode() == dns.rcode.NOERROR
        assert answer.answer[0][0].address == "192.0.2.80"
        replay = dns.message.from_wire(exchange(host, port, request, tcp))
        assert replay.rcode() == dns.rcode.NOTAUTH, "SIG(0) replay accepted"

    for edns, do in ((-1, False), (0, False), (0, True)):
        query = dns.message.make_query(
            "large.example.test.", "TXT", use_edns=edns, want_dnssec=do, payload=512
        )
        assert query.edns == edns and bool(query.ednsflags & dns.flags.DO) == do
        request = sign(query)
        response_wire = exchange(host, port, request, False)
        answer = verify(response_wire, request)
        assert len(response_wire) <= 512
        assert answer.rcode() == dns.rcode.NOERROR
        assert (
            answer.flags & dns.flags.TC and not answer.answer and not answer.authority
        )
        assert answer.question == query.question
        assert answer.edns == edns
        assert bool(answer.ednsflags & dns.flags.DO) == do
    print(
        "PASS SIG(0) UDP truncation keeps required OPT and valid signature", flush=True
    )

    change = dns.update.Update("example.test.")
    change.replace("sig0-dynamic", 60, "A", "192.0.2.203")
    request = sign(change)
    answer = verify(exchange(host, port, request, True), request)
    assert answer.rcode() == dns.rcode.NOERROR
    answer = dns.query.tcp(
        dns.message.make_query("sig0-dynamic.example.test.", "A"),
        host,
        port=port,
        timeout=5,
    )
    assert answer.answer[0][0].address == "192.0.2.203"
    tampered = bytearray(sign(dns.message.make_query("www.example.test.", "A")))
    tampered[-1] ^= 1
    rejected = dns.message.from_wire(exchange(host, port, bytes(tampered), True))
    assert rejected.rcode() == dns.rcode.NOTAUTH
    print(
        "PASS: independent SIG(0) UDP/TCP queries, response signatures, replay rejection, UPDATE, tampering"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=5301)
    args = parser.parse_args()
    run(args.host, args.port)
