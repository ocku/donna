"""External DNS clients, flag matrix, RFC assertions, and deterministic fuzzing."""

import argparse
import itertools
import json
import os
import random
import socket
import ssl
import struct

import dns.edns
import dns.flags
import dns.message
import dns.query
import dns.quic
import dns.rcode
import dns.rdatatype
import dns.tsigkeyring
import dns.zone

from crypto_peer import exchange as crypt_exchange

PROTOCOLS = (
    "udp",
    "tcp",
    "tls",
    "doh-get",
    "doh-post",
    "doq",
    "dnscrypt-udp",
    "dnscrypt-tcp",
)


def exchange(query, host, protocol, cert, port=None):
    if protocol in ("udp", "tcp"):
        return getattr(dns.query, protocol)(query, host, port=port or 5300, timeout=3)
    if protocol == "tls":
        context = ssl.create_default_context(cafile=cert)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["dot"])
        return dns.query.tls(
            query,
            host,
            port=port or 8530,
            timeout=3,
            ssl_context=context,
            server_hostname="localhost",
        )
    if protocol.startswith("doh-"):
        return dns.query.https(
            query,
            f"https://localhost:{port or 8443}/dns-query",
            bootstrap_address=host,
            timeout=3,
            verify=cert,
            post=protocol == "doh-post",
            http_version=dns.query.HTTPVersion.H2,
        )
    if protocol == "doq":
        return dns.query.quic(
            query,
            host,
            port=port or 8853,
            timeout=3,
            verify=cert,
            server_hostname="localhost",
        )
    return crypt_exchange(query, host, port or 5443, tcp=protocol == "dnscrypt-tcp")


def flags_matrix(host, protocol, cert):
    for rd, cd, ad, do in itertools.product((False, True), repeat=4):
        query = dns.message.make_query(
            "www.example.test.", "A", use_edns=0, want_dnssec=do
        )
        query.flags = (
            (dns.flags.RD if rd else 0)
            | (dns.flags.CD if cd else 0)
            | (dns.flags.AD if ad else 0)
        )
        answer = exchange(query, host, protocol, cert)
        assert answer.rcode() == dns.rcode.NOERROR, answer.to_text()
        assert answer.answer[0][0].address == "192.0.2.80", answer.to_text()
        assert bool(answer.flags & dns.flags.RD) == rd, (
            "RFC 1035 4.1.1: RD must be copied"
        )
        assert not answer.flags & dns.flags.CD, (
            "RFC 4035 3.1.6: authoritative server should clear CD"
        )
        assert answer.flags & dns.flags.AA, "authoritative answer missing AA"
        assert not answer.flags & (dns.flags.AD | dns.flags.RA | dns.flags.TC)


def functionality(host, protocol, cert):
    for name, kind in (
        ("example.test.", "SOA"),
        ("example.test.", "NS"),
        ("www.example.test.", "AAAA"),
        ("alias.example.test.", "A"),
        ("example.test.", "MX"),
        ("text.example.test.", "TXT"),
        ("_sip._tcp.example.test.", "SRV"),
        ("example.test.", "CAA"),
        ("a.wild.example.test.", "TXT"),
    ):
        query = dns.message.make_query(name, kind)
        answer = exchange(query, host, protocol, cert)
        assert answer.rcode() == 0 and answer.answer, answer.to_text()
    for name, kind, rcode in (
        ("missing.example.test.", "A", dns.rcode.NXDOMAIN),
        ("www.example.test.", "MX", 0),
    ):
        answer = exchange(dns.message.make_query(name, kind), host, protocol, cert)
        assert answer.rcode() == rcode and not answer.answer, answer.to_text()
        assert answer.authority[0].rdtype == dns.rdatatype.SOA
        assert answer.authority[0].ttl == 30, (
            "RFC 2308 negative TTL must use SOA minimum"
        )
    query = dns.message.make_query("www.example.test.", "A", use_edns=1)
    answer = exchange(query, host, protocol, cert)
    assert answer.rcode() == dns.rcode.BADVERS and answer.edns == 0, answer.to_text()
    for payload in (0, 128, 512, 1232, 4096, 65535):
        query = dns.message.make_query(
            "www.example.test.", "A", use_edns=0, payload=payload
        )
        answer = exchange(query, host, protocol, cert)
        assert answer.rcode() == 0


def signed_query(host, protocol, cert):
    query = dns.message.make_query("www.example.test.", "A")
    if protocol == "doq":
        query.id = 0
    keys = dns.tsigkeyring.from_text(
        {"interop-key.": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
    )
    query.use_tsig(keys, keyname="interop-key.", algorithm="hmac-sha256")
    if protocol == "doq":
        # dnspython 2.8 query.quic passes q.request_mac instead of q.mac when
        # verifying signed responses. Supply the actual request MAC ourselves.
        query.id = 0
        wire = query.to_wire()
        with dns.quic.SyncQuicManager(
            verify_mode=cert, server_name="localhost"
        ) as manager:
            connection = manager.connect(host, 8853)
            with connection.make_stream(3) as stream:
                stream.send(wire, True)
                response_wire = stream.receive(3)
        answer = dns.message.from_wire(
            response_wire, keyring=keys, request_mac=query.mac
        )
    elif protocol.startswith("doh-"):
        # dnspython's HTTPS helper has the same request_mac issue as QUIC.
        # Keep its independent HTTP implementation and verify the raw wire
        # with the request MAC captured when the query was actually signed.
        import http_errors
        import base64

        wire = query.to_wire()
        encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
        status, response_wire = http_errors.request(
            "POST" if protocol == "doh-post" else "GET",
            "/dns-query" if protocol == "doh-post" else "/dns-query?dns=" + encoded,
            wire if protocol == "doh-post" else b"",
            return_wire=True,
            host=host,
            cert=cert,
        )
        assert status == 200
        answer = dns.message.from_wire(
            response_wire, keyring=keys, request_mac=query.mac
        )
    else:
        answer = exchange(query, host, protocol, cert)
    assert answer.had_tsig and answer.rcode() == 0


def raw_exchange(host, wire, tcp=False, port=5300):
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    ) as connection:
        connection.settimeout(0.15)
        connection.connect((host, port))
        if tcp:
            connection.sendall(struct.pack("!H", len(wire)) + wire)
            prefix = connection.recv(2)
            if len(prefix) != 2:
                return b""
            length = struct.unpack("!H", prefix)[0]
            output = b""
            while len(output) < length:
                part = connection.recv(length - len(output))
                if not part:
                    break
                output += part
            return output
        connection.send(wire)
        return connection.recv(65535)


def fuzz(host, cases):
    rng = random.Random(10356891)
    seed = dns.message.make_query("www.example.test.", "A", use_edns=0).to_wire()
    seeds = [b"", b"\0" * 12, seed[:12] + b"\xc0\x0c" + seed[-4:], seed]
    counts = {"accepted": 0, "rejected": 0, "dropped": 0}
    for index in range(cases):
        wire = bytearray(seeds[index % len(seeds)])
        for _ in range(1 + rng.randrange(4)):
            if wire:
                wire[rng.randrange(len(wire))] ^= 1 << rng.randrange(8)
        if index % 5 == 0:
            del wire[rng.randrange(len(wire) + 1) :]
        try:
            result = raw_exchange(host, bytes(wire), tcp=bool(index % 2))
            if result:
                response = dns.message.from_wire(result)
                assert response.flags & dns.flags.QR, "server returned a query"
                counts["accepted" if response.rcode() == 0 else "rejected"] += 1
            else:
                counts["dropped"] += 1
        except (TimeoutError, ConnectionError):
            counts["dropped"] += 1
        # Each malformed input is followed by a fresh valid request: a hung or
        # crashed listener is a failure, even when dropping the input was legal.
        answer = dns.query.udp(
            dns.message.make_query("www.example.test.", "A"), host, port=5300, timeout=1
        )
        assert answer.rcode() == 0 and answer.answer
    print("FUZZ", json.dumps({"seed": 10356891, "cases": cases, **counts}), flush=True)


def malformed_requests(host):
    seed = dns.message.make_query("www.example.test.", "A", use_edns=0).to_wire()
    for tcp in (False, True):
        for label, bit in (
            ("QR", 0x8000),
            ("AA", 0x0400),
            ("TC", 0x0200),
            ("RA", 0x0080),
            ("Z", 0x0040),
            ("RCODE", 0x0002),
        ):
            wire = bytearray(seed)
            flags = struct.unpack("!H", wire[2:4])[0] | bit
            wire[2:4] = struct.pack("!H", flags)
            try:
                result = raw_exchange(host, wire, tcp)
            except (TimeoutError, ConnectionError):
                result = b""
            if result:
                assert dns.message.from_wire(result).rcode() == dns.rcode.FORMERR, label
        # Classic DNS, unknown EDNS options, and duplicate OPT RR handling.
        query = dns.message.make_query("www.example.test.", "A", use_edns=None)
        assert (
            getattr(dns.query, "tcp" if tcp else "udp")(
                query, host, port=5300, timeout=3
            ).edns
            == -1
        )
        query = dns.message.make_query(
            "www.example.test.",
            "A",
            use_edns=0,
            options=[dns.edns.GenericOption(65001, b"unknown")],
        )
        response = getattr(dns.query, "tcp" if tcp else "udp")(
            query, host, port=5300, timeout=3
        )
        assert response.rcode() == 0
        wire = bytearray(seed)
        wire[10:12] = struct.pack("!H", 2)
        wire.extend(b"\0\0\x29\x04\xd0\0\0\0\0\0\0")
        response = dns.message.from_wire(raw_exchange(host, wire, tcp))
        assert response.rcode() == dns.rcode.FORMERR
        for opcode in (1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15):
            wire = seed[:2] + struct.pack("!H", opcode << 11) + seed[4:]
            response = dns.message.from_wire(raw_exchange(host, wire, tcp))
            assert response.rcode() == dns.rcode.NOTIMP, (opcode, response.to_text())
    print(
        "PASS invalid QR/AA/TC/RA/Z/RCODE, no-EDNS, unknown option, duplicate OPT",
        flush=True,
    )


def truncation_and_pipeline(host):
    query = dns.message.make_query("large.example.test.", "TXT", use_edns=None)
    response = dns.query.udp(query, host, port=5300, timeout=3)
    assert response.flags & dns.flags.TC and not response.answer
    response, used_tcp = dns.query.udp_with_fallback(query, host, port=5300, timeout=3)
    assert used_tcp and len(response.answer[0]) == 10
    with socket.create_connection((host, 5300), timeout=3) as stream:
        from crypto_peer import read_exact

        for index in range(4):
            query = dns.message.make_query("www.example.test.", "A")
            query.id = 100 + index
            wire = query.to_wire()
            stream.sendall(struct.pack("!H", len(wire)) + wire)
        received = set()
        for _ in range(4):
            length = struct.unpack("!H", read_exact(stream, 2))[0]
            response = dns.message.from_wire(read_exact(stream, length))
            assert response.rcode() == 0 and response.answer
            received.add(response.id)
        assert received == {100, 101, 102, 103}
    print(
        "PASS whole-RRset UDP truncation, independent TCP fallback and TCP pipelining",
        flush=True,
    )


def signed_truncation(host):
    keys = dns.tsigkeyring.from_text(
        {"interop-key.": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
    )
    for edns, do in ((-1, False), (0, False), (0, True)):
        query = dns.message.make_query(
            "large.example.test.", "TXT", use_edns=edns, want_dnssec=do, payload=512
        )
        assert query.edns == edns and bool(query.ednsflags & dns.flags.DO) == do
        query.use_tsig(keys, keyname="interop-key.", algorithm="hmac-sha256")
        wire = query.to_wire()
        response_wire = raw_exchange(host, wire)
        response = dns.message.from_wire(
            response_wire, keyring=keys, request_mac=query.mac
        )
        assert len(response_wire) <= 512
        assert response.rcode() == dns.rcode.NOERROR
        assert response.had_tsig and response.flags & dns.flags.TC
        assert not response.answer and not response.authority
        assert response.question == query.question
        assert response.edns == edns
        assert bool(response.ednsflags & dns.flags.DO) == do
    print("PASS TSIG UDP truncation keeps required OPT and valid MAC", flush=True)


def transfers(host):
    records = list(
        dns.query.xfr(host, "example.test.", port=5300, timeout=3, lifetime=5)
    )
    assert records[0].answer[0].rdtype == dns.rdatatype.SOA
    assert records[-1].answer[-1].rdtype == dns.rdatatype.SOA
    changes = list(
        dns.query.xfr(
            host,
            "example.test.",
            rdtype=dns.rdatatype.IXFR,
            serial=1,
            port=5300,
            timeout=3,
            lifetime=5,
        )
    )
    assert len(changes) == 1 and len(changes[0].answer) == 1
    response = dns.query.udp(
        dns.message.make_query("example.test.", "AXFR"), host, port=5300, timeout=3
    )
    assert response.rcode() in (dns.rcode.REFUSED, dns.rcode.NOTIMP, dns.rcode.FORMERR)
    print("PASS AXFR TCP, IXFR current serial, UDP AXFR rejection", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("DONNA_HOST", "172.29.53.10"))
    parser.add_argument(
        "--cert", default=os.environ.get("CERT_DIR", "/certs") + "/cert.pem"
    )
    parser.add_argument("--protocol", choices=PROTOCOLS, action="append")
    parser.add_argument("--fuzz", type=int, default=200)
    args = parser.parse_args()
    failures = []
    for protocol in args.protocol or PROTOCOLS:
        for label, check in (
            ("flags-16", flags_matrix),
            ("records-edns-negative", functionality),
            ("TSIG", signed_query),
        ):
            try:
                check(args.host, protocol, args.cert)
                print(f"PASS {protocol} {label}", flush=True)
            except Exception as error:
                failures.append(f"{protocol} {label}: {type(error).__name__}: {error}")
                print("FAIL", failures[-1], flush=True)
    for label, check in (
        ("malformed", malformed_requests),
        ("transfers", transfers),
        ("truncation", truncation_and_pipeline),
        ("TSIG truncation", signed_truncation),
    ):
        try:
            check(args.host)
        except Exception as error:
            failures.append(f"{label}: {type(error).__name__}: {error}")
            print("FAIL", failures[-1], flush=True)
    fuzz(args.host, args.fuzz)
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
