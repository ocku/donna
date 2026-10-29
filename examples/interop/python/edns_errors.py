"""Raw malformed EDNS requests must retain DNS FORMERR on ordinary transports.

Uses the existing independently implemented clients and Peers.Dockerfile.
DoQ's connection-level malformed-message checks live in stream_abuse.py.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import struct
from types import SimpleNamespace

import dns.message
import dns.name
import dns.rrset
import dns.rcode

from crypto_peer import exchange as crypt_exchange, read_exact
from http_errors import request
from probe import raw_exchange

HOST = os.environ.get("DONNA_HOST", "172.29.53.10")
CERT = os.environ.get("CERT_DIR", "/certs") + "/cert.pem"


def malformed_queries():
    query = dns.message.make_query("www.example.test.", "A", use_edns=0)
    wire = query.to_wire()
    question, opt = wire[12:-11], wire[-11:]

    def packet(answer_count=0, authority_count=0, additional_count=1, records=opt):
        return (
            struct.pack(
                "!6H",
                query.id,
                query.flags,
                1,
                answer_count,
                authority_count,
                additional_count,
            )
            + question
            + records
        )

    return query, {
        "duplicate-opt": packet(additional_count=2, records=opt + opt),
        "nonroot-opt": packet(records=b"\x01x\0" + opt[1:]),
        "answer-opt": packet(answer_count=1, additional_count=0),
        "authority-opt": packet(authority_count=1, additional_count=0),
        "duplicate-padding": packet(records=opt[:-2] + b"\0\x08\0\x0c\0\0\0\x0c\0\0"),
    }


def exchange(wire, protocol):
    if protocol in ("udp", "tcp"):
        return dns.message.from_wire(raw_exchange(HOST, wire, tcp=protocol == "tcp"))
    if protocol == "tls":
        context = ssl.create_default_context(cafile=CERT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["dot"])
        with socket.create_connection((HOST, 8530), timeout=1) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as connection:
                connection.sendall(struct.pack("!H", len(wire)) + wire)
                length = struct.unpack("!H", read_exact(connection, 2))[0]
                return dns.message.from_wire(read_exact(connection, length))
    if protocol.startswith("doh-"):
        post = protocol == "doh-post"
        encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
        status, response = request(
            "POST" if post else "GET",
            "/dns-query" if post else "/dns-query?dns=" + encoded,
            wire if post else b"",
            return_wire=True,
        )
        assert status == 200, (
            f"expected HTTP 200 carrying DNS FORMERR; got HTTP {status}"
        )
        return dns.message.from_wire(response)
    # Encrypt the intentionally malformed wire without asking dnspython to
    # serialize it: the independent libsodium peer supplies DNSCrypt framing.
    query = SimpleNamespace(to_wire=lambda: wire, keyring=None, mac=b"")
    return crypt_exchange(query, HOST, tcp=protocol == "dnscrypt-tcp")


def oversized_questions():
    query = dns.message.make_query("www.example.test.", "A", use_edns=0, payload=4096)
    for index in range(8):
        name = (
            ".".join([str(index) + "x" * 59, "y" * 60, "z" * 60, "example", "test"])
            + "."
        )
        query.question.append(dns.rrset.RRset(dns.name.from_text(name), 1, 1))
    wire = query.to_wire()
    # Serialize with a larger buffer, then advertise the minimum UDP size.
    wire = wire[:-8] + struct.pack("!H", 512) + wire[-6:]
    assert len(wire) > 512
    response_wire = raw_exchange(HOST, wire)
    assert len(response_wire) <= 512, "minimal FORMERR exceeds advertised UDP limit"
    response = dns.message.from_wire(response_wire)
    assert response.id == query.id and response.rcode() == dns.rcode.FORMERR
    assert not response.question and not response.answer and not response.authority
    assert response.edns == 0, "minimal EDNS FORMERR lost its mandatory OPT"
    print(
        "PASS oversized question section retains OPT in minimal UDP FORMERR", flush=True
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--protocol",
        choices=(
            "udp",
            "tcp",
            "tls",
            "doh-get",
            "doh-post",
            "dnscrypt-udp",
            "dnscrypt-tcp",
        ),
    )
    args = parser.parse_args()
    protocols = (
        (args.protocol,)
        if args.protocol
        else (
            "udp",
            "tcp",
            "tls",
            "doh-get",
            "doh-post",
            "dnscrypt-udp",
            "dnscrypt-tcp",
        )
    )
    query, cases = malformed_queries()
    failures = []
    for protocol in protocols:
        for name, wire in cases.items():
            try:
                response = exchange(wire, protocol)
                assert response.id == query.id
                assert response.rcode() == dns.rcode.FORMERR, response.to_text()
                assert response.question == query.question
                assert not response.answer and not response.authority
                assert response.edns == 0, "RFC 6891 section 7 requires a response OPT"
                print(f"PASS malformed EDNS {protocol} {name}", flush=True)
            except Exception as error:
                failure = {
                    "protocol": protocol,
                    "case": name,
                    "error": f"{type(error).__name__}: {error}",
                }
                failures.append(failure)
                print(json.dumps(failure), flush=True)
    if args.protocol in (None, "udp"):
        oversized_questions()
    print(json.dumps({"edns_failures": failures}, indent=2), flush=True)
    if failures:
        raise SystemExit(f"{len(failures)} malformed EDNS transport inconsistencies")


if __name__ == "__main__":
    main()
