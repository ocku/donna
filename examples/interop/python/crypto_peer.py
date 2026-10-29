"""Independent DNSCrypt v2 framing using libsodium, not Donna's crypto code."""

import ctypes
import ctypes.util
import os
import socket
import struct
import time

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey

PROVIDER_SECRET = bytes([31]) * 32
RESOLVER_SECRET = bytes([41]) * 32
PROVIDER = "2.dnscrypt-cert.example.test."
CLIENT_MAGIC = b"DONNALAB"
SERVER_MAGIC = b"r6fnvWj8"
SODIUM = ctypes.cdll.LoadLibrary(ctypes.util.find_library("sodium"))
SODIUM.sodium_init()


def box(data, nonce, public, secret, decrypt=False):
    function = "crypto_box_curve25519xchacha20poly1305_"
    function += "open_easy" if decrypt else "easy"
    output = ctypes.create_string_buffer(len(data) + 16)
    result = getattr(SODIUM, function)(
        output, data, ctypes.c_ulonglong(len(data)), nonce, public, secret
    )
    if result:
        raise ValueError("DNSCrypt authentication failed")
    return output.raw[: len(data) - 16 if decrypt else len(data) + 16]


def pad(data):
    return data + b"\x80" + b"\0" * ((-len(data) - 1) % 64)


def unpad(data):
    data = data.rstrip(b"\0")
    if not data.endswith(b"\x80"):
        raise ValueError("DNSCrypt padding terminator missing")
    return data[:-1]


def read_exact(connection, length):
    output = bytearray()
    while len(output) < length:
        part = connection.recv(length - len(output))
        if not part:
            raise EOFError("short DNS frame")
        output.extend(part)
    return bytes(output)


def transact(host, port, wire, tcp):
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    ) as connection:
        connection.settimeout(3)
        connection.connect((host, port))
        if tcp:
            connection.sendall(struct.pack("!H", len(wire)) + wire)
            return read_exact(
                connection, struct.unpack("!H", read_exact(connection, 2))[0]
            )
        connection.send(wire)
        return connection.recv(65535)


def exchange(query, host, port=5443, tcp=False):
    certificate_query = dns.message.make_query(PROVIDER, "TXT")
    response = dns.message.from_wire(
        transact(host, port, certificate_query.to_wire(), tcp)
    )
    if response.flags & dns.flags.TC:
        response = dns.message.from_wire(
            transact(host, port, certificate_query.to_wire(), True)
        )
    certificate = b"".join(response.answer[0][0].strings)
    assert certificate[:8] == b"DNSC\0\2\0\0"
    VerifyKey(SigningKey(PROVIDER_SECRET).verify_key.encode()).verify(
        certificate[72:], certificate[8:72]
    )
    resolver_public = certificate[72:104]
    magic = certificate[104:112]
    key = PrivateKey.generate()
    nonce = os.urandom(12)
    packet = magic + key.public_key.encode() + nonce
    packet += box(
        pad(query.to_wire()), nonce + bytes(12), resolver_public, key.encode()
    )
    response = transact(host, port, packet, tcp)
    assert response[:8] == SERVER_MAGIC and response[8:20] == nonce
    plain = box(response[32:], response[8:32], resolver_public, key.encode(), True)
    answer = dns.message.from_wire(
        unpad(plain), keyring=query.keyring, request_mac=query.mac
    )
    if not tcp and answer.flags & dns.flags.TC:
        return exchange(query, host, port, tcp=True)
    return answer


def server_reply(packet, upstream):
    if packet[:8] != CLIENT_MAGIC:
        query = dns.message.from_wire(packet)
        response = dns.message.make_response(query)
        now = int(time.time())
        public = PrivateKey(RESOLVER_SECRET).public_key.encode()
        payload = public + CLIENT_MAGIC + struct.pack("!III", 1, now - 60, now + 86400)
        certificate = (
            b"DNSC\0\2\0\0"
            + SigningKey(PROVIDER_SECRET).sign(payload).signature
            + payload
        )
        escaped = "".join(f"\\{value:03d}" for value in certificate)
        response.answer.append(
            dns.rrset.from_text(PROVIDER, 60, "IN", "TXT", f'"{escaped}"')
        )
        return response.to_wire()
    public, nonce = packet[8:40], packet[40:52]
    query = dns.message.from_wire(
        unpad(box(packet[52:], nonce + bytes(12), public, RESOLVER_SECRET, True))
    )
    response = dns.query.udp(query, upstream, timeout=3)
    full_nonce = nonce + os.urandom(12)
    return (
        SERVER_MAGIC
        + full_nonce
        + box(pad(response.to_wire()), full_nonce, public, RESOLVER_SECRET)
    )
