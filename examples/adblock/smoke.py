#!/usr/bin/env python3
"""Exercise the built image with its full list and an authenticated DoQ upstream."""

import argparse
import asyncio
import ipaddress
import socket
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))

        if not chunk:
            raise EOFError("incomplete TCP DNS frame")

        data.extend(chunk)

    return bytes(data)


def answer(query):
    end = 12
    labels = []

    while query[end]:
        length = query[end]
        labels.append(query[end + 1 : end + 1 + length].decode("ascii"))
        end += 1 + length

    end += 1
    qtype = struct.unpack_from("!H", query, end)[0]
    end += 4

    print("query " + ".".join(labels), flush=True)

    if qtype == 28:
        rdata = ipaddress.ip_address("2001:db8::42").packed
    else:
        rdata = ipaddress.ip_address("192.0.2.42").packed

    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    response = (
        query[:2]
        + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        + query[12:end]
        + answer
    )

    return response


async def upstream():
    from datetime import datetime, timedelta, timezone

    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import StreamDataReceived
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    Path("/certs/cert.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    Path("/certs/key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    Path("/certs/key.pem").chmod(0o600)

    class Upstream(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.buffers = {}

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                data = self.buffers.setdefault(event.stream_id, bytearray())
                data.extend(event.data)
                if event.end_stream:
                    wire = bytes(self.buffers.pop(event.stream_id))
                    assert struct.unpack("!H", wire[:2])[0] == len(wire) - 2
                    assert wire[2:4] == b"\0\0", "DoQ query ID must be zero"
                    response = answer(wire[2:])
                    self._quic.send_stream_data(
                        event.stream_id,
                        struct.pack("!H", len(response)) + response,
                        end_stream=True,
                    )
                    self.transmit()

    def config(alpn):
        configuration = QuicConfiguration(is_client=False, alpn_protocols=[alpn])
        configuration.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
        return configuration

    # Reject the first endpoint's handshake immediately to exercise failover
    # without depending on UDP/ICMP behavior or waiting for a timeout.
    rejected = await serve("0.0.0.0", 9, configuration=config("not-doq"))
    healthy = await serve(
        "0.0.0.0", 5353, configuration=config("doq"), create_protocol=Upstream
    )
    print("ready", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        rejected.close()
        healthy.close()


def exchange(host, name, qtype=1, tcp=False, edns=True, rd=True):
    identifier = 0x1234

    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )

    query = (
        struct.pack("!HHHHHH", identifier, 0x100 if rd else 0, 1, 0, 0, int(edns))
        + question
        + b"\0"
        + struct.pack("!HH", qtype, 1)
    )

    if edns:
        query += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)

    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    ) as client:
        client.settimeout(5)
        client.connect((host, 5353))

        if tcp:
            client.sendall(struct.pack("!H", len(query)) + query)
            response = read_exact(client, struct.unpack("!H", read_exact(client, 2))[0])
        else:
            client.send(query)
            response = client.recv(65535)

    reply_id, flags, questions, answers, _, additionals = struct.unpack_from(
        "!HHHHHH", response
    )

    assert reply_id == identifier and flags & 0x8000 and flags & 0x80, response.hex()
    assert questions == 1, response.hex()

    return flags & 15, answers, additionals, response


def probe(host):
    domains = [
        line.strip()
        for line in sys.stdin.read().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    assert domains, "image contains an empty blocklist"

    for _ in range(50):
        try:
            assert exchange(host, domains[0], tcp=True)[0] == 3
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("ad blocker did not become ready")

    samples = domains[:: max(1, len(domains) // 16)]
    for tcp in (False, True):
        for name in samples:
            for qtype in (1, 28, 16, 65):
                rcode, answers, _, response = exchange(
                    host, "cdn." + name.upper(), qtype, tcp
                )

                assert rcode == 3 and answers == 0, (name, response.hex())
                assert response.endswith(b"\x00\x0f\x00\x02\x00\x0f"), response.hex()

            rcode, answers, additionals, _ = exchange(host, name, tcp=tcp, edns=False)
            assert (rcode, answers, additionals) == (3, 0, 0)

        # Both listeners share the forwarder's cache.
        for qtype, expected in ((1, "192.0.2.42"), (28, "2001:db8::42")):
            rcode, answers, _, response = exchange(host, "allowed.test", qtype, tcp)

            assert (rcode, answers) == (0, 1), response.hex()
            assert ipaddress.ip_address(expected).packed in response, response.hex()

        assert exchange(host, domains[0], tcp=tcp, rd=False)[0] == 5

    print(
        f"PASS: {len(domains)} loaded domains; {len(samples)} samples and subdomains blocked"
    )
    print("PASS: UDP/TCP, A/AAAA/TXT/HTTPS, EDNS Blocked, plain DNS, RD policy")


def smoke(image):
    suffix = uuid.uuid4().hex[:10]
    network = "donna-adblock-test-" + suffix
    upstream = network + "-upstream"
    server = network + "-server"
    certificates = network + "-certs"
    fixture_image = network + "-fixture"

    try:
        subprocess.run(
            ["docker", "build", "-f", "-", "-t", fixture_image, "."],
            input="FROM python:3.13-slim-bookworm\n"
            "RUN pip install --no-cache-dir aioquic==1.7.0\n",
            text=True,
            check=True,
        )
        docker("network", "create", network)
        docker("volume", "create", certificates)
        docker(
            "run",
            "--detach",
            "--name",
            upstream,
            "--network",
            network,
            "--volume",
            f"{Path(__file__).resolve()}:/smoke.py:ro",
            "--volume",
            f"{certificates}:/certs",
            fixture_image,
            "python",
            "-u",
            "/smoke.py",
            "--upstream",
        )

        for _ in range(100):
            if "ready" in docker("logs", upstream).splitlines():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("DoQ upstream did not become ready")

        upstream_ip = docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            upstream,
        )

        docker(
            "run",
            "--detach",
            "--name",
            server,
            "--network",
            network,
            "--env",
            f"UPSTREAM_ADDRS={upstream_ip}:9,{upstream_ip}:5353",
            "--env",
            "UPSTREAM_SERVER_NAME=localhost",
            "--env",
            "UPSTREAM_CA_FILE=/certs/cert.pem",
            "--volume",
            f"{certificates}:/certs:ro",
            image,
        )

        server_ip = docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            server,
        )

        text = docker("exec", server, "cat", "/etc/donna/blocklist.txt")

        # Probe on the bridge itself so the check also works with VM-backed
        # Docker engines whose localhost forwarding supports only TCP.
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--interactive",
                "--network",
                network,
                "--volume",
                f"{Path(__file__).resolve()}:/smoke.py:ro",
                "python:3.13-slim-bookworm",
                "python",
                "/smoke.py",
                "--probe",
                server_ip,
            ],
            input=text,
            text=True,
            check=True,
        )

        logs = [line for line in docker("logs", upstream).splitlines() if line != "ready"]

        assert logs == ["query allowed.test", "query allowed.test"], logs

        print(
            "PASS: authenticated DoQ and failover, allowed A/AAAA forwarded and cached; zero blocked queries reached upstream"
        )
    except BaseException:
        for container in (server, upstream):
            subprocess.run(["docker", "logs", container], check=False)

        raise
    finally:
        subprocess.run(
            ["docker", "rm", "--force", server, upstream],
            check=False,
            stdout=subprocess.DEVNULL,
        )

        subprocess.run(
            ["docker", "network", "rm", network], check=False, stdout=subprocess.DEVNULL
        )
        subprocess.run(
            ["docker", "volume", "rm", certificates], check=False, stdout=subprocess.DEVNULL
        )
        subprocess.run(
            ["docker", "image", "rm", fixture_image], check=False, stdout=subprocess.DEVNULL
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="donna-adblock:local")
    parser.add_argument("--upstream", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.upstream:
        asyncio.run(upstream())
    elif args.probe:
        probe(args.probe)
    else:
        smoke(args.image)
