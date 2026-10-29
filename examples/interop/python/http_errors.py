"""HTTP/2 error status checks without involving Donna's client implementation."""

import base64
import os
import socket
import ssl

import dns.message
import h2.config
import h2.connection
import h2.events

HOST = os.environ.get("DONNA_HOST", "172.29.53.10")
CERT = os.environ.get("CERT_DIR", "/certs") + "/cert.pem"


def request(
    method,
    path,
    body=b"",
    media="application/dns-message",
    accept="application/dns-message",
    return_wire=False,
    host=HOST,
    cert=CERT,
):
    context = ssl.create_default_context(cafile=cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(header_encoding="utf-8")
    )
    with socket.create_connection((host, 8443), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as stream:
            connection.initiate_connection()
            headers = [
                (":method", method),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", path),
                ("content-type", media),
                ("accept", accept),
            ]
            connection.send_headers(1, headers, end_stream=not body)
            if body:
                connection.send_data(1, body, end_stream=True)
            stream.sendall(connection.data_to_send())
            status = None
            response_wire = bytearray()
            while data := stream.recv(65535):
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = int(dict(event.headers)[":status"])
                    elif isinstance(event, h2.events.DataReceived):
                        response_wire.extend(event.data)
                    elif isinstance(event, h2.events.StreamEnded):
                        return (status, bytes(response_wire)) if return_wire else status
                stream.sendall(connection.data_to_send())
    raise AssertionError("HTTP response did not finish")


def main():
    wire = dns.message.make_query("www.example.test.", "A").to_wire()
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    cases = [
        (
            "GET",
            "/dns-query?dns=" + encoded,
            b"",
            "application/dns-message",
            "application/dns-message",
            200,
        ),
        (
            "POST",
            "/dns-query",
            wire,
            "application/dns-message",
            "application/dns-message",
            200,
        ),
        (
            "POST",
            "/wrong-path",
            wire,
            "application/dns-message",
            "application/dns-message",
            404,
        ),
        (
            "PUT",
            "/dns-query",
            wire,
            "application/dns-message",
            "application/dns-message",
            405,
        ),
        ("POST", "/dns-query", wire, "text/plain", "application/dns-message", 415),
        ("POST", "/dns-query", wire, "application/dns-message", "text/plain", 200),
        (
            "GET",
            "/dns-query?dns=not!base64",
            b"",
            "application/dns-message",
            "application/dns-message",
            400,
        ),
    ]
    for method, path, body, media, accept, expected in cases:
        actual = request(method, path, body, media, accept)
        assert actual == expected, (method, path, actual, expected)
    print(
        "PASS independent HTTP/2 DoH GET/POST, endpoint, method, media, accept, base64 errors"
    )


if __name__ == "__main__":
    main()
