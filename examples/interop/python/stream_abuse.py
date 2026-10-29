"""Bounded independent DoQ protocol violations and HTTP/2 cancellation probes."""

import asyncio
import os
import socket
import ssl
import struct

import dns.edns
import dns.message
import dns.query
import h2.config
import h2.connection
import h2.events
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

HOST = os.environ.get("DONNA_HOST", "172.29.53.10")
CERT = os.environ.get("CERT_DIR", "/certs") + "/cert.pem"


class Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminated = asyncio.get_running_loop().create_future()
        self.answers = {}
        self.complete = {}

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated) and not self.terminated.done():
            self.terminated.set_result(event)
        if isinstance(event, StreamDataReceived):
            self.answers.setdefault(event.stream_id, bytearray()).extend(event.data)
            if event.end_stream and event.stream_id in self.complete:
                self.complete[event.stream_id].set_result(
                    bytes(self.answers[event.stream_id])
                )
        # No asyncio StreamReaders are used: QUIC events are inspected directly.

    def send(self, data, end_stream=True):
        stream = self._quic.get_next_available_stream_id()
        self.complete[stream] = asyncio.get_running_loop().create_future()
        self._quic.send_stream_data(stream, data, end_stream=end_stream)
        self.transmit()
        return stream


def query(identifier=0, keepalive=False):
    request = dns.message.make_query(
        "www.example.test.",
        "A",
        use_edns=0,
        options=[dns.edns.GenericOption(11, b"")] if keepalive else [],
    )
    request.id = identifier
    return request.to_wire()


def frame(wire):
    return struct.pack("!H", len(wire)) + wire


async def doq():
    configuration = QuicConfiguration(
        is_client=True, alpn_protocols=["doq"], server_name="localhost"
    )
    configuration.load_verify_locations(CERT)
    valid = frame(query())
    qr = bytearray(query())
    qr[2] |= 0x80
    cases = {
        "nonzero-id": frame(query(123)),
        "truncated-prefix": b"\x00",
        "truncated-message": valid[:-1],
        "multiple-queries": valid + valid,
        "trailing-octet": valid + b"\x00",
        "zero-length": b"\x00\x00",
        "response-in-query-stream": frame(qr),
        "forbidden-tcp-keepalive": frame(query(keepalive=True)),
    }
    for label, wire in cases.items():
        async with connect(
            HOST, 8853, configuration=configuration, create_protocol=Protocol
        ) as protocol:
            protocol.send(wire)
            event = await asyncio.wait_for(asyncio.shield(protocol.terminated), 3)
            assert event.error_code == 2, (label, event)
        print("PASS DoQ connection protocol error:", label, flush=True)
    async with connect(
        HOST, 8853, configuration=configuration, create_protocol=Protocol
    ) as protocol:
        # Reset requests before FIN and stop receiving each response, then prove
        # an unrelated stream on the same authenticated connection still works.
        for _ in range(12):
            stream = protocol.send(valid[:-1], end_stream=False)
            protocol._quic.reset_stream(stream, 3)
            protocol._quic.stop_stream(stream, 3)
        stream = protocol.send(valid)
        protocol.transmit()
        wire = await asyncio.wait_for(protocol.complete[stream], 3)
        size = struct.unpack("!H", wire[:2])[0]
        assert len(wire) == size + 2
        response = dns.message.from_wire(wire[2:])
        assert response.id == 0 and response.rcode() == 0 and response.answer
        assert not protocol.terminated.done()
    print(
        "PASS DoQ 12 cancelled streams preserve unrelated same-connection query",
        flush=True,
    )


def http2():
    context = ssl.create_default_context(cafile=CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(header_encoding="utf-8")
    )
    with socket.create_connection((HOST, 8443), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as stream:
            connection.initiate_connection()
            headers = [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/dns-query"),
                ("content-type", "application/dns-message"),
            ]
            # Partially sent requests are cancelled while the body reader waits.
            for identifier in range(1, 25, 2):
                connection.send_headers(identifier, headers)
                connection.send_data(identifier, query()[:8])
                connection.reset_stream(identifier, error_code=8)
            connection.send_headers(25, headers)
            connection.send_data(25, query(), end_stream=True)
            stream.sendall(connection.data_to_send())
            response = bytearray()
            status = None
            while data := stream.recv(65535):
                for event in connection.receive_data(data):
                    if (
                        isinstance(event, h2.events.ResponseReceived)
                        and event.stream_id == 25
                    ):
                        status = int(dict(event.headers)[":status"])
                    if (
                        isinstance(event, h2.events.DataReceived)
                        and event.stream_id == 25
                    ):
                        response.extend(event.data)
                        connection.acknowledge_received_data(
                            event.flow_controlled_length, 25
                        )
                    if (
                        isinstance(event, h2.events.StreamEnded)
                        and event.stream_id == 25
                    ):
                        assert status == 200, status
                        message = dns.message.from_wire(bytes(response))
                        assert message.rcode() == 0 and message.answer
                        print(
                            "PASS HTTP/2 12 body cancellations preserve unrelated same-connection query",
                            flush=True,
                        )
                        return
                stream.sendall(connection.data_to_send())
    raise AssertionError(
        "HTTP/2 connection closed before independent request completed"
    )


def main():
    asyncio.run(doq())
    http2()
    answer = dns.query.udp(
        dns.message.make_query("www.example.test.", "A"), HOST, port=5300, timeout=3
    )
    assert answer.rcode() == 0 and answer.answer


if __name__ == "__main__":
    main()
