"""Independent encrypted DNS protocol peers backed by a real BIND authority."""

import asyncio
import os
import ssl
import struct

import dns.message
import dns.query
import h2.config
import h2.connection
import h2.events
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

from crypto_peer import server_reply

UPSTREAM = os.environ.get("BIND_HOST", "172.29.53.20")
CERT_DIR = os.environ.get("CERT_DIR", "/certs")


async def answer(wire):
    query = dns.message.from_wire(wire)
    response = await asyncio.to_thread(dns.query.udp, query, UPSTREAM, timeout=3)
    return response.to_wire()


async def framed(reader, writer):
    try:
        while True:
            length = struct.unpack("!H", await reader.readexactly(2))[0]
            wire = await answer(await reader.readexactly(length))
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def https(reader, writer):
    import base64
    import urllib.parse

    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
    )
    connection.initiate_connection()
    writer.write(connection.data_to_send())
    requests = {}
    try:
        while data := await reader.read(65535):
            for event in connection.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    requests[event.stream_id] = [dict(event.headers), bytearray()]
                elif isinstance(event, h2.events.DataReceived):
                    requests[event.stream_id][1].extend(event.data)
                    connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    headers, body = requests.pop(event.stream_id)
                    if headers[":method"] == "GET":
                        encoded = urllib.parse.parse_qs(
                            urllib.parse.urlsplit(headers[":path"]).query
                        )["dns"][0]
                        body = base64.urlsafe_b64decode(
                            encoded + "=" * (-len(encoded) % 4)
                        )
                    wire = await answer(bytes(body))
                    connection.send_headers(
                        event.stream_id,
                        [
                            (":status", "200"),
                            ("content-type", "application/dns-message"),
                            ("content-length", str(len(wire))),
                        ],
                    )
                    connection.send_data(event.stream_id, wire, end_stream=True)
            writer.write(connection.data_to_send())
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


class DoqPeer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffers = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            data = self.buffers.setdefault(event.stream_id, bytearray())
            data.extend(event.data)
            if event.end_stream:
                asyncio.create_task(
                    self.respond(
                        event.stream_id, bytes(self.buffers.pop(event.stream_id))
                    )
                )

    async def respond(self, stream_id, data):
        length = struct.unpack("!H", data[:2])[0]
        assert length == len(data) - 2
        wire = await answer(data[2:])
        self._quic.send_stream_data(
            stream_id, struct.pack("!H", len(wire)) + wire, end_stream=True
        )
        self.transmit()


class CryptDatagrams(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        asyncio.create_task(self.respond(data, peer))

    async def respond(self, data, peer):
        try:
            wire = await asyncio.to_thread(server_reply, data, UPSTREAM)
            self.transport.sendto(wire, peer)
        except Exception as error:
            print(f"DNSCrypt UDP rejected packet: {error}", flush=True)


async def crypt_tcp(reader, writer):
    try:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
        data = await reader.readexactly(length)
        wire = await asyncio.to_thread(server_reply, data, UPSTREAM)
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
    finally:
        writer.close()


async def main():
    def context(alpn):
        config = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        config.minimum_version = ssl.TLSVersion.TLSv1_3
        config.load_cert_chain(f"{CERT_DIR}/cert.pem", f"{CERT_DIR}/key.pem")
        config.set_alpn_protocols([alpn])
        return config

    await asyncio.start_server(framed, "0.0.0.0", 8530, ssl=context("dot"))
    await asyncio.start_server(https, "0.0.0.0", 8443, ssl=context("h2"))
    config = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    config.load_cert_chain(f"{CERT_DIR}/cert.pem", f"{CERT_DIR}/key.pem")
    await serve("0.0.0.0", 8853, configuration=config, create_protocol=DoqPeer)
    await asyncio.start_server(crypt_tcp, "0.0.0.0", 5443)
    await asyncio.get_running_loop().create_datagram_endpoint(
        CryptDatagrams, local_addr=("0.0.0.0", 5443)
    )
    print(
        "Independent TLS/HTTP2/QUIC/libsodium peers ready; forwarding to BIND",
        flush=True,
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
