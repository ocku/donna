"""Counted DNS message boundaries, independent of response reserialization."""

import struct


def layout(wire):
    assert len(wire) >= 12
    identifier, flags, *counts = struct.unpack("!6H", wire[:12])

    def name_end(offset):
        while True:
            assert offset < len(wire), "short encoded name"
            size = wire[offset]
            offset += 1
            if size & 0xC0 == 0xC0:
                assert offset < len(wire), "short compression pointer"
                return offset + 1
            assert size <= 63, "reserved label encoding"
            if not size:
                return offset
            offset += size
            assert offset <= len(wire), "short label"

    offset = 12
    for _ in range(counts[0]):
        offset = name_end(offset) + 4
        assert offset <= len(wire), "short question"
    boundaries = []
    for section, count in zip(("answer", "authority", "additional"), counts[1:]):
        for index in range(count):
            start = offset
            fixed = name_end(offset)
            assert fixed + 10 <= len(wire), "short record header"
            rtype, rclass, ttl, length = struct.unpack(
                "!HHIH", wire[fixed : fixed + 10]
            )
            offset = fixed + 10 + length
            assert offset <= len(wire), "short record data"
            boundaries.append([section, index, start, offset, rtype, rclass, length])
    return dict(
        id=identifier,
        flags=flags,
        counts=counts,
        counted_end=offset,
        trailing_wire_hex=wire[offset:].hex(),
        records=boundaries,
    )
