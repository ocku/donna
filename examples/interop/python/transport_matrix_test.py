"""Independent fault injection for transport matrix contents and framing."""

import copy
import itertools
import unittest

import dns.flags
import dns.message
import dns.rrset

from transport_matrix import (
    CASES,
    PROFILES,
    check_reply,
    check_rows,
    expected,
    frame,
    query,
    read_frame,
)


def response(request, payload, partial=False):
    reply = dns.message.make_response(request)
    reply.flags |= dns.flags.AA
    if payload is not None:
        reply.use_edns(edns=0, payload=1232)
    label = request.question[0].name.labels[0].decode()
    kind = request.question[0].rdtype.name
    wanted = expected(label, kind)
    if partial:
        reply.flags |= dns.flags.TC
        wanted = {next(iter(wanted))}
    grouped = {}
    for owner, rtype, value in wanted:
        grouped.setdefault((owner, rtype), []).append(value)
    for (owner, rtype), values in grouped.items():
        reply.answer.append(dns.rrset.from_text(owner, 300, "IN", rtype, *values))
    return reply.to_wire(max_size=65535)


def fixture():
    rows = []

    def keep(phase, request, payload):
        wire = response(request, payload, partial=phase == "udp" and payload != 4096)
        row = dict(
            server="fixture",
            phase=phase,
            payload=payload,
            query_wire_hex=request.to_wire().hex(),
            response_wire_hex=wire.hex(),
            observed=check_reply(request, wire, payload, phase != "udp"),
        )
        if phase != "udp":
            row["received_frame_hex"] = frame(wire).hex()
        rows.append(row)

    for i, payload in enumerate(PROFILES):
        request = query("many", "A", payload, 0x2000 + i)
        keep("udp", request, payload)
        keep("tcp-recovery", request, payload)
    requests = [
        query(label, kind, payload, 0x3000 + i)
        for i, (payload, (label, kind)) in enumerate(itertools.product(PROFILES, CASES))
    ]
    for request, (payload, _) in reversed(
        list(zip(requests, itertools.product(PROFILES, CASES)))
    ):
        keep("pipeline", request, payload)
    keep("reuse", query("www", "A", 512, 0x4000), 512)
    combined = b"".join(frame(q.to_wire()) for q in requests)
    rows.append(
        dict(
            pipeline_connection="fixture",
            query_ids=[q.id for q in requests],
            response_ids=[q.id for q in reversed(requests)],
            application_writes_hex=[
                part.hex() for part in (combined[:1], combined[1:8], combined[8:])
            ],
        )
    )
    return rows


class TransportMatrixTests(unittest.TestCase):
    def test_full_matrix_accepts_out_of_order_pipeline_and_complete_recovery(self):
        self.assertEqual(
            check_rows(fixture()),
            dict(
                servers=1,
                responses=33,
                truncated_udp=3,
                tc_trailing_datagrams=0,
                failed_reply_checks=0,
            ),
        )

    def test_missing_record_or_missing_tc_cannot_pass_as_complete(self):
        for tcp in (False, True):
            request = query("many", "A", 512, 1)
            reply = dns.message.from_wire(response(request, 512, partial=True))
            reply.flags &= ~dns.flags.TC
            with self.subTest(tcp=tcp), self.assertRaises(AssertionError):
                check_reply(request, reply.to_wire(), 512, tcp)

    def test_partial_correct_rrset_with_tc_is_permitted_but_wrong_data_is_not(self):
        for payload in (512, 4096):
            request = query("many", "A", payload, 1)
            wire = response(request, payload, partial=True)
            self.assertTrue(check_reply(request, wire, payload, False)["tc"])
        request = query("many", "A", 512, 1)
        wire = response(request, 512, partial=True)
        reply = dns.message.from_wire(wire)
        reply.answer[0] = dns.rrset.from_text(
            request.question[0].name, 300, "IN", "A", "203.0.113.1"
        )
        with self.assertRaises(AssertionError):
            check_reply(request, reply.to_wire(), 512, False)

    def test_tc_trailing_bytes_are_diagnostic_and_do_not_block_tcp_recovery(self):
        request = query("many", "A", 512, 1)
        wire = response(request, 512, partial=True) + bytes.fromhex("046d616e7907")
        observation = check_reply(request, wire, 512, False)
        self.assertEqual(observation["strict_decoder"], "TrailingJunk")
        self.assertEqual(
            observation["counted_layout"]["trailing_wire_hex"], "046d616e7907"
        )
        self.assertEqual(observation["counted_layout"]["counted_end"], len(wire) - 6)
        with self.assertRaises(AssertionError):
            check_reply(request, wire, 512, True)

    def test_duplicate_id_missing_pipeline_reuse_and_bad_frame_fail(self):
        for label in ("duplicate", "missing", "reuse", "frame", "question", "writes"):
            rows = fixture()
            pipeline = [
                i for i, row in enumerate(rows) if row.get("phase") == "pipeline"
            ]
            if label == "duplicate":
                rows[pipeline[0]] = copy.deepcopy(rows[pipeline[1]])
            elif label == "missing":
                rows.pop(pipeline[0])
            elif label == "reuse":
                rows = [row for row in rows if row.get("phase") != "reuse"]
            elif label == "frame":
                rows[pipeline[0]]["received_frame_hex"] = (
                    "0000" + rows[pipeline[0]]["response_wire_hex"]
                )
            elif label == "writes":
                summary = rows[-1]
                summary["application_writes_hex"] = [
                    "".join(summary["application_writes_hex"])
                ]
            else:
                row = rows[pipeline[0]]
                reply = dns.message.from_wire(bytes.fromhex(row["response_wire_hex"]))
                reply.id ^= 1
                row["response_wire_hex"] = reply.to_wire().hex()
            with self.subTest(label=label), self.assertRaises(AssertionError):
                check_rows(rows)
        with self.assertRaises(AssertionError):
            check_rows([])

    def test_udp_payload_advertisement_does_not_limit_complete_tcp_response(self):
        request = query("many", "A", 512, 1)
        wire = response(request, 512)
        self.assertGreater(len(wire), 1232)
        self.assertEqual(check_reply(request, wire, 512, True)["records"], 96)
        with self.assertRaisesRegex(AssertionError, "UDP payload"):
            check_reply(request, wire, 512, False)

    def test_evidence_replay_preserves_recorded_failure_without_claiming_it_passed(
        self,
    ):
        rows = fixture()
        row = rows[0]
        reply = dns.message.from_wire(bytes.fromhex(row["response_wire_hex"]))
        reply.answer[0] = dns.rrset.from_text(
            "many.example.test.", 300, "IN", "A", "203.0.113.1"
        )
        row.update(
            response_wire_hex=reply.to_wire().hex(),
            observed=None,
            error="AssertionError: truncated response contains incorrect data",
        )
        self.assertEqual(check_rows(rows, allow_errors=True)["failed_reply_checks"], 1)
        with self.assertRaises(AssertionError):
            check_rows(rows)

    def test_fragmented_and_coalesced_response_frames_are_not_misparsed(self):
        class Stream:
            def __init__(self, data):
                self.data = data

            def recv(self, count):
                count = min(count, 1)
                part, self.data = self.data[:count], self.data[count:]
                return part

        request = query("www", "A", None, 10)
        wire = response(request, None)
        stream = Stream(frame(wire) * 2)
        self.assertEqual(read_frame(stream), (wire, frame(wire)))
        self.assertEqual(read_frame(stream), (wire, frame(wire)))
        self.assertEqual(stream.data, b"")
        with self.assertRaises(EOFError):
            read_frame(Stream(frame(wire)[:-1]))
        with self.assertRaises(AssertionError):
            read_frame(Stream(b"\x00\x00"))


if __name__ == "__main__":
    unittest.main()
