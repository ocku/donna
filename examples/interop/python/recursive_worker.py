"""Untimed preparation and independent verification around native recursive load."""

import argparse
import json
from pathlib import Path
import socket
import time

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.flags
import dns.message
import dns.rcode

from recursive_capture import compact, read_compact
from recursive_evidence import Verifier, authenticated_keys, zones, rrset
from recursive_fixture import (
    cases,
    preloads,
    pool,
    frame,
    request,
    expiry_cases,
)
from recursive_refresh import Refreshes


def fetch(address, case, cd=False):
    query = request(case, cd)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(12)
        peer.connect(address)
        assert peer.send(query) == len(query)
        wire = peer.recv(65535)
        monotonic_ns, wall = time.monotonic_ns(), time.time()
    message = dns.message.from_wire(wire)
    assert dns.message.from_wire(query).is_response(message)
    return dict(
        case=case,
        cd=cd,
        query=query.hex(),
        response=wire.hex(),
        received_monotonic_ns=monotonic_ns,
        checked_at=wall,
    ), message


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "inputs",
            "capability",
            "preload",
            "verify",
            "security",
            "coherence",
            "expiry",
        ),
    )
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--kind", choices=("all", "direct", "dname"), default="all")
    parser.add_argument("--path", default="/suite/state.json")
    parser.add_argument("--cd-first", action="store_true")
    args = parser.parse_args()
    address = args.host, args.port
    public = json.loads(Path("/work/public.json").read_text())
    kind = None if args.kind == "all" else args.kind
    if args.action == "inputs":
        for label in ("all", "direct", "dname"):
            packets = pool(kind=None if label == "all" else label)
            Path("/suite/" + label + ".queries").write_bytes(frame(packets))
        print(
            json.dumps(
                dict(
                    input_populations={
                        label: len(pool(kind=None if label == "all" else label))
                        for label in ("all", "direct", "dname")
                    }
                )
            )
        )
    elif args.action == "capability":
        records = []
        for case in [
            dict(
                kind="direct",
                name="www.example.test.",
                rtype="A",
                target="www.example.test.",
                value="192.0.2.80",
            ),
            next(case for case in cases("direct") if case["rtype"] == "AAAA"),
            dict(
                kind="dname",
                name="prime.old.example.test.",
                rtype="A",
                target="prime.dest.example.test.",
                value="192.0.2.80",
            ),
        ]:
            capture = None
            try:
                capture, message = fetch(address, case)
                verifier = Verifier(public, capture["checked_at"])
                verifier.verify(case, capture)
                records.append(
                    dict(
                        kind=case["kind"],
                        case=case,
                        passed=True,
                        capture=capture,
                        flags=message.flags,
                    )
                )
            except Exception as error:
                records.append(
                    dict(
                        kind=case["kind"],
                        case=case,
                        passed=False,
                        error=repr(error),
                        capture=capture,
                    )
                )
        print(json.dumps(dict(capabilities=records)), flush=True)
    elif args.action == "preload":
        verifier = Verifier(public, time.time())
        captures = []
        for case in preloads(kind):
            capture, message = fetch(address, case)
            verifier.verify(case, capture)
            captures.append(capture)
        record = dict(captures=captures, verification=verifier.summary())
        Path(args.path).write_text(json.dumps(record))
        print(
            json.dumps(
                dict(
                    preloaded=len(captures),
                    deadlines=len(verifier.deadlines),
                    flags=message.flags,
                    state=args.path,
                )
            ),
            flush=True,
        )
    elif args.action == "verify":
        path = Path(args.path)
        native = json.loads(Path(str(path) + ".json").read_text())
        inputs = pool(kind=kind)
        compact_path = Path(str(path) + ".rcc")
        packing = compact(path, compact_path, inputs, native)
        state_path = Path(str(path) + ".preload.json")
        deadlines = (
            json.loads(state_path.read_text())["verification"]["deadlines"]
            if state_path.exists()
            else None
        )
        refresh_path = Path(str(path) + ".refresh.json")
        refreshes = (
            Refreshes(json.loads(refresh_path.read_text()))
            if refresh_path.exists()
            else None
        )
        verifier = Verifier(
            public,
            native["started_unix_seconds"],
            deadlines=deadlines,
            refreshes=refreshes,
        )
        plan = cases(kind)
        for capture in read_compact(compact_path, inputs, native):
            verifier.verify(plan[capture["index"]], capture)
        authenticated_keys(public, native["ended_unix_seconds"])
        verification = verifier.summary()
        result = dict(compaction=packing, verification=verification)
        Path(str(path) + ".verified.json").write_text(json.dumps(result))
        path.unlink()
        print(
            json.dumps(
                dict(
                    compaction=packing,
                    verification={
                        k: v for k, v in verification.items() if k != "deadlines"
                    },
                )
            ),
            flush=True,
        )
    elif args.action == "coherence":
        verifier = Verifier(public, time.time())
        captures = []
        for rtype, value in [
            ("A", "192.0.2.84"),
            ("AAAA", "2001:db8::84"),
            ("TXT", '"coherence"'),
        ]:
            case = dict(
                kind="direct",
                name="coherence.example.test.",
                target="coherence.example.test.",
                rtype=rtype,
                value=value,
            )
            capture, _ = fetch(address, case)
            verifier.verify(case, capture)
            captures.append(capture)
        case = dict(
            kind="direct",
            name="coherence.example.test.",
            target="coherence.example.test.",
            rtype="RRSIG",
            value="",
        )
        capture, message = fetch(address, case)
        covered = []
        if message.rcode() == 0:
            leaf = zones(public)["leaf"]
            keys = authenticated_keys(public, capture["checked_at"])
            for record in message.answer:
                assert (
                    record.rdtype == dns.rdatatype.RRSIG
                    and record.name == dns.name.from_text(case["name"])
                    and record.rdclass == 1
                )
                for sig in record:
                    data = rrset(leaf, record.name, sig.type_covered)
                    dns.dnssec.validate_rrsig(
                        data, sig, keys, now=capture["checked_at"]
                    )
                    covered.append(sig.type_covered)
        print(
            json.dumps(
                dict(
                    coherence=captures,
                    rrsig_observation=capture,
                    rrsig_rcode=message.rcode(),
                    covered_types=sorted(covered),
                )
            ),
            flush=True,
        )
    elif args.action == "security":
        case = dict(
            kind="direct",
            name="www.example.test.",
            rtype="A",
            target="www.example.test.",
            value="192.0.2.80",
        )
        records = []
        for cd in (True, False) if args.cd_first else (False, True):
            capture, message = fetch(address, case, cd)
            assert (
                bool(message.flags & dns.flags.CD) == cd
                and not message.flags & dns.flags.AD
            )
            assert message.flags & dns.flags.RA and message.flags & dns.flags.RD
            assert not message.flags & (dns.flags.AA | dns.flags.TC)
            try:
                authenticated_keys(public, capture["checked_at"], bad=True)
            except AssertionError as error:
                assert "DS does not match" in str(error)
            else:
                raise AssertionError("bad DS unexpectedly authenticates leaf")
            if cd:
                assert message.rcode() == 0
                Verifier(public, capture["checked_at"], trusted=False).verify(
                    case, capture, cd=True, ad=False
                )
            else:
                assert message.rcode() == dns.rcode.SERVFAIL and not message.answer
            records.append(capture)
        print(json.dumps(dict(security=records, cd_first=args.cd_first)), flush=True)
    else:
        verifier = Verifier(public, time.time())
        selected = [
            case for case in expiry_cases() if kind is None or case["kind"] == kind
        ]
        deadline = 0
        for phase in ("initial", "warm", "expired"):
            if phase == "expired":
                time.sleep(max(0, (deadline - time.monotonic_ns()) / 1e9) + 0.25)
                verifier = Verifier(public, time.time())
            captures = []
            for case in selected:
                capture, _ = fetch(address, case)
                verifier.verify(case, capture)
                captures.append(capture)
                if phase == "initial":
                    message = dns.message.from_wire(bytes.fromhex(capture["response"]))
                    ttl = min(rr.ttl for rr in message.answer)
                    deadline = max(
                        deadline, capture["received_monotonic_ns"] + ttl * 1_000_000_000
                    )
            print(
                json.dumps(
                    dict(expiry_phase=phase, captures=captures, deadline_ns=deadline)
                ),
                flush=True,
            )
            assert input().strip() == "continue"


if __name__ == "__main__":
    main()
