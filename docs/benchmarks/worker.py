"""Container-side measurements for the documented, unsigned UDP workloads."""

import argparse
import contextlib
import io
import json
import os
import socket
import subprocess
import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
from cache_load import measure


def query(case):
    name, kind = {
        "positive": ("www.example.test.", "A"),
        "negative": ("missing.example.test.", "A"),
        "wildcard": ("m.wild.example.test.", "TXT"),
        "cname": ("alias.example.test.", "A"),
    }[case]
    return dns.message.make_query(name, kind, use_edns=0, payload=1232)


def verify(q, r, case, recursive):
    assert q.is_response(r) and not r.flags & dns.flags.TC
    assert r.rcode() == (dns.rcode.NXDOMAIN if case == "negative" else 0)
    assert bool(r.flags & dns.flags.RA) == recursive
    assert not r.flags & dns.flags.AD  # unsigned hierarchy, validation disabled
    if not recursive:
        assert r.flags & dns.flags.AA
    if case == "negative":
        assert not r.answer
        assert any(
            x.rdtype == dns.rdatatype.SOA
            and x.name.to_text() == "example.test."
            and x[0].minimum == 30
            for x in r.authority
        )
    elif case == "wildcard":
        assert len(r.answer) == 1 and r.answer[0].name == q.question[0].name
        assert r.answer[0].rdtype == dns.rdatatype.TXT and r.answer[0][0].strings == (
            b"wildcard",
        )
    else:
        assert len(r.answer) == (2 if case == "cname" else 1)
        assert any(
            x.rdtype == dns.rdatatype.A
            and x.name.to_text() == "www.example.test."
            and x[0].address == "192.0.2.80"
            for x in r.answer
        )
        if case == "cname":
            assert any(
                x.rdtype == dns.rdatatype.CNAME
                and x.name == q.question[0].name
                and x[0].target.to_text() == "www.example.test."
                for x in r.answer
            )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("load", "cold", "cli"))
    p.add_argument("host")
    p.add_argument("--case", default="positive")
    p.add_argument("--recursive", action="store_true")
    p.add_argument("--seconds", type=int, default=3)
    p.add_argument("--repeat", type=int, default=0)
    args = p.parse_args()
    if args.mode == "cli":
        commands = {
            "donna": [
                "donna",
                "query",
                "www.example.test.",
                "A",
                "-s",
                args.host,
                "--short",
                "--no-edns",
                "--attempts",
                "1",
                "--timeout",
                "2",
            ],
            "dig": [
                "dig",
                "@" + args.host,
                "www.example.test.",
                "A",
                "+short",
                "+noedns",
                "+adflag",
                "+tries=1",
                "+timeout=2",
            ],
        }
        samples = {name: [] for name in commands}
        env = {**os.environ, "TOKIO_WORKER_THREADS": "1"}
        for repeat in range(70):
            order = list(commands) if repeat % 2 == 0 else list(reversed(commands))
            for name in order:
                started = time.perf_counter_ns()
                result = subprocess.run(
                    commands[name], check=True, capture_output=True, env=env
                )
                elapsed = (time.perf_counter_ns() - started) / 1e6
                assert result.stdout.strip() == b"192.0.2.80", result.stdout
                if repeat >= 10:
                    samples[name].append(elapsed)
        print(
            json.dumps(
                {
                    "commands": commands,
                    "warmup": 10,
                    "samples_ms": samples,
                    "versions": {
                        name: subprocess.check_output(
                            [name, "--version" if name == "donna" else "-v"], text=True
                        ).strip()
                        for name in commands
                    },
                }
            )
        )
        return
    q = query(args.case)
    if not args.recursive:
        q.flags &= ~dns.flags.RD
    started = time.perf_counter_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.settimeout(10)
        peer.connect((args.host, 53))
        peer.send(q.to_wire())
        response_wire = peer.recv(65535)
    response = dns.message.from_wire(response_wire)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    verify(q, response, args.case, args.recursive)
    if args.mode == "cold":
        print(
            json.dumps(
                {
                    "elapsed_ms": elapsed,
                    "question": q.to_text(),
                    "response": response.to_text(),
                }
            )
        )
        return
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        measure(
            "peer",
            (args.host, 53),
            [(q, q.to_wire(), response.rcode())],
            args.case,
            args.repeat,
            args.seconds,
            query_format="edns",
            load_client="batched",
            expected_response_wire=None if args.recursive else response_wire,
        )
    row = json.loads(capture.getvalue())
    after = dns.query.udp(q, args.host, timeout=10)
    verify(q, after, args.case, args.recursive)
    row["semantic_pre_post_checks"] = "PASS"
    row["reference_response"] = response.to_text()
    print(json.dumps(row))


if __name__ == "__main__":
    main()
