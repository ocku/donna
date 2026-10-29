#!/usr/bin/env python3
"""Execute the pinned Hickory clients in Docker against both Donna roles."""

import argparse
import json
import re
import subprocess
from pathlib import Path


def check_answers(output, name, resolver=False):
    marker = ";; ANSWER SECTION:\n" if resolver else "; answers "
    section = output.split(marker, 1)[1]
    if resolver:
        section = section.split(";; ", 1)[0]
    else:
        count, section = section.split("\n", 1)
        section = section.split("; authorities", 1)[0]
    records = []
    for line in section.splitlines():
        if not line.strip():
            continue
        owner, ttl, rdclass, kind, value = line.split(maxsplit=4)
        assert ttl.isdecimal() and rdclass == "IN", line
        records.append((owner.lower(), kind, value.lower()))
    if not resolver:
        assert len(records) == int(count), output
    if name.startswith("many."):
        expected = [(name, "A", f"192.0.2.{number}") for number in range(1, 97)]
    elif name.startswith("alias."):
        expected = [
            (name, "CNAME", "www.example.test."),
            ("www.example.test.", "A", "192.0.2.80"),
        ]
    elif name.startswith("www."):
        expected = [(name, "A", "192.0.2.80")]
    else:
        expected = []
    assert sorted(records) == sorted(expected), output


def check_clients(image, network, servers):
    rows = []
    for role, address in servers:
        for protocol in ("udp", "tcp"):
            for name, status, answer in (
                ("www.example.test.", "NoError", "192.0.2.80"),
                ("alias.example.test.", "NoError", "192.0.2.80"),
                ("missing.example.test.", "NXDomain", None),
                ("text.example.test.", "NoError", None),
            ):
                command = [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    network,
                    image,
                    "dns",
                    "--nameserver",
                    address,
                    "--protocol",
                    protocol,
                    "query",
                    name,
                    "A",
                ]
                result = subprocess.run(
                    command, text=True, capture_output=True, timeout=30
                )
                output = result.stdout
                if result.returncode or not re.search(
                    rf"; header .*:{status}:QUERY", output
                ):
                    raise RuntimeError(
                        f"Hickory query failed: {command}\n{output}\n{result.stderr}"
                    )
                check_answers(output, name)
                if not answer and (
                    "; answers 0\n" not in output
                    or not re.search(r"example\.test\.\s+\d+\s+IN\s+SOA", output)
                ):
                    raise AssertionError(
                        f"negative answer must be empty and include SOA: {output}"
                    )
                rows.append(
                    dict(role=role, protocol=protocol, name=name, output=output)
                )
        # The resolver utility uses the high-level library, including CNAME
        # following and UDP/TCP fallback. Its exit code alone does not prove a
        # successful lookup; it also returns zero for NoRecordsFound.
        for name in ("www.example.test.", "alias.example.test.", "many.example.test."):
            command = [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                image,
                "resolve",
                "--nameserver",
                address,
                name,
            ]
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
            if result.returncode or "Success for query" not in output:
                raise RuntimeError(
                    f"Hickory resolver failed: {command}\n{output}\n{result.stderr}"
                )
            check_answers(output, name, resolver=True)
            rows.append(
                dict(role=role, protocol="resolver-default", name=name, output=output)
            )
    print(
        f"PASS Hickory clients: {len(rows)} authoritative/recursive checks", flush=True
    )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="donna-interop-hickory:0.26.3")
    parser.add_argument("--network", default="donna-interop-laboratory")
    parser.add_argument("--authority", default="172.29.53.10:5300")
    parser.add_argument("--recursive", default="172.29.53.11:5301")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rows = check_clients(
        args.image,
        args.network,
        (("authority", args.authority), ("recursive", args.recursive)),
    )
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
