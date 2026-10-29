"""Optional native UDP load client; correctness is checked before each run."""

import json
import hashlib
import re
import resource
import subprocess
import tempfile
import time

import dns.rdatatype
import dns.query


def run_load(command):
    try:
        return subprocess.run(command, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"load client exited {error.returncode}: {command!r}\n"
            f"stdout:\n{error.stdout or ''}\nstderr:\n{error.stderr or ''}"
        ) from error


def measure(
    server,
    address,
    prepared,
    kind,
    repeat,
    seconds,
    source_port=None,
    query_format="classic",
    binary_queries=False,
    max_runs=None,
    load_client="dnsperf",
    expected_response_flags=None,
    expected_response_wire=None,
):
    if expected_response_wire is not None and (
        load_client != "batched" or len(prepared) != 1 or max_runs is not None
    ):
        raise ValueError(
            "exact response verification requires a repeated authoritative batched fixture"
        )
    if load_client == "batched":
        finite = max_runs == 1
        if (
            not prepared
            or source_port is not None
            or max_runs not in (None, 1)
            or (not finite and len(prepared) > 2048)
        ):
            raise ValueError(
                "batched diagnostic requires a bounded repeated pool or one finite pass"
            )
        cycling = not finite and len(prepared) > 1
        query, wire, rcode = prepared[0]
        if any(code != rcode for _, _, code in prepared):
            raise ValueError("batched diagnostic requires one expected response code")
        if finite:
            if expected_response_flags is None or expected_response_flags & 15 != rcode:
                raise ValueError(
                    "finite diagnostic needs flags from a separate control owner"
                )
            flags = expected_response_flags
        else:
            before_reply = dns.query.udp(query, address[0], port=address[1], timeout=3)
            if not query.is_response(before_reply) or before_reply.rcode() != rcode:
                raise RuntimeError("batched preflight mismatch")
            flags = before_reply.flags
        with (
            tempfile.NamedTemporaryFile(mode="wb", suffix=".wire") as data,
            tempfile.NamedTemporaryFile(mode="wb", suffix=".response") as expected,
        ):
            if finite or cycling:
                for _, wire, _ in prepared:
                    data.write(len(wire).to_bytes(2, "big") + wire)
            else:
                data.write(wire)
            data.flush()
            command = [
                "batched_load",
                address[0],
                str(address[1]),
                str(seconds),
                str(flags),
                data.name,
            ]
            if finite:
                command.append("finite")
            elif cycling:
                command.append("cycle")
            if expected_response_wire is not None:
                expected.write(expected_response_wire)
                expected.flush()
                command += ["--expected-response", expected.name]
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.perf_counter()
            result = run_load(command)
            elapsed = time.perf_counter() - started
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = json.loads(result.stdout)
        if (
            expected_response_wire is not None
            and row.get("response_body_verified") is not True
        ):
            raise RuntimeError(
                "native client did not verify the expected authoritative response"
            )
        if (
            row["sent"] != row["queries"]
            or row["lost"] != 0
            or (finite and row["queries"] != len(prepared))
        ):
            raise RuntimeError("incomplete batched run")
        if not finite:
            after_reply = dns.query.udp(query, address[0], port=address[1], timeout=3)
            if (
                not query.is_response(after_reply)
                or after_reply.flags != flags
                or after_reply.rcode() != rcode
            ):
                raise RuntimeError("batched postflight mismatch")
        cpu_seconds = (after.ru_utime + after.ru_stime) - (
            before.ru_utime + before.ru_stime
        )
        row.update(
            server=server,
            workload=kind,
            repeat=repeat,
            client="batched",
            population=len(prepared),
            outstanding=32,
            query_format=query_format,
            input_mode="finite" if finite else ("cycle" if cycling else "repeat"),
            source_port=None,
            binary_queries=True,
            max_runs=max_runs,
            client_wall_seconds=elapsed,
            client_cpu_seconds=cpu_seconds,
            client_cpu_percent=100 * cpu_seconds / elapsed,
            native_output=result.stdout,
            scope="diagnostic batched native client; dnsperf results retained separately",
        )
        if expected_response_wire is not None:
            row.update(
                expected_response_wire_hex=expected_response_wire.hex(),
                query_wire_hex=wire.hex(),
                expected_body_sha256=hashlib.sha256(
                    expected_response_wire[2:]
                ).hexdigest(),
                expected_response_bytes=len(expected_response_wire),
                body_verification_scope="every timed response matches this independently validated immutable authoritative packet, excluding only the two-byte ID",
            )
        # Keep the common native-client row prefix used by the host drivers.
        print(
            json.dumps({"server": server, "workload": kind, "repeat": repeat, **row}),
            flush=True,
        )
        return
    if load_client != "dnsperf":
        raise ValueError("unknown load client")
    with tempfile.NamedTemporaryFile(
        mode="wb" if binary_queries else "w", suffix=".queries"
    ) as data:
        for query, wire, _ in prepared:
            if binary_queries:
                data.write(len(wire).to_bytes(2, "big") + wire)
            else:
                data.write(
                    f"{query.question[0].name} {dns.rdatatype.to_text(query.question[0].rdtype)}\n"
                )
        data.flush()
        command = [
            "dnsperf",
            "-s",
            address[0],
            "-p",
            str(address[1]),
            "-d",
            data.name,
            "-l",
            str(seconds),
            "-q",
            "32",
            "-c",
            "1",
            "-T",
            "1",
            "-t",
            "2",
        ]
        if max_runs is not None:
            command += ["-n", str(max_runs)]
        if source_port is not None:
            command += ["-x", str(source_port)]
        if binary_queries:
            command += ["-B"]
        elif query_format == "edns":
            command += ["-e"]
        elif query_format == "edns-do":
            command += ["-D"]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.perf_counter()
        result = run_load(command)
        elapsed = time.perf_counter() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu_seconds = (after.ru_utime + after.ru_stime) - (
            before.ru_utime + before.ru_stime
        )
    output = result.stdout + result.stderr

    def metric(label):
        found = re.search(
            r"^\s*" + re.escape(label) + r"\s*:\s*([0-9.]+)", output, re.M
        )
        if not found:
            raise RuntimeError(f"missing dnsperf metric {label}\n{output}")
        return float(found[1])

    sent, completed = metric("Queries sent"), metric("Queries completed")
    if sent != completed or metric("Queries lost") != 0:
        raise RuntimeError(f"load comparison lost requests\n{output}")
    if max_runs is not None and completed != len(prepared) * max_runs:
        raise RuntimeError(
            f"finite load did not complete its exact query list\n{output}"
        )
    expected = "NXDOMAIN" if kind == "negative" else "NOERROR"
    codes = re.search(r"Response codes:\s*(.*)", output)
    if not codes or not re.fullmatch(
        re.escape(expected) + r"\s+\d+\s+\(100\.00%\)", codes[1].strip()
    ):
        raise RuntimeError(f"unexpected response codes\n{output}")
    print(
        json.dumps(
            {
                "server": server,
                "workload": kind,
                "repeat": repeat,
                "client": "dnsperf",
                "population": len(prepared),
                "outstanding": 32,
                "queries": int(completed),
                "qps": metric("Queries per second"),
                "mean_us": metric("Average Latency (s)") * 1000000,
                "query_format": query_format,
                "source_port": source_port,
                "binary_queries": binary_queries,
                "max_runs": max_runs,
                "client_wall_seconds": elapsed,
                "client_cpu_seconds": cpu_seconds,
                "client_cpu_percent": 100 * cpu_seconds / elapsed,
                # Retain native tail latency and diagnostics as evidence.
                # Summary extraction and printing happen after timing.
                "native_output": output,
            }
        ),
        flush=True,
    )
