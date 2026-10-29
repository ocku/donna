"""Opt-in, paused-trial Linux server-process CPU accounting (not host CPU)."""

import subprocess


def parse_processes(text):
    processes = {}
    for line in text.splitlines():
        pid, opening, rest = line.partition(" (")
        if not opening:
            continue
        name, closing, fields = rest.rpartition(") ")
        if not closing or not name.startswith(
            ("listeners", "named", "knotd", "nsd", "hickory-dns")
        ):
            continue
        values = fields.split()
        if len(values) < 20 or not pid.isdecimal():
            raise ValueError("incomplete server process stat")
        identity = f"{pid}:{values[19]}"  # PID + Linux starttime, field 22
        processes[identity] = {
            "comm": name,
            "user_ticks": int(values[11]),
            "system_ticks": int(values[12]),
        }
    if not processes:
        raise ValueError("no authoritative server processes found")
    return processes


def snapshot(container):
    clock = subprocess.check_output(
        ["docker", "exec", container, "getconf", "CLK_TCK"], text=True, timeout=10
    )
    result = subprocess.run(
        [
            "docker",
            "exec",
            container,
            "find",
            "/proc",
            "-maxdepth",
            "2",
            "-type",
            "f",
            "-name",
            "stat",
            "-exec",
            "cat",
            "{}",
            "+",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Unrelated short-lived exec processes can disappear during traversal. The
    # target process set and starttimes must nevertheless match across samples.
    return {"hz": int(clock.strip()), "processes": parse_processes(result.stdout)}


def difference(before, after, queries):
    if before["hz"] != after["hz"] or before["hz"] <= 0 or queries <= 0:
        raise ValueError("invalid CPU sample clock or query count")
    if before["processes"].keys() != after["processes"].keys():
        raise ValueError("server process identity changed during trial")
    result = {
        "clock_hz": before["hz"],
        "processes": len(before["processes"]),
        "before": before,
        "after": after,
        "quantization_ns_per_query": 1e9 / before["hz"] / queries,
        "scope": "server processes only; excludes kernel CPU outside those processes",
    }
    result["rounding_bound_ns_per_query"] = (
        2 * len(before["processes"]) * result["quantization_ns_per_query"]
    )
    for category in ("user", "system"):
        key = category + "_ticks"
        deltas = [
            after["processes"][pid][key] - values[key]
            for pid, values in before["processes"].items()
        ]
        if any(ticks < 0 for ticks in deltas):
            raise ValueError("server CPU counter moved backwards")
        ticks = sum(deltas)
        result[key] = ticks
        result[category + "_ns_per_query"] = ticks * 1e9 / before["hz"] / queries
    result["total_ns_per_query"] = (
        result["user_ns_per_query"] + result["system_ns_per_query"]
    )
    return result
