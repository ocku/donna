"""Read service RAM from an observer in a separate cgroup and shared PID namespace.

Linux only. Writes JSON to stdout; never resets counters, signals a process or
changes cgroups. Live Docker validation is deliberately separate from parsers.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import sys
import time


class InvalidSample(RuntimeError):
    """Required accounting or stable process identity could not be established."""


def text(path, limit=131072):
    with Path(path).open("rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise InvalidSample(f"oversized accounting file: {path}")
    return data.decode("utf-8", errors="surrogateescape")


def number(value):
    if not value or not value.isascii() or not value.isdecimal():
        raise InvalidSample("expected nonnegative decimal accounting value")
    return int(value)


def process_stat(value):
    left, right = value.find("("), value.rfind(")")
    fields = value[right + 1 :].split()
    if left < 1 or right <= left or len(fields) < 20:
        raise InvalidSample("invalid /proc PID stat")
    return dict(
        pid=number(value[:left].strip()),
        comm=value[left + 1 : right],
        ppid=number(fields[1]),
        threads=number(fields[17]),
        start_ticks=number(fields[19]),
    )


def rollup(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if not fields or not fields[0].endswith(":"):
            continue  # The initial address/mapping line is not a metric.
        if len(fields) != 3 or fields[2] != "kB":
            raise InvalidSample("invalid smaps_rollup unit/field")
        name = fields[0][:-1]
        if name in result:
            raise InvalidSample("duplicate smaps_rollup field")
        result[name] = number(fields[1]) * 1024
    required = (
        "Rss",
        "Pss",
        "Private_Clean",
        "Private_Dirty",
        "Shared_Clean",
        "Shared_Dirty",
    )
    if any(key not in result for key in required):
        raise InvalidSample("incomplete smaps_rollup; no VmRSS fallback")
    return result


def unified_path(value):
    paths = [line[3:] for line in value.splitlines() if line.startswith("0::")]
    if len(paths) != 1 or not paths[0].startswith("/"):
        raise InvalidSample("one unified cgroup-v2 membership is required")
    path = PurePosixPath(paths[0])
    if ".." in path.parts or paths[0].startswith("//") or str(path) != paths[0]:
        raise InvalidSample(
            "relative/unnormalized cgroup path; use host cgroup namespace"
        )
    return path


def group_directory(root, membership):
    return Path(root).joinpath(*membership.parts[1:])


def group_pids(directory):
    pending, visited, result = [(Path(directory), 0)], 0, set()
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > 512 or depth > 16:
            raise InvalidSample("cgroup subtree exceeds bounded collector scope")
        for value in text(current / "cgroup.procs").split():
            pid = number(value)
            if not pid:
                raise InvalidSample(
                    "cgroup contains a process invisible to this PID namespace"
                )
            result.add(pid)
            if len(result) > 1024:
                raise InvalidSample("service has more than1024 processes")
        for child in current.iterdir():
            if child.is_symlink():
                raise InvalidSample("unexpected symlink in cgroup subtree")
            if child.is_dir():
                pending.append((child, depth + 1))
    return sorted(result)


def pairs(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in result:
            raise InvalidSample("invalid cgroup key/value counters")
        result[fields[0]] = number(fields[1])
    return result


def group_memory(directory):
    directory = Path(directory)
    return dict(
        current_bytes=number(text(directory / "memory.current").strip()),
        lifetime_peak_bytes=number(text(directory / "memory.peak").strip()),
        stat_bytes_or_counts=pairs(text(directory / "memory.stat")),
        events=pairs(text(directory / "memory.events")),
        limit=text(directory / "memory.max").strip(),
    )


def measures(raw):
    return dict(
        rss_bytes=raw["Rss"],
        pss_bytes=raw["Pss"],
        private_clean_dirty_bytes=raw["Private_Clean"] + raw["Private_Dirty"],
        shared_clean_dirty_bytes=raw["Shared_Clean"] + raw["Shared_Dirty"],
        swap_bytes=raw.get("Swap", 0),
    )


def sample(proc, cgroups, root_pid, observer_pid, roles=None):
    proc, roles = Path(proc), roles or {}
    started_mono, started_wall = time.monotonic_ns(), time.time_ns()
    pid_namespace = os.readlink(proc / str(root_pid) / "ns/pid")
    if os.readlink(proc / str(observer_pid) / "ns/pid") != pid_namespace:
        raise InvalidSample("observer and service root must share the PID namespace")
    namespace_ids = dict(
        pid=pid_namespace,
        service_cgroup=os.readlink(proc / str(root_pid) / "ns/cgroup"),
        observer_cgroup=os.readlink(proc / str(observer_pid) / "ns/cgroup"),
    )
    target_path = unified_path(text(proc / str(root_pid) / "cgroup"))
    observer_path = unified_path(text(proc / str(observer_pid) / "cgroup"))
    if str(target_path) == "/":
        raise InvalidSample("refuse global/root cgroup as service scope")
    if observer_path == target_path or target_path in observer_path.parents:
        raise InvalidSample("observer is charged to the service cgroup/subtree")
    target = group_directory(cgroups, target_path)
    observer = group_directory(cgroups, observer_path)
    pids = group_pids(target)
    if root_pid not in pids or observer_pid in pids:
        raise InvalidSample(
            "wrong service root or observer present in target membership"
        )
    identities = {pid: process_stat(text(proc / str(pid) / "stat")) for pid in pids}
    before = group_memory(target)
    processes, totals, by_role = [], {}, {}
    for pid in pids:
        identity = identities[pid]
        if identity["pid"] != pid:
            raise InvalidSample("PID accounting identity mismatch")
        raw = rollup(text(proc / str(pid) / "smaps_rollup"))
        exe = os.readlink(proc / str(pid) / "exe")
        role = roles.get(
            identity["comm"],
            roles.get(
                Path(exe).name, "service_main" if pid == root_pid else "service_helper"
            ),
        )
        row = dict(
            **identity, exe=exe, role=role, metrics=measures(raw), rollup_bytes=raw
        )
        processes.append(row)
        for key, value in row["metrics"].items():
            totals[key] = totals.get(key, 0) + value
            bucket = by_role.setdefault(role, {})
            bucket[key] = bucket.get(key, 0) + value
    after = group_memory(target)
    if pids != group_pids(target):
        raise InvalidSample("service process membership changed during sampling")
    for pid in pids:
        current = process_stat(text(proc / str(pid) / "stat"))
        if (current["pid"], current["start_ticks"]) != (
            pid,
            identities[pid]["start_ticks"],
        ):
            raise InvalidSample("service PID exited/reused during sampling")
    if unified_path(text(proc / str(root_pid) / "cgroup")) != target_path:
        raise InvalidSample("service root changed cgroup during sampling")
    observer_metrics = measures(rollup(text(proc / str(observer_pid) / "smaps_rollup")))
    return dict(
        schema=1,
        platform="Linux cgroup-v2 + proc smaps_rollup",
        started_monotonic_ns=started_mono,
        ended_monotonic_ns=time.monotonic_ns(),
        started_unix_ns=started_wall,
        ended_unix_ns=time.time_ns(),
        clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
        service_root_pid=root_pid,
        service_cgroup=str(target_path),
        namespace_ids=namespace_ids,
        processes=processes,
        process_totals=totals,
        process_totals_by_role=by_role,
        cgroup_before=before,
        cgroup_after=after,
        observer=dict(
            pid=observer_pid,
            cgroup=str(observer_path),
            process_metrics=observer_metrics,
            cgroup_memory=group_memory(observer),
            charged_to_service=False,
        ),
        semantics=dict(
            rss="Process sum can double-count shared mappings.",
            pss="Proportional share; sharing depends on other mapped processes, including observer.",
            private="Private_Clean + Private_Dirty; explicit hugetlb remains a separate raw field.",
            cgroup="Includes descendants, file cache and charged kernel memory; not equivalent to process RSS/PSS.",
            peak="Lifetime cgroup high-water since creation; never reset by collector.",
            observer="Separate cgroup: excluded from service process and cgroup totals. PSS/library sharing can still influence values.",
            snapshot="Read interval, not atomic; endpoint membership/start ticks are checked.",
        ),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-pid", type=int, default=1)
    parser.add_argument("--role", action="append", default=[], metavar="PROGRAM=ROLE")
    args = parser.parse_args()
    if sys.platform != "linux" or args.root_pid < 1:
        parser.error("Linux and positive root PID required")
    roles = {}
    for value in args.role:
        key, separator, role = value.partition("=")
        if not separator or not key or not role or len(value) > 256 or key in roles:
            parser.error("role mappings need unique nonempty PROGRAM=ROLE values")
        roles[key] = role
    try:
        print(
            json.dumps(
                sample("/proc", "/sys/fs/cgroup", args.root_pid, os.getpid(), roles)
            )
        )
    except (OSError, InvalidSample) as error:
        print(json.dumps(dict(complete=False, error=str(error))), file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
