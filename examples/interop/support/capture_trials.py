"""Shared capture measurement and public evidence accounting for resolver labs."""

import hashlib
import json
import re
import subprocess
import time
from collections import Counter

from python.recursive_refresh import events

from .daemon import record_runtime_identity, resolver_port
from .docker import docker
from .recursive_lab import ADDRESSES, CLIENT, PREFIX, delta


def requests(logs, address):
    result = Counter()
    for zone, text in logs.items():
        for name, kind in re.findall(
            re.escape(address) + r"#.*query: (\S+) IN (\S+)", text
        ):
            result[zone + "/" + name.lower().rstrip(".") + "/" + kind] += 1
    return result


def checkpoint(logs):
    return {
        name: dict(
            bytes=len(text.encode()), sha256=hashlib.sha256(text.encode()).hexdigest()
        )
        for name, text in logs.items()
    }


def request_delta(before, after, address):
    old, new = requests(before, address), requests(after, address)
    assert all(new[key] >= count for key, count in old.items())
    return dict(new - old)


class CaptureTrials:
    def __init__(self, args, lab, record, evidence, *, negative=False):
        self.args = args
        self.lab = lab
        self.record = record
        self.evidence = evidence
        self.negative = negative
        self.worker_script = "negative_worker.py" if negative else "recursive_worker.py"

    def command(self, argv):
        run = subprocess.run(
            argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        self.record["raw_commands"].append(
            dict(argv=argv, exit_code=run.returncode, output=run.stdout)
        )
        assert run.returncode == 0, run.stdout
        return run.stdout

    def worker(self, action, role=None, extra=()):
        argv = [
            "docker",
            "exec",
            CLIENT,
            "python",
            "/suite/" + self.worker_script,
            action,
        ]
        if role:
            record_runtime_identity(self.record, role, PREFIX + role)
            argv += [
                "--host",
                ADDRESSES[role],
                "--port",
                str(resolver_port(role)),
            ]
        return json.loads(self.command(argv + list(extra)))

    def phase(
        self,
        role,
        label,
        trial,
        kind,
        flags,
        preload=None,
        cold_logs=None,
        preload_logs=None,
    ):
        record_runtime_identity(self.record, role, PREFIX + role)
        name = f"{role}-{label}-{trial}-{kind}"
        remote = "/suite/" + name + ".capture"
        preload_checkpoints = None
        if preload_logs is not None:
            pre_after = self.lab.authority_logs()
            pre_events = events(preload_logs, pre_after, ADDRESSES[role])
            saved = self.evidence / (name + ".preload.events.json")
            saved.write_text(json.dumps(pre_events))
            docker("cp", str(saved), CLIENT + ":" + preload + ".events.json")
            self.worker("freeze", extra=("--path", preload))
            preload_checkpoints = dict(
                before=checkpoint(preload_logs), after=checkpoint(pre_after)
            )
        # Imports, packet validation and preload work finish before this
        # quiet period; the timed process is the native executable itself.
        time.sleep(0.25)
        logs_before = cold_logs or self.lab.authority_logs()
        before = self.lab.snapshots()
        output = self.command(
            [
                "docker",
                "exec",
                CLIENT,
                "batched_load",
                ADDRESSES[role],
                str(resolver_port(role)),
                str(self.args.seconds if label == "warm" else 20),
                str(flags),
                "/suite/" + kind + ".queries",
                "cycle" if label == "warm" else "finite",
                "--window",
                "32",
                "--capture-responses",
                remote,
                *(
                    ["--capture-budget-bytes", str(self.args.capture_budget_bytes)]
                    if self.negative
                    else []
                ),
            ]
        )
        native = json.loads(output)
        if self.negative:
            assert native["capture_budget_bytes"] == self.args.capture_budget_bytes
        after = self.lab.snapshots()
        logs_after = self.lab.authority_logs()
        acquired = request_delta(logs_before, logs_after, ADDRESSES[role])
        witnesses = events(logs_before, logs_after, ADDRESSES[role])
        refresh_path = self.evidence / (name + ".refresh.json")
        refresh_path.write_text(json.dumps(witnesses))
        docker("cp", str(refresh_path), CLIENT + ":" + remote + ".refresh.json")
        metadata = self.evidence / (name + ".json")
        metadata.write_text(json.dumps(native))
        docker("cp", str(metadata), CLIENT + ":" + remote + ".json")
        if preload:
            docker(
                "cp",
                CLIENT + ":" + preload,
                str(self.evidence / (name + ".preload.json")),
            )
            docker("exec", CLIENT, "cp", preload, remote + ".preload.json")
        try:
            checked = self.worker("verify", extra=("--kind", kind, "--path", remote))
        except Exception:
            for suffix in (".rcc", ""):
                target = self.evidence / (
                    name + (".rcc" if suffix else ".failed.capture")
                )
                docker(
                    "cp",
                    CLIENT + ":" + remote + suffix,
                    str(target),
                    check=False,
                    capture=True,
                )
                if target.exists():
                    break
            raise
        for suffix in (".rcc", ".verified.json"):
            docker(
                "cp",
                CLIENT + ":" + remote + suffix,
                str(self.evidence / (name + suffix)),
            )
        item = dict(
            role=role,
            label=label,
            repeat=trial,
            kind=kind,
            native=native,
            native_output=output,
            verification=checked,
            expected_response_flags=flags,
            capture=name + ".rcc",
            cpu_before=before,
            cpu_after=after,
            cpu_delta={name: delta(before[name], after[name]) for name in before},
            authority_requests=acquired,
            request_total=sum(acquired.values()),
            authority_events=witnesses,
            zero_upstream_reuse=not acquired,
            log_checkpoints=dict(
                before=checkpoint(logs_before), after=checkpoint(logs_after)
            ),
            scope="Cold includes logged authority acquisition; warm upstream requests are reported; any renewed deadline requires an owner/type/timestamp witness; client capture overhead and cgroup read/invocation overhead retained",
        )
        if preload_checkpoints is not None:
            item["preload_log_checkpoints"] = preload_checkpoints
        if label == "cold":
            item["resolver_total_usage_since_creation_usec"] = after[role]["usage_usec"]
        self.record["trials"].append(item)
        print(
            json.dumps(
                dict(
                    completed=label,
                    role=role,
                    repeat=trial,
                    kind=kind,
                    responses=native["queries"],
                    qps=native["qps"],
                    upstream=item["request_total"],
                )
            ),
            flush=True,
        )
        return item
