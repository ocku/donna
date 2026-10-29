#!/usr/bin/env python3
"""Compare matched authoritative Docker peers without changing Donna source."""

import hashlib
import json
from support.paths import SUITE
from pathlib import Path
import subprocess
import tempfile

from support.lock import exclusive_laboratory
from support.docker import docker
from .similar_fixture import (
    metadata,
    prepare as prepare_fixtures,
    start as start_fixtures,
)
from .similar_cli import arguments
from support.server_cpu import snapshot as cpu_snapshot, difference as cpu_difference

PREFIX = "donna-compare-"
NETWORK = PREFIX + "laboratory"
VOLUME = PREFIX + "fixtures"
CERTS = PREFIX + "certificates"
WORKERS = 2
SERVICES = ("verified", "current", "bind", "knot", "nsd", "hickory")
ROLES = {
    "verified": ("donna-compare-verified", "172.29.54.10"),
    "current": ("donna-compare-current", "172.29.54.11"),
    "bind": ("donna-interop-bind", "172.29.54.20"),
    "knot": ("cznic/knot:3.6", "172.29.54.30"),
    "nsd": ("donna-compare-nsd", "172.29.54.40"),
    "hickory": ("donna-interop-hickory:0.26.3", "172.29.54.50"),
}
ALL_ROLES = dict(ROLES)


def stop():
    docker("rm", "-f", "-v", *(PREFIX + s for s in SERVICES), check=False, capture=True)


def cleanup():
    stop()
    docker(
        "rm",
        "-f",
        "-v",
        *(PREFIX + s for s in ("signer", "probe", "client")),
        check=False,
        capture=True,
    )
    docker("network", "rm", NETWORK, check=False, capture=True)
    docker("volume", "rm", VOLUME, CERTS, check=False, capture=True)


def put(directory, name, text):
    p = directory / name
    p.write_text(text)
    docker("cp", str(p), PREFIX + "signer:/work/" + name)


def start(mode):
    stop()
    start_fixtures(
        mode,
        roles=ROLES,
        prefix=PREFIX,
        network=NETWORK,
        volume=VOLUME,
        certs=CERTS,
        workers=WORKERS,
        docker=docker,
    )


def output_rows(text, mode, phase):
    for line in text.splitlines():
        if line.startswith("{"):
            row = json.loads(line)
            row.update(mode=mode, phase=phase)
            print(json.dumps(row), flush=True)


def quiet_logs(expected=None, *, mode=None, checkpoint=None):
    # The generic docker helper strips text. Preserve every log byte here,
    # including blank lines and trailing whitespace, for the equality gate.
    logs = {
        role: subprocess.run(
            ["docker", "logs", PREFIX + role],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ).stdout
        for role in ROLES
    }
    if expected is not None and logs != expected:
        changed = [role for role in ROLES if logs[role] != expected[role]]
        raise RuntimeError(
            "benchmark query traffic emitted server logs: " + ", ".join(changed)
        )
    print(
        json.dumps(
            {
                "mode": mode,
                "checkpoint": checkpoint,
                "logging_gate": {
                    role: {
                        "bytes": len(value),
                        "sha256": hashlib.sha256(value).hexdigest(),
                    }
                    for role, value in logs.items()
                },
            }
        ),
        flush=True,
    )
    return logs


def stream_rows(command, mode, phase, server_cpu=False):
    """Preserve completed trials even if a later trial fails its loss gate."""
    invocation = ["docker", "exec"] + (["-i"] if server_cpu else [])
    invocation += [PREFIX + "client", *command]
    pending = None
    with subprocess.Popen(
        invocation,
        stdin=subprocess.PIPE if server_cpu else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        for line in process.stdout:
            if line.startswith("{"):
                row = json.loads(line)
                if server_cpu:
                    role = {
                        "donna-verified": "verified",
                        "donna-current": "current",
                    }.get(row["server"], row["server"])
                    sample = cpu_snapshot(PREFIX + role)
                    if "qps" in row:
                        if pending is None or pending[0] != row["server"]:
                            raise RuntimeError("CPU trial handshake lost correlation")
                        row["server_cpu"] = cpu_difference(
                            pending[1], sample, row["queries"]
                        )
                        pending = None
                    else:
                        if pending is not None:
                            raise RuntimeError("CPU trial handshake overlapped")
                        pending = (row["server"], sample)
                    process.stdin.write("continue\n")
                    process.stdin.flush()
                output_rows(json.dumps(row), mode, phase)
            else:
                print(line, end="", flush=True)
        if process.wait():
            raise RuntimeError(f"similar load failed ({process.returncode})")


def main():
    execute(arguments(ROLES, SERVICES))


@exclusive_laboratory
def execute(args):
    global ROLES, WORKERS
    WORKERS = getattr(args, "workers", 2)
    ROLES = {**ALL_ROLES, **ROLES}
    ROLES["verified"] = (args.control_image, ROLES["verified"][1])
    ROLES["current"] = (args.current_image, ROLES["current"][1])
    ROLES["hickory"] = (
        getattr(args, "hickory_image", ROLES["hickory"][0]),
        ROLES["hickory"][1],
    )
    selected = getattr(args, "roles", ["verified", "current", "bind", "knot", "nsd"])
    ROLES = {role: ROLES[role] for role in selected}
    server_names = [
        {"current": "donna-current", "verified": "donna-verified"}.get(role, role)
        for role in ROLES
    ]
    cleanup()
    if args.cleanup:
        return
    suite = SUITE
    harness = [
        "labs/authority/similar.py",
        "labs/authority/similar_fixture.py",
        "labs/authority/similar_cli.py",
        "support/server_cpu.py",
        "python/similar_load.py",
        "python/cache_load.py",
        "python/batched_load.c",
        "python/batched_load_test.py",
        "python/similar_load_test.py",
        "python/signed_probe.py",
        "python/authority_replay.py",
    ]
    try:
        print(
            json.dumps(metadata(args, ROLES, WORKERS, suite, harness, docker)),
            flush=True,
        )
        docker("network", "create", "--subnet", "172.29.54.0/24", NETWORK, capture=True)
        for volume in (VOLUME, CERTS):
            docker("volume", "create", volume, capture=True)
        docker(
            "run",
            "--rm",
            "-v",
            CERTS + ":/certs",
            "donna-interop-peers",
            "python",
            "certificates.py",
            capture=True,
        )
        docker(
            "run",
            "-d",
            "--name",
            PREFIX + "signer",
            "--network",
            "none",
            "-v",
            VOLUME + ":/work",
            "donna-interop-bind",
            "sleep",
            "infinity",
            capture=True,
        )
        with tempfile.TemporaryDirectory(
            prefix="donna-comparison-fixtures-"
        ) as temporary:
            directory = Path(temporary)
            prepare_fixtures(
                directory,
                args,
                suite=suite,
                prefix=PREFIX,
                network=NETWORK,
                volume=VOLUME,
                workers=WORKERS,
                put=put,
                docker=docker,
            )
            if args.upstream_semantics:
                for name in ("upstream_authority.py", "authority_expectations.py"):
                    docker(
                        "cp",
                        str(suite / "python" / name),
                        PREFIX + "probe:/suite/" + name,
                    )
                start("unsigned")
                print(
                    json.dumps(
                        {
                            "fixture_sha256": docker(
                                "exec",
                                PREFIX + "signer",
                                "sha256sum",
                                "/work/active.db",
                                capture=True,
                            ),
                            "mode": "upstream-semantics",
                        }
                    ),
                    flush=True,
                )
                failures = []
                for role, (_, address) in ROLES.items():
                    port = 5300 if role in ("verified", "current") else 53
                    result = subprocess.run(
                        [
                            "docker",
                            "exec",
                            PREFIX + "probe",
                            "python",
                            "/suite/upstream_authority.py",
                            "--server",
                            f"{role}={address}:{port}",
                        ],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                    )
                    print(result.stdout, end="", flush=True)
                    if result.returncode:
                        failures.append(role)
                if failures:
                    raise RuntimeError(
                        "upstream semantic checks failed: " + ", ".join(failures)
                    )
                return
            # Current wrapper and executable integrity gates precede every suite.
            docker(
                "cp",
                str(suite / "python/cache_load.py"),
                PREFIX + "client:/suite/cache_load.py",
            )
            docker(
                "cp",
                str(suite / "python/similar_load_test.py"),
                PREFIX + "client:/suite/similar_load_test.py",
            )
            print(
                docker(
                    "exec",
                    PREFIX + "client",
                    "python",
                    "/suite/similar_load_test.py",
                    capture=True,
                ),
                flush=True,
            )
            print(
                docker(
                    "exec",
                    PREFIX + "client",
                    "python",
                    "/suite/batched_load_test.py",
                    capture=True,
                ),
                flush=True,
            )
            for mode in args.modes:
                start(mode)
                public_zone = subprocess.run(
                    ["docker", "exec", PREFIX + "signer", "cat", "/work/active.db"],
                    check=True,
                    stdout=subprocess.PIPE,
                ).stdout
                print(
                    json.dumps(
                        {
                            "public_fixture": {
                                "mode": mode,
                                "sha256": hashlib.sha256(public_zone).hexdigest(),
                                "zone_text": public_zone.decode("utf-8"),
                            }
                        }
                    ),
                    flush=True,
                )
                print(
                    json.dumps(
                        {
                            "fixture_sha256": docker(
                                "exec",
                                PREFIX + "signer",
                                "sha256sum",
                                "/work/active.db",
                                capture=True,
                            ),
                            "mode": mode,
                        }
                    ),
                    flush=True,
                )
                logs = quiet_logs(mode=mode, checkpoint="before")
                output_rows(
                    docker(
                        "exec",
                        PREFIX + "probe",
                        "python",
                        "/suite/similar_load.py",
                        "--mode",
                        mode,
                        "--servers",
                        *server_names,
                        "--verify",
                        *(["--cases", *args.cases] if args.cases else []),
                        capture=True,
                    ),
                    mode,
                    "before",
                )
                quiet_logs(logs, mode=mode, checkpoint="after-preflight")
                if args.verify_only:
                    continue
                command = [
                    "python",
                    "/suite/similar_load.py",
                    "--mode",
                    mode,
                    "--load-client",
                    args.load_client,
                    "--repeats",
                    str(args.repeats),
                    "--seconds",
                    str(args.seconds),
                    "--servers",
                    *server_names,
                ]
                if args.cases:
                    command += ["--cases", *args.cases]
                if getattr(args, "server_cpu", False):
                    command += ["--cpu-handshake"]
                if getattr(args, "verify_wire", False):
                    command += ["--verify-wire"]
                stream_rows(command, mode, "timing", getattr(args, "server_cpu", False))
                quiet_logs(logs, mode=mode, checkpoint="after-timing")
                output_rows(
                    docker(
                        "exec",
                        PREFIX + "probe",
                        "python",
                        "/suite/similar_load.py",
                        "--mode",
                        mode,
                        "--servers",
                        *server_names,
                        "--verify",
                        *(["--cases", *args.cases] if args.cases else []),
                        capture=True,
                    ),
                    mode,
                    "after",
                )
                quiet_logs(logs, mode=mode, checkpoint="after")
            print(
                json.dumps(
                    {
                        "comparison_complete": {
                            "modes": args.modes,
                            "roles": list(ROLES),
                            "cases": args.cases,
                            "repeats": args.repeats,
                            "verify_wire": getattr(args, "verify_wire", False),
                            "verify_only": args.verify_only,
                        }
                    }
                ),
                flush=True,
            )
    except Exception:
        for service in SERVICES:
            print(
                docker(
                    "logs", "--tail", "15", PREFIX + service, check=False, capture=True
                ),
                flush=True,
            )
        raise
    finally:
        if not args.keep:
            cleanup()


if __name__ == "__main__":
    main()
