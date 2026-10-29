#!/usr/bin/env python3
"""Frozen Docker-only Hickory TC regression, strict baseline versus candidate."""

import argparse
import gzip
import hashlib
import json
from support.paths import ROOT
from pathlib import Path
import subprocess
import tempfile

from support.lock import laboratory_lock


def digest(data):
    return hashlib.sha256(data).hexdigest()


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    if check and result.returncode:
        raise RuntimeError(result.stdout[-4000:])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builder", default="donna-prefix-control-builder:local")
    parser.add_argument("--peer", default="donna-interop-hickory:0.26.3")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("examples/interop/.artifacts/truncated-client.json"),
    )
    args = parser.parse_args()
    root = ROOT
    paths = [
        "crates/dns/src/wire/message/mod.rs",
        "crates/transport/src/udp/mod.rs",
        "crates/transport/examples/truncated_fallback.rs",
        "crates/transport/src/udp/tests/truncated_client.rs",
        "crates/transport/src/udp/tests/mod.rs",
        "crates/transport/src/udp/tests/fixtures/hickory-0.26.3-many-a-tc.bin",
        "crates/transport/src/tcp/tests/server_limits.rs",
        "examples/interop/tests/truncated_resolver.rs",
    ]
    frozen = {path: root.joinpath(path).read_bytes() for path in paths}
    udp_path = "crates/transport/src/udp/mod.rs"
    candidate = frozen[udp_path].decode()
    start = candidate.index(
        "        // RFC 2181 section 9: a correlated TC reply requests TCP even when"
    )
    end = candidate.index("        let Ok(reply) = Message::from_wire", start)
    baseline = (candidate[:start] + candidate[end:]).encode()
    identities = {
        name: json.loads(docker("image", "inspect", image).stdout)[0]["Id"]
        for name, image in (("builder", args.builder), ("peer", args.peer))
    }
    record = {
        "scope": "Docker-only actual classic UDP TC to TCP96A; no throughput claim",
        "images": identities,
        "source_sha256": {p: digest(b) for p, b in frozen.items()},
        "harness_sha256": digest(Path(__file__).read_bytes()),
        "baseline": "Same frozen source; only UDP TC-prefix branch removed. New codec API remains unused.",
        "runs": [],
    }
    prefix = "donna-tc-frozen-"
    client, peer, network = (prefix + part for part in ("client", "peer", "network"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    artifact_dir = args.output.parent / "binaries"
    artifact_dir.mkdir(exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="donna-tc-frozen-") as temporary,
        laboratory_lock(),
    ):
        directory = Path(temporary)
        try:
            docker("network", "create", "--subnet", "172.29.56.0/24", network)
            docker(
                "run",
                "-d",
                "--name",
                peer,
                "--network",
                network,
                "--ip",
                "172.29.56.50",
                "-e",
                "RUST_LOG=error",
                identities["peer"],
            )
            docker(
                "run",
                "-d",
                "--name",
                client,
                "--network",
                network,
                "--entrypoint",
                "sleep",
                identities["builder"],
                "infinity",
            )
            manifest = directory / "Cargo.toml"
            docker("cp", client + ":/source/examples/interop/Cargo.toml", str(manifest))
            manifest.write_text(
                manifest.read_text().replace(
                    "[package]\n", "[package]\nautobins = false\n", 1
                )
                + '\n[[bin]]\nname = "tc_fallback"\n'
                'path = "../../crates/transport/examples/truncated_fallback.rs"\n'
            )
            docker("cp", str(manifest), client + ":/source/examples/interop/Cargo.toml")
            record["interop_manifest_sha256"] = digest(manifest.read_bytes())
            for path, data in frozen.items():
                local = directory / path
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(data)
                docker("exec", client, "mkdir", "-p", str(Path("/source", path).parent))
                docker("cp", str(local), client + ":/source/" + path)
            for role, data in (("baseline", baseline), ("candidate", frozen[udp_path])):
                local = directory / (role + "-udp.rs")
                local.write_bytes(data)
                docker("cp", str(local), client + ":/source/" + udp_path)
                build = docker(
                    "exec",
                    client,
                    "cargo",
                    "build",
                    "--offline",
                    "--locked",
                    "--release",
                    "--manifest-path",
                    "examples/interop/Cargo.toml",
                    "--bin",
                    "tc_fallback",
                    check=False,
                )
                assert build.returncode == 0, build.stdout[-4000:]
                binary = directory / (role + "-client")
                target = "/source/examples/interop/target/release/tc_fallback"
                docker("cp", client + ":" + target, str(binary))
                result = docker("exec", client, target, "172.29.56.50:53", check=False)
                resolver_test = docker(
                    "exec",
                    client,
                    "cargo",
                    "test",
                    "--offline",
                    "--locked",
                    "--release",
                    "--manifest-path",
                    "examples/interop/Cargo.toml",
                    "--test",
                    "truncated_resolver",
                    "--",
                    "--nocapture",
                    check=False,
                )
                retained = artifact_dir / ("truncated-client-" + role + ".gz")
                retained.write_bytes(gzip.compress(binary.read_bytes(), mtime=0))
                record["runs"].append(
                    {
                        "role": role,
                        "exit_code": result.returncode,
                        "output": result.stdout,
                        "build_output": build.stdout,
                        "automatic_resolver_test": {
                            "exit_code": resolver_test.returncode,
                            "output": resolver_test.stdout,
                        },
                        "udp_source_sha256": digest(data),
                        "binary_sha256": digest(binary.read_bytes()),
                        "binary_gzip": str(retained),
                        "binary_gzip_sha256": digest(retained.read_bytes()),
                    }
                )
            record["peer_logs"] = docker("logs", peer, check=False).stdout
            docker("exec", client, "mkdir", "-p", "/source/audit")
            docker(
                "cp",
                str(directory / "baseline-udp.rs"),
                client + ":/source/audit/baseline-udp.rs",
            )
            docker(
                "exec",
                client,
                "tar",
                "--exclude=target",
                "--exclude=.git",
                "-czf",
                "/tmp/tc-source.tar.gz",
                "-C",
                "/source",
                "Cargo.toml",
                "Cargo.lock",
                "crates",
                "vendor",
                "src",
                "audit",
                "examples/interop/Cargo.toml",
                "examples/interop/Cargo.lock",
                "examples/interop/src",
                "examples/interop/tests",
            )
            source_archive = artifact_dir / "truncated-client-source.tar.gz"
            docker("cp", client + ":/tmp/tc-source.tar.gz", str(source_archive))
            record["source_archive"] = str(source_archive)
            record["source_archive_sha256"] = digest(source_archive.read_bytes())
            assert (
                record["runs"][0]["exit_code"] != 0
                and "Timeout" in record["runs"][0]["output"]
            )
            assert record["runs"][1]["exit_code"] == 0
            assert record["runs"][0]["automatic_resolver_test"]["exit_code"] != 0
            assert (
                "test result: FAILED. 0 passed; 1 failed"
                in record["runs"][0]["automatic_resolver_test"]["output"]
            )
            assert (
                "NoReachableServer"
                in record["runs"][0]["automatic_resolver_test"]["output"]
            )
            assert record["runs"][1]["automatic_resolver_test"]["exit_code"] == 0
            assert (
                "test result: ok. 1 passed"
                in record["runs"][1]["automatic_resolver_test"]["output"]
            )
        finally:
            docker("rm", "-f", client, peer, check=False)
            docker("network", "rm", network, check=False)
            record["cleanup"] = (
                "Task containers, network and host temporary directory removed; inherited images retained."
            )
            args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(
        json.dumps(
            {
                "runs": [
                    {
                        k: v
                        for k, v in run.items()
                        if k in ("role", "exit_code", "output")
                    }
                    for run in record["runs"]
                ],
                "automatic_resolver": [
                    run["automatic_resolver_test"]["exit_code"]
                    for run in record["runs"]
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
