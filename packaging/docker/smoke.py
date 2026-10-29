"""Exercise the container roles on an isolated bridge without public DNS."""

import argparse
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def docker(*args, check=True):
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-image", default="donna-client:local")
    parser.add_argument("--server-image", default="donna-recursive:local")
    args = parser.parse_args()
    prefix = "donna-container-smoke-" + uuid.uuid4().hex[:8]
    network = prefix + "-network"
    subnet = "172.30.96."
    containers = []
    volumes = []

    def query(address, name="example.test.", protocol="udp", rcode=0):
        result = docker(
            "run",
            "--rm",
            "--network",
            network,
            args.client_image,
            "query",
            name,
            "A",
            "-s",
            address + ":5353",
            "--protocol",
            protocol,
            "--json",
            "--attempts",
            "1",
            "--timeout",
            "1",
            "--deadline",
            "2",
            check=False,
        )
        expected_exit = 1 if rcode in (2, 5) else 0
        assert result.returncode == expected_exit, result.stderr
        answer = json.loads(result.stdout)
        assert answer["rcode"] == rcode, answer
        return answer

    def start(role, suffix, address, environment=None, files=None):
        name = prefix + "-" + suffix
        containers.append(name)
        command = [
            "create",
            "--name",
            name,
            "--network",
            network,
            "--ip",
            address,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "-e",
            "DONNA_ROLE=" + role,
        ]
        for key, value in (environment or {}).items():
            command += ["-e", key + "=" + value]
        if files:
            volume = prefix + "-" + suffix + "-config"
            volumes.append(volume)
            docker("volume", "create", volume)
            carrier = name + "-config"
            containers.append(carrier)
            docker(
                "create",
                "--name",
                carrier,
                "--network",
                "none",
                "--mount",
                "type=volume,src=" + volume + ",dst=/etc/donna",
                "--entrypoint",
                "sleep",
                args.client_image,
                "infinity",
            )
            with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
                folder = Path(tmp) / "donna"
                folder.mkdir(mode=0o755)
                for filename, content in files.items():
                    (folder / filename).write_text(content)
                docker("cp", str(folder) + "/.", carrier + ":/etc/donna/")
            docker("rm", carrier)
            command += [
                "--mount",
                "type=volume,src=" + volume + ",dst=/etc/donna,readonly",
            ]
        command.append(args.server_image)
        docker(*command)
        docker("start", name)
        assert docker("exec", name, "id", "-u").stdout.strip() == "10001"
        return name

    def ready(address, qname="example.test.", rcode=0):
        for _ in range(20):
            try:
                return query(address, qname, rcode=rcode)
            except (AssertionError, ValueError):
                time.sleep(0.1)
        raise RuntimeError("DNS endpoint did not become ready: " + address)

    def has_address(answer, expected):
        assert any(
            rr["type"] == "A" and rr["data"] == expected for rr in answer["answers"]
        ), answer

    def configuration(role, address):
        return (
            f'role = "{role}"\n'
            f'[[listen]]\nprotocol = "udp"\naddress = "{address}:5353"\n'
            f'[[listen]]\nprotocol = "tcp"\naddress = "{address}:5353"\n'
        )

    try:
        docker("run", "--rm", "--network", "none", args.client_image, "--help")
        docker("network", "create", "--subnet", subnet + "0/24", network)

        authority = start("authoritative", "authority", subnet + "10")
        ready(subnet + "10")
        for protocol in ("udp", "tcp"):
            answer = query(subnet + "10", protocol=protocol)
            has_address(answer, "192.0.2.80")
            assert answer["flags"]["aa"] and not answer["flags"]["ra"]

        start(
            "forward",
            "forward",
            subnet + "11",
            {
                "DONNA_UPSTREAM": subnet + "10:5353",
                "DONNA_RECURSION_CIDRS": subnet + "0/24",
            },
        )
        ready(subnet + "11")
        for protocol in ("udp", "tcp"):
            answer = query(subnet + "11", protocol=protocol)
            has_address(answer, "192.0.2.80")
            assert answer["flags"]["ra"]

        start("recursive", "denied", subnet + "12")
        ready(subnet + "12", rcode=5)

        # A private root directly owns this test name. No Internet, referrals
        # or public trust anchors are involved in this unsigned iteration test.
        root_config = configuration("authoritative", subnet + "14")
        root_config += '[[zones]]\norigin = "."\nfile = "root.zone"\n'
        root = start(
            "ignored",
            "root",
            subnet + "14",
            {
                "DONNA_CONFIG": "/etc/donna/donna.toml",
            },
            {
                "donna.toml": root_config,
                "root.zone": (
                    "$ORIGIN .\n$TTL 300\n"
                    "@ IN SOA ns. hostmaster. 1 60 60 60 30\n"
                    "@ IN NS ns.\n"
                    f"ns. IN A {subnet}14\n"
                    "private.example.test. IN A 192.0.2.99\n"
                ),
            },
        )
        ready(subnet + "14", "private.example.test.")

        recursive_config = configuration("recursive", subnet + "13")
        recursive_config += (
            f'[access]\nrecursion = ["{subnet}0/24"]\n'
            f'[resolver]\nvalidate = false\nroot_servers = ["{subnet}14:5353"]\n'
        )
        recursive = start(
            "ignored",
            "recursive",
            subnet + "13",
            {
                "DONNA_CONFIG": "/etc/donna/donna.toml",
            },
            {"donna.toml": recursive_config},
        )
        ready(subnet + "13", "private.example.test.")
        for protocol in ("udp", "tcp"):
            answer = query(subnet + "13", "private.example.test.", protocol)
            has_address(answer, "192.0.2.99")
            assert answer["flags"]["ra"] and not answer["flags"]["ad"]
        docker("stop", "--time", "5", root)
        has_address(query(subnet + "13", "private.example.test."), "192.0.2.99")
        assert (
            docker("exec", recursive, "cat", "/proc/1/comm").stdout.strip() == "donna"
        )

        for key, value in (
            ("DONNA_ROLE", "invalid"),
            ("DONNA_PORT", "invalid"),
            ("DONNA_RECURSION_CIDRS", "not-a-network"),
            ("DONNA_LISTEN_IP", "0.0.0.0"),
        ):
            result = docker(
                "run",
                "--rm",
                "--network",
                "none",
                "-e",
                "DONNA_LISTEN_IP=127.0.0.1",
                "-e",
                key + "=" + value,
                args.server_image,
                check=False,
            )
            assert result.returncode != 0, (key, result.stdout, result.stderr)

        docker("stop", "--time", "5", authority)
        state = json.loads(docker("inspect", authority).stdout)[0]["State"]
        assert state["ExitCode"] == 0, state
        print(
            "PASS: client, UDP/TCP authority, forwarding, recursion, cache reuse, ACL denial, invalid configuration, non-root/read-only runtime, SIGTERM"
        )
    except BaseException as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr)
        for name in containers:
            result = docker("logs", "--tail", "15", name, check=False)
            print(name, result.stdout, result.stderr)
        raise
    finally:
        for name in containers:
            docker("rm", "-f", name, check=False)
        for volume in volumes:
            docker("volume", "rm", volume, check=False)
        docker("network", "rm", network, check=False)


if __name__ == "__main__":
    main()
