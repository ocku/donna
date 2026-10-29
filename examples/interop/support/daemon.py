"""Configure the shipped recursive daemon in isolated Docker laboratories."""

import json
import tempfile
from pathlib import Path

from .docker import docker

RECURSIVE_PORT = 5301
LAB_EXCHANGE_TIMEOUT_SECS = 2
CONFIG_PATH = "/tmp/donna-lab.toml"
DAEMON_BINARY = "/usr/local/bin/donna"
CLI_IMAGE = "donna-interop-donna"
DNS_PORT = 53


def resolver_port(role):
    return RECURSIVE_PORT if role == "donna" else DNS_PORT


def require_cli(image):
    try:
        version = docker(
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            DAEMON_BINARY,
            image,
            "--version",
            capture=True,
        )
        if not version.startswith("donna "):
            raise RuntimeError(f"unexpected CLI version: {version!r}")
    except RuntimeError as error:
        raise RuntimeError(
            f"{image} must contain the shipped Donna CLI; build "
            "examples/interop/docker/Donna.Dockerfile or select a compatible --donna-image"
        ) from error


def record_runtime_identity(record, role, container):
    if role == "donna" and "donna_binary_sha256" not in record:
        record["donna_binary_sha256"] = docker(
            "exec", container, "sha256sum", DAEMON_BINARY, capture=True
        ).split()[0]


def recursive_config(address, root, subnet, *, anchors=None, cache_capacity=None):
    quote = json.dumps
    lines = ['role = "recursive"']

    for protocol in ("udp", "tcp"):
        lines += [
            "",
            "[[listen]]",
            f"protocol = {quote(protocol)}",
            f"address = {quote(f'{address}:{RECURSIVE_PORT}')}",
        ]

    lines += [
        "",
        "[access]",
        f"recursion = [{quote(subnet)}]",
        "",
        "[resolver]",
        f"root_servers = [{quote(root)}]",
        f"timeout_secs = {LAB_EXCHANGE_TIMEOUT_SECS}",
        f"validate = {'true' if anchors else 'false'}",
    ]
    if anchors:
        lines.append(f"trust_anchors = {quote(anchors)}")
    if cache_capacity is not None:
        lines.append(f"cache_capacity = {cache_capacity}")

    return "\n".join(lines) + "\n"


def create_recursive(
    name,
    image,
    network,
    address,
    root,
    subnet,
    *,
    anchors=None,
    cache_capacity=None,
    options=(),
    workers=2,
    start=True,
    run=None,
):
    """Create/copy/start rather than bind-mounting a host-only temporary path."""
    if run is None:

        def run(*args):
            return docker(*args, capture=True)

    configuration = recursive_config(
        address, root, subnet, anchors=anchors, cache_capacity=cache_capacity
    )
    run(
        "create",
        "--name",
        name,
        "--network",
        network,
        "--ip",
        address,
        "-e",
        f"TOKIO_WORKER_THREADS={workers}",
        *options,
        image,
        DAEMON_BINARY,
        "serve",
        "-c",
        CONFIG_PATH,
    )
    with tempfile.TemporaryDirectory(prefix="donna-cli-") as directory:
        path = Path(directory) / "donna.toml"
        path.write_text(configuration)
        run("cp", str(path), name + ":" + CONFIG_PATH)
    if start:
        run("start", name)
