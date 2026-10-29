"""Run shipped Donna client commands and verify the full lab's positive fixture."""

import json

from .docker import docker

QUERY_NAME = "www.example.test."
EXPECTED_IPV4 = "192.0.2.80"


def query_command(protocol, address, *, provider_key=None):
    cli_protocol = {"doh-get": "https", "doh-post": "https", "doq": "quic"}.get(
        protocol, protocol
    )
    command = [
        "donna",
        "query",
        QUERY_NAME,
        "A",
        "--protocol",
        cli_protocol,
        "--server",
        address,
        "--json",
        "--attempts",
        "1",
    ]

    if cli_protocol in ("tls", "https", "quic"):
        command += ["--tls-name", "localhost", "--ca", "/certs/cert.pem"]
    if protocol == "doh-get":
        command.append("--https-get")
    if cli_protocol.startswith("dnscrypt-"):
        if not provider_key:
            raise ValueError(
                "DNSCrypt queries require the laboratory provider public key"
            )
        command += [
            "--provider-name",
            "2.dnscrypt-cert.example.test.",
            "--provider-key",
            provider_key,
        ]

    return command


def check_response(output):
    response = json.loads(output)
    expected_question = {"name": QUERY_NAME, "type": "A", "class_code": 1}

    if response.get("status") != "Ok" or response.get("questions") != [
        expected_question
    ]:
        raise RuntimeError(f"Donna CLI returned an unexpected response: {output}")

    answers = response.get("answers", [])
    if len(answers) != 1 or any(
        answers[0].get(field) != expected
        for field, expected in (
            ("name", QUERY_NAME),
            ("type", "A"),
            ("class", "IN"),
            ("data", EXPECTED_IPV4),
        )
    ):
        raise RuntimeError(f"Donna CLI returned an unexpected A answer: {output}")

    return response


def query_fixture(container, protocol, address, *, provider_key=None):
    command = query_command(protocol, address, provider_key=provider_key)
    check_response(docker("exec", container, *command, capture=True))
    print(f"PASS Donna CLI {protocol} query against {address}", flush=True)


def resolve_fixture(container, root):
    command = [
        "donna",
        "resolve",
        QUERY_NAME,
        "A",
        "--root",
        root,
        "--no-validate",
        "--json",
    ]
    check_response(docker("exec", container, *command, capture=True))
    print(f"PASS Donna CLI iterative resolution from {root}", flush=True)
