"""Independent signed hierarchy fixtures shared by recursive DNS labs."""

import hashlib
import json

from support.topology import PREFIX, docker

SIGNER = PREFIX + "chain-signer"
VOLUME = PREFIX + "chain-fixtures"
ORIGINS = {"root": ".", "tld": "test.", "leaf": "example.test."}


def put(directory, filename, text):
    path = directory / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    docker("cp", str(path), SIGNER + ":/work/" + filename)


def sign(zone, mode, filename="signed.db"):
    command = [
        "exec",
        "-w",
        "/work/" + zone,
        SIGNER,
        "dnssec-signzone",
        "-q",
        "-S",
        "-n",
        "1",
        "-s",
        "now-3600",
        "-e",
        "now+86400",
        "-N",
        "keep",
        "-o",
        ORIGINS[zone],
        "-f",
        filename,
    ]
    if mode == "nsec3":
        command += ["-3", "A1B2"]  # Fully signed chain, without Opt-Out.
    docker(*command, "zone.db", capture=True)


def prepare(directory, population, mode):
    docker("volume", "create", VOLUME, capture=True)
    docker(
        "run",
        "-d",
        "--name",
        SIGNER,
        "--network",
        "none",
        "-v",
        VOLUME + ":/work",
        PREFIX + "bind",
        "sleep",
        "infinity",
        capture=True,
    )
    docker("exec", SIGNER, "mkdir", "-p", "/work/root", "/work/tld", "/work/leaf")
    keys = {}
    for zone, origin in ORIGINS.items():
        for flag in ("KSK", "ZSK"):
            command = [
                "exec",
                "-w",
                "/work/" + zone,
                SIGNER,
                "dnssec-keygen",
                "-q",
                "-a",
                "ECDSAP256SHA256",
            ]
            if flag == "KSK":
                command += ["-f", "KSK"]
            key = docker(*command, origin, capture=True)
            if flag == "KSK":
                keys[zone] = key
    ds = {
        zone: docker(
            "exec",
            "-w",
            "/work/" + zone,
            SIGNER,
            "dnssec-dsfromkey",
            "-2",
            keys[zone] + ".key",
            capture=True,
        )
        + "\n"
        for zone in ("tld", "leaf")
    }
    root = (
        "$ORIGIN .\n$TTL 300\n@ IN SOA root. hostmaster.root. 1 60 60 3600 30\n"
        "@ IN NS root.\nroot. IN A 172.29.53.70\ntest. IN NS ns.test.\n"
        "ns.test. IN A 172.29.53.71\n"
    ) + ds["tld"]
    tld = (
        "$ORIGIN test.\n$TTL 300\n@ IN SOA ns.test. hostmaster.test. 1 60 60 3600 30\n"
        "@ IN NS ns.test.\nns IN A 172.29.53.71\nexample IN NS ns.example.test.\n"
        "ns.example IN A 172.29.53.72\n"
    ) + ds["leaf"]
    leaf = (
        "$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 3600 30\n"
        "@ IN NS ns.example.test.\nns IN A 172.29.53.72\nwww IN A 192.0.2.80\n"
    )
    for index in range(population):
        leaf += (
            f"host-{index:04d} IN A 192.0.2.80\n"
            f'n-{index:04d}-a IN TXT "lower boundary"\n'
            f'n-{index:04d}-c IN TXT "upper boundary"\n'
        )
    for zone, text in (("root", root), ("tld", tld), ("leaf", leaf)):
        put(directory, zone + "/zone.db", text)
        sign(zone, mode)
        docker(
            "exec", SIGNER, "cp", f"/work/{zone}/signed.db", f"/work/{zone}/active.db"
        )
        config = (
            'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
            "recursion no; dnssec-validation no; querylog yes; };\n"
            f'zone "{ORIGINS[zone]}" {{ type primary; file "/work/{zone}/active.db"; }};\n'
        )
        put(directory, zone + ".conf", config)

    # Sign an incorrect child DS with the genuine TLD key. Root and TLD
    # signatures remain valid, but the chain cannot authenticate the leaf key.
    fields = ds["leaf"].split()
    offset = fields.index("DS") + 1
    fields[offset] = str(int(fields[offset]) ^ 1)
    put(directory, "tld/zone.db", tld.replace(ds["leaf"], " ".join(fields) + "\n"))
    sign("tld", mode, "bad-ds.db")
    put(directory, "tld/zone.db", tld)
    docker("cp", SIGNER + ":/work/root/signed.db", str(directory / "public-root.zone"))
    docker(
        "cp",
        str(directory / "public-root.zone"),
        PREFIX + "probe:/suite/chain-root.zone",
    )
    root_keys = json.loads(
        docker(
            "exec",
            PREFIX + "probe",
            "python",
            "-c",
            "import dns.zone,dns.rdatatype,json; "
            "z=dns.zone.from_file('/suite/chain-root.zone',origin='.',relativize=False); "
            "print(json.dumps([k.to_text() for k in z.get_rdataset('.',dns.rdatatype.DNSKEY) if k.flags==257]))",
            capture=True,
        )
    )
    if not root_keys:
        raise RuntimeError("missing independent root KSK")
    put(
        directory,
        "anchors.zone",
        "".join(". 300 IN DNSKEY " + key + "\n" for key in root_keys),
    )
    anchors = ""
    for key in root_keys:
        flags, protocol, algorithm, *parts = key.split()
        anchors += (
            f'"." static-key {flags} {protocol} {algorithm} "{"".join(parts)}";\n'
        )
    put(directory, "root.hints", ". 300 IN NS root.\nroot. 300 IN A 172.29.53.70\n")
    put(
        directory,
        "recursive.conf",
        'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
        "recursion yes; allow-recursion { 172.29.53.0/24; }; dnssec-validation yes; "
        "empty-zones-enable no; max-cache-size 64m; minimal-responses yes; };\n"
        "trust-anchors { " + anchors + " };\n"
        'zone "." { type hint; file "/work/root.hints"; };\n',
    )
    docker("exec", SIGNER, "named-checkconf", "/work/recursive.conf")
    print(
        json.dumps(
            {
                "fixture": "root/test/example.test DNSSEC chain",
                "mode": mode,
                "root_ksk": root_keys,
                "child_ds": ds,
                "public_root_sha256": hashlib.sha256(
                    (directory / "public-root.zone").read_bytes()
                ).hexdigest(),
            }
        ),
        flush=True,
    )
