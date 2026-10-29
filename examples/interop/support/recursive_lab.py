"""Small resource-bounded signed recursive hierarchy; signing keys stay private."""

import json
import subprocess
from pathlib import Path

from support.daemon import create_recursive, resolver_port
from support.docker import docker
from support.recursive_peers import start_peer

PREFIX = "donna-recursive-peers-"
NETWORK = PREFIX + "network"
PRIVATE = PREFIX + "private"
PUBLIC = PREFIX + "public"
SIGNER = PREFIX + "signer"
CARRIER = PREFIX + "public-files"
CLIENT = PREFIX + "client"
ORIGINS = {"root": ".", "tld": "test.", "leaf": "example.test."}
ADDRESSES = {
    "donna": "172.29.53.74",
    "knot-resolver": "172.29.53.75",
    "hickory": "172.29.53.76",
}


def identity(image):
    return json.loads(docker("image", "inspect", image, capture=True))[0]["Id"]


def stats(container):
    text = docker("exec", container, "cat", "/sys/fs/cgroup/cpu.stat", capture=True)
    return {
        key: int(value) for key, value in (line.split() for line in text.splitlines())
    }


def delta(before, after):
    assert before.keys() == after.keys()
    result = {key: after[key] - before[key] for key in before}
    assert all(value >= 0 for value in result.values())
    return result


class Lab:
    def __init__(
        self,
        directory,
        client_image,
        donna_image,
        peers,
        cache_capacity=None,
        denial="nsec",
        negative_ttl=30,
        client_memory="256m",
    ):
        self.directory = Path(directory)
        self.client_image, self.donna_image, self.peers = (
            client_image,
            donna_image,
            peers,
        )
        self.role = None
        self.cache_capacity = cache_capacity
        assert denial in ("nsec", "nsec3") and 1 <= negative_ttl <= 300
        self.denial, self.negative_ttl = denial, negative_ttl
        self.client_memory = client_memory
        assert client_memory in ("256m", "512m")
        self.commands = []

    def run(self, *args):
        self.commands.append(list(args))
        return docker(*args, capture=True)

    def put(self, filename, text, public=False):
        path = self.directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.run(
            "cp", str(path), (CARRIER if public else SIGNER) + ":/work/" + filename
        )

    def sign(self, zone, filename="signed.db"):
        proof = ["-3", "ABCD", "-H", "0"] if self.denial == "nsec3" else []
        return self.run(
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
            *proof,
            "-f",
            filename,
            "zone.db",
        )

    def prepare(self, leaf_additions, reused=None):
        bind = self.peers["authority"]
        assert (
            NETWORK
            not in self.run("network", "ls", "--format", "{{.Name}}").splitlines()
        )
        self.run("network", "create", "--subnet", "172.29.53.0/24", NETWORK)
        for volume in (PRIVATE, PUBLIC):
            self.run("volume", "create", volume)
        self.run(
            "run",
            "-d",
            "--name",
            SIGNER,
            "--network",
            "none",
            "--cpus",
            ".5",
            "--memory",
            "256m",
            "-v",
            PRIVATE + ":/work",
            bind,
            "sleep",
            "infinity",
        )
        self.run(
            "run",
            "-d",
            "--name",
            CARRIER,
            "--network",
            "none",
            "--cpus",
            ".02",
            "--memory",
            "64m",
            "-v",
            PUBLIC + ":/work",
            bind,
            "sleep",
            "infinity",
        )
        self.run(
            "run",
            "-d",
            "--name",
            CLIENT,
            "--network",
            NETWORK,
            "--cpus",
            ".5",
            "--memory",
            self.client_memory,
            "-v",
            PUBLIC + ":/work:ro",
            "--entrypoint",
            "sleep",
            self.client_image,
            "infinity",
        )
        self.run("exec", SIGNER, "mkdir", "-p", "/work/root", "/work/tld", "/work/leaf")
        self.run(
            "exec", CARRIER, "mkdir", "-p", "/work/root", "/work/tld", "/work/leaf"
        )
        if reused is not None:
            return self.publish(reused)
        keys = {}
        for zone, origin in ORIGINS.items():
            for flag in ("KSK", "ZSK"):
                args = [
                    "exec",
                    "-w",
                    "/work/" + zone,
                    SIGNER,
                    "dnssec-keygen",
                    "-q",
                    "-a",
                    "ECDSAP256SHA256",
                    "-P",
                    "now-7200",
                    "-A",
                    "now-7200",
                ]
                if flag == "KSK":
                    args += ["-f", "KSK"]
                key = self.run(*args, origin)
                if flag == "KSK":
                    keys[zone] = key
        ds = {
            zone: self.run(
                "exec",
                "-w",
                "/work/" + zone,
                SIGNER,
                "dnssec-dsfromkey",
                "-2",
                keys[zone] + ".key",
            )
            + "\n"
            for zone in ("tld", "leaf")
        }
        zones = {
            "root": "$ORIGIN .\n$TTL 300\n@ IN SOA root. hostmaster.root. 1 60 60 3600 30\n@ IN NS root.\nroot. IN A 172.29.53.70\ntest. IN NS ns.test.\nns.test. IN A 172.29.53.71\n"
            + ds["tld"],
            "tld": "$ORIGIN test.\n$TTL 300\n@ IN SOA ns.test. hostmaster.test. 1 60 60 3600 30\n@ IN NS ns.test.\nns IN A 172.29.53.71\nexample IN NS ns.example.test.\nns.example IN A 172.29.53.72\n"
            + ds["leaf"],
            "leaf": f"$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 3600 {self.negative_ttl}\n@ IN NS ns.example.test.\nns IN A 172.29.53.72\nwww IN A 192.0.2.80\n"
            + leaf_additions,
        }
        verification = {}
        for zone, text in zones.items():
            self.put(zone + "/zone.db", text)
            self.sign(zone)
            verification[zone] = self.run(
                "exec",
                "-w",
                "/work/" + zone,
                SIGNER,
                "dnssec-verify",
                "-o",
                ORIGINS[zone],
                "signed.db",
            )
        fields = ds["leaf"].split()
        fields[fields.index("DS") + 1] = str(int(fields[fields.index("DS") + 1]) ^ 1)
        self.put(
            "tld/zone.db", zones["tld"].replace(ds["leaf"], " ".join(fields) + "\n")
        )
        self.sign("tld", "bad-ds.db")
        public = dict(
            zones={},
            origins=ORIGINS,
            signing_verification=verification,
            denial=self.denial,
            signing_policy="Key publication/activation7200s before signing; RRSIG inception3600s before current time, lifetime86400s",
        )
        for zone in ORIGINS:
            public["zones"][zone] = (
                self.run("exec", SIGNER, "cat", f"/work/{zone}/signed.db") + "\n"
            )
        public["bad_tld"] = (
            self.run("exec", SIGNER, "cat", "/work/tld/bad-ds.db") + "\n"
        )
        keytext = self.run("exec", SIGNER, "cat", "/work/root/" + keys["root"] + ".key")
        keyfields = (
            " ".join(line for line in keytext.splitlines() if not line.startswith(";"))
            .replace("(", "")
            .replace(")", "")
            .split()
        )
        public["anchors"] = (
            ". 300 IN DNSKEY "
            + " ".join(keyfields[keyfields.index("DNSKEY") + 1 :])
            + "\n"
        )
        return self.publish(public)

    def publish(self, public):
        for zone in ORIGINS:
            text = public["zones"][zone]
            self.put(zone + "/active.db", text, public=True)
            if zone == "tld":
                self.put("tld/good.db", text, public=True)
            config = (
                'options { directory "/tmp"; listen-on { any; }; listen-on-v6 { none; }; '
                "recursion no; dnssec-validation no; minimal-responses yes; max-cache-size 4m; querylog yes; };\n"
                f'zone "{ORIGINS[zone]}" {{ type primary; file "/work/{zone}/active.db"; }};\n'
            )
            self.put(zone + ".conf", config, public=True)
        self.put("tld/bad-ds.db", public["bad_tld"], public=True)
        self.put("anchors.zone", public["anchors"], public=True)
        self.put(
            "root.hints",
            ". 300 IN NS root.\nroot. 300 IN A 172.29.53.70\n",
            public=True,
        )
        self.put("public.json", json.dumps(public), public=True)
        self.run("stop", SIGNER)
        for index, zone in enumerate(ORIGINS):
            self.run(
                "run",
                "-d",
                "--name",
                PREFIX + zone,
                "--network",
                NETWORK,
                "--ip",
                f"172.29.53.{70 + index}",
                "--cpus",
                ".15",
                "--memory",
                "128m",
                "-e",
                "TZ=UTC",
                "-v",
                PUBLIC + ":/work:ro",
                self.peers["authority"],
                "named",
                "-g",
                "-n",
                "1",
                "-c",
                "/work/" + zone + ".conf",
                "-u",
                "root",
            )
        ready = "import socket,time; end=time.monotonic()+20\nwhile True:\n try:\n  [socket.create_connection(('172.29.53.'+str(i),53),.2).close() for i in (70,71,72)];break\n except OSError:\n  if time.monotonic()>end:raise\n  time.sleep(.1)\n"
        self.run("exec", CLIENT, "python", "-c", ready)
        return public

    def set_bad_ds(self, bad):
        self.run(
            "exec",
            CARRIER,
            "cp",
            "/work/tld/" + ("bad-ds.db" if bad else "good.db"),
            "/work/tld/active.db",
        )
        self.run("restart", PREFIX + "tld")

    def start(self, role):
        self.stop()
        name, address = PREFIX + role, ADDRESSES[role]
        self.role = role  # Cleanup also owns a container whose readiness fails.
        if role == "donna":
            create_recursive(
                name,
                self.donna_image,
                NETWORK,
                address,
                "172.29.53.70:53",
                "172.29.53.0/24",
                anchors="/work/anchors.zone",
                cache_capacity=self.cache_capacity,
                workers=1,
                run=self.run,
                options=(
                    "--cpus",
                    "1",
                    "--memory",
                    "256m",
                    "-v",
                    PUBLIC + ":/work:ro",
                    "-e",
                    "RUST_LOG=error",
                ),
            )
        else:
            start_peer(
                role,
                name,
                NETWORK,
                PUBLIC,
                address,
                self.directory / role,
                image=self.peers[role],
                workers=1,
            )
        port = resolver_port(role)
        program = "import socket,sys,time; end=time.monotonic()+20\nwhile True:\n try:\n  socket.create_connection((sys.argv[1],int(sys.argv[2])),.2).close();break\n except OSError:\n  if time.monotonic()>end: raise\n  time.sleep(.1)\n"
        self.run("exec", CLIENT, "python", "-c", program, address, str(port))
        return address, port

    def stop(self):
        if self.role:
            docker("rm", "-fv", PREFIX + self.role, check=False, capture=True)
            self.role = None

    def authority_logs(self):
        return {
            zone: subprocess.check_output(
                ["docker", "logs", PREFIX + zone], stderr=subprocess.STDOUT
            ).decode()
            for zone in ORIGINS
        }

    def snapshots(self):
        return {name: stats(PREFIX + name) for name in [*ORIGINS, self.role]} | {
            "client": stats(CLIENT)
        }

    def cleanup(self):
        self.stop()
        docker(
            "rm",
            "-fv",
            CLIENT,
            SIGNER,
            CARRIER,
            *(PREFIX + zone for zone in ORIGINS),
            check=False,
            capture=True,
        )
        docker("network", "rm", NETWORK, check=False, capture=True)
        docker("volume", "rm", PRIVATE, PUBLIC, check=False, capture=True)
