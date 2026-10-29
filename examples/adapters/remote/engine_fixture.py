"""Generate a small public signed hierarchy; private signing keys stay in Docker."""

from pathlib import Path

ORIGINS = {"root": ".", "tld": "test.", "leaf": "example.test."}


def prepare(run, name, bind_image, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    signer = name + "-signer"
    volume = name + "-signing-keys"
    run("volume", "create", volume)
    try:
        run(
            "run",
            "-d",
            "--name",
            signer,
            "--network",
            "none",
            "--cpus",
            ".5",
            "--memory",
            "256m",
            "-v",
            volume + ":/work",
            bind_image,
            "sleep",
            "infinity",
        )
        keys = {}
        for role, origin in ORIGINS.items():
            run("exec", signer, "mkdir", "-p", "/work/" + role)
            keys[role] = {}
            for kind in ("KSK", "ZSK"):
                args = [
                    "exec",
                    "-w",
                    "/work/" + role,
                    signer,
                    "dnssec-keygen",
                    "-q",
                    "-a",
                    "ECDSAP256SHA256",
                    "-P",
                    "now-7200",
                    "-A",
                    "now-7200",
                ]
                if kind == "KSK":
                    args += ["-f", "KSK"]
                keys[role][kind] = run(*args, origin).strip()
        ds = {
            role: run(
                "exec",
                "-w",
                "/work/" + role,
                signer,
                "dnssec-dsfromkey",
                "-2",
                keys[role]["KSK"] + ".key",
            ).strip()
            + "\n"
            for role in ("tld", "leaf")
        }
        zones = {
            "root": "$ORIGIN .\n$TTL 300\n@ IN SOA root. hostmaster.root. 1 60 60 3600 30\n@ IN NS root.\nroot. IN A 172.29.53.70\ntest. IN NS ns.test.\nns.test. IN A 172.29.53.71\n"
            + ds["tld"],
            "tld": "$ORIGIN test.\n$TTL 300\n@ IN SOA ns.test. hostmaster.test. 1 60 60 3600 30\n@ IN NS ns.test.\nns IN A 172.29.53.71\nexample IN NS ns.example.test.\nns.example IN A 172.29.53.72\n"
            + ds["leaf"],
            "leaf": '$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns.example.test. hostmaster.example.test. 1 60 60 3600 30\n@ IN NS ns.example.test.\nns IN A 172.29.53.72\ncoherence IN A 192.0.2.84\ncoherence IN AAAA 2001:db8::84\ncoherence IN TXT "coherence"\nold IN DNAME dest.example.test.\nprime.dest IN A 192.0.2.80\nexpire 5 IN A 192.0.2.81\n',
        }
        verification = {}

        def sign(role, text, filename):
            source = directory / (role + "-input.db")
            includes = "".join(f'$INCLUDE "{key}.key"\n' for key in keys[role].values())
            source.write_text(text + includes)
            run("cp", str(source), signer + ":/work/" + role + "/zone.db")
            # Explicit keys avoid smart-signing key-discovery/activation races.
            run(
                "exec",
                "-w",
                "/work/" + role,
                signer,
                "dnssec-signzone",
                "-q",
                "-n",
                "1",
                "-s",
                "now-3600",
                "-e",
                "now+86400",
                "-N",
                "keep",
                "-o",
                ORIGINS[role],
                "-k",
                keys[role]["KSK"],
                "-f",
                filename,
                "zone.db",
                keys[role]["ZSK"],
            )
            checked = run(
                "exec",
                "-w",
                "/work/" + role,
                signer,
                "dnssec-verify",
                "-o",
                ORIGINS[role],
                filename,
            )
            target = directory / (
                role + ".db"
                if filename == "signed.db"
                else ("bad-tld.db" if filename == "bad.db" else "restored-tld.db")
            )
            run("cp", signer + ":/work/" + role + "/" + filename, str(target))
            return checked, target.read_text()

        public = {
            "origins": ORIGINS,
            "zones": {},
            "denial": "nsec",
            "signing_policy": "Explicit ECDSAP256SHA256 KSK/ZSK; inception now-3600, expiration now+86400; original data bounds unchanged.",
        }
        for role, text in zones.items():
            verification[role], public["zones"][role] = sign(role, text, "signed.db")
        fields = ds["leaf"].split()
        index = fields.index("DS") + 1
        fields[index] = str(int(fields[index]) ^ 1)
        _, public["bad_tld"] = sign(
            "tld",
            zones["tld"]
            .replace(ds["leaf"], " ".join(fields) + "\n")
            .replace("hostmaster.test. 1 60", "hostmaster.test. 2 60"),
            "bad.db",
        )
        _, public["restored_tld"] = sign(
            "tld",
            zones["tld"].replace("hostmaster.test. 1 60", "hostmaster.test. 3 60"),
            "restored.db",
        )
        anchor = run(
            "exec", signer, "cat", "/work/root/" + keys["root"]["KSK"] + ".key"
        )
        fields = (
            " ".join(line for line in anchor.splitlines() if not line.startswith(";"))
            .replace("(", "")
            .replace(")", "")
            .split()
        )
        public["anchors"] = (
            ". 300 IN DNSKEY " + " ".join(fields[fields.index("DNSKEY") + 1 :]) + "\n"
        )
        public["signing_verification"] = verification
        (directory / "anchors.zone").write_text(public["anchors"])
        # Inputs refer only to public key filenames; applications consume signed files.
        for p in directory.glob("*-input.db"):
            p.unlink()
        return public
    finally:
        run("rm", "-fv", signer, check=False)
        run("volume", "rm", volume, check=False)
