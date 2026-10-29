#!/usr/bin/env python3
"""Clean Docker-only per-entry Redis and PostgreSQL application integration."""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from engine_build import build
from engine_fixture import prepare
from engine_evidence import save, sha

ROOT = Path(__file__).resolve().parents[3]
SUITE = ROOT / "examples/interop"
sys.path.insert(0, str(SUITE))
from support.lock import exclusive_laboratory

REDIS = "redis@sha256:b6b6e3dc0c0952737748e55d5d885272840c7e42ba41ab1d5489f693419882f5"
POSTGRES = "postgres:17-bookworm"


@exclusive_laboratory
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=SUITE / "results/remote-cache-engine.json"
    )
    parser.add_argument(
        "--public-fixture",
        type=Path,
        help="Reuse a retained signed public hierarchy; generates no signing keys",
    )
    parser.add_argument(
        "--keep-images",
        action="store_true",
        help="Retain only this lab builder/runtime for development",
    )
    args = parser.parse_args()
    name = "donna-entry-adapter-" + secrets.token_hex(4)
    record = dict(
        scope="Real per-entry Redis CacheEngine plus PostgreSQL ZoneStore. Library/API integration, not a transport or throughput benchmark.",
        runs=[],
        commands=[],
        complete=False,
    )
    redactions = []
    owned_images = []
    private_marker = "[REDACTED]"

    def run(*argv, check=True):
        result = subprocess.run(
            ["docker", *argv],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = result.stdout
        for value in redactions:
            output = output.replace(value, private_marker)
        record["commands"].append(
            dict(argv=["docker", *argv], exit_code=result.returncode, output=output)
        )
        if check:
            assert result.returncode == 0, (argv, output)
        return output

    def image(reference):
        result = subprocess.run(
            ["docker", "image", "inspect", reference], capture_output=True, text=True
        )
        if result.returncode:
            run("pull", reference)
        info = json.loads(run("image", "inspect", reference))[0]
        return dict(
            id=info["Id"],
            repo_digests=info.get("RepoDigests", []),
            architecture=info["Architecture"],
        )

    def wait_ready(redis, postgres):
        end = time.monotonic() + 30
        while True:
            r = subprocess.run(
                ["docker", "exec", redis, "redis-cli", "ping"], capture_output=True
            )
            p = subprocess.run(
                [
                    "docker",
                    "exec",
                    postgres,
                    "pg_isready",
                    "-U",
                    "donna",
                    "-d",
                    "donna",
                ],
                capture_output=True,
            )
            final = subprocess.run(
                ["docker", "exec", postgres, "cat", "/proc/1/comm"], capture_output=True
            )
            # Docker init uses a temporary accepting postmaster before shutdown.
            if (
                r.stdout.strip() == b"PONG"
                and p.returncode == 0
                and final.stdout.strip() == b"postgres"
            ):
                return
            assert time.monotonic() < end, "database readiness timeout"
            time.sleep(0.1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="donna-entry-adapter-") as temporary:
        directory = Path(temporary)
        public_dir = directory / "public"
        public_dir.mkdir()
        evidence = directory / "evidence"
        evidence.mkdir()
        network = name + "-network"
        redis = name + "-redis"
        postgres = name + "-postgres"
        carrier = name + "-secrets"
        offline = name + "-offline"
        redis_volume = name + "-redis-data"
        postgres_volume = name + "-postgres-data"
        secret_volume = name + "-secrets-data"
        public_volume = name + "-public-data"
        application_containers = []
        application = Path(__file__).parent
        try:
            frozen = build(ROOT, directory / "build", run, name, owned_images)
            context = Path(frozen["directory"]) / "context"
            suite = context / "examples/interop"
            application = context / "examples/adapters/remote"
            record["build"] = {
                key: value for key, value in frozen.items() if key != "commands"
            }
            peers = {}
            for role, filename in (("signer", "Bind"), ("checker", "Peers")):
                reference = f"{name}-{role}:local"
                owned_images.append(reference)
                run(
                    "build", "--force-rm", "-t", reference, "-f",
                    str(suite / "docker" / f"{filename}.Dockerfile"), str(context)
                )
                peers[role] = reference
            record["images"] = {
                key: image(value)
                for key, value in dict(
                    redis=REDIS, postgres=POSTGRES, **peers
                ).items()
            }
            if args.public_fixture:
                public = json.loads(args.public_fixture.read_text())
                assert (
                    public["origins"]
                    == {"root": ".", "tld": "test.", "leaf": "example.test."}
                    and public["denial"] == "nsec"
                )
                for role, text in public["zones"].items():
                    (public_dir / (role + ".db")).write_text(text)
                for field, file in [
                    ("bad_tld", "bad-tld.db"),
                    ("restored_tld", "restored-tld.db"),
                    ("anchors", "anchors.zone"),
                ]:
                    (public_dir / file).write_text(public[field])
                record["public_fixture_source"] = dict(
                    path=str(args.public_fixture), sha256=sha(args.public_fixture)
                )
                record["private_signing_keys_generated"] = 0
            else:
                public = prepare(
                    run, name, record["images"]["signer"]["id"], public_dir
                )
                record["private_signing_keys_generated"] = 6
            record["public"] = public
            # No credential or signing private key belongs to the public volume.
            (public_dir / "public.json").write_text(json.dumps(public))
            password = secrets.token_hex(32)
            secret = secrets.token_bytes(32)
            redactions.extend([password, secret.hex()])
            private_dir = directory / "private"
            private_dir.mkdir(mode=0o700)
            (private_dir / "postgres.password").write_text(password)
            (private_dir / "cache.key").write_bytes(secret)
            for p in private_dir.iterdir():
                p.chmod(0o400)
            run("network", "create", "--internal", network)
            for volume in (redis_volume, postgres_volume, secret_volume, public_volume):
                run("volume", "create", volume)
            run(
                "run",
                "-d",
                "--name",
                carrier,
                "--network",
                "none",
                "--cpus",
                ".02",
                "--memory",
                "64m",
                "-v",
                secret_volume + ":/run/secrets",
                "-v",
                public_volume + ":/work",
                "--entrypoint",
                "sleep",
                frozen["runtime"],
                "infinity",
            )
            run("cp", str(private_dir) + "/.", carrier + ":/run/secrets")
            run("cp", str(public_dir) + "/.", carrier + ":/work")
            run(
                "run",
                "-d",
                "--name",
                redis,
                "--network",
                network,
                "--network-alias",
                "redis",
                "--cpus",
                ".2",
                "--memory",
                "192m",
                "-v",
                redis_volume + ":/data",
                record["images"]["redis"]["id"],
                "redis-server",
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--maxmemory",
                "96mb",
                "--maxmemory-policy",
                "noeviction",
            )
            run(
                "run",
                "-d",
                "--name",
                postgres,
                "--network",
                network,
                "--network-alias",
                "postgres",
                "--cpus",
                ".3",
                "--memory",
                "256m",
                "-v",
                postgres_volume + ":/var/lib/postgresql/data",
                "-v",
                secret_volume + ":/run/secrets:ro",
                "-e",
                "POSTGRES_USER=donna",
                "-e",
                "POSTGRES_DB=donna",
                "-e",
                "POSTGRES_PASSWORD_FILE=/run/secrets/postgres.password",
                record["images"]["postgres"]["id"],
                "postgres",
                "-c",
                "shared_buffers=32MB",
                "-c",
                "max_connections=32",
            )
            wait_ready(redis, postgres)

            def app(mode):
                binary = "cache-engine"
                current = name + "-app-" + str(len(record["runs"]))
                application_containers.append(current)
                envfile = private_dir / "app.env"
                envfile.write_text(
                    "REDIS_URL=redis://redis:6379/\nPOSTGRES_URL=host=postgres user=donna password="
                    + password
                    + " dbname=donna"
                    + "\nCACHE_SECRET_FILE=/run/secrets/cache.key\nFIXTURE_DIR=/work\nTOKIO_WORKER_THREADS=1\n"
                )
                envfile.chmod(0o600)
                output = run(
                    "run",
                    "--rm",
                    "--name",
                    current,
                    "--network",
                    network,
                    "--cpus",
                    "1",
                    "--memory",
                    "256m",
                    "--env-file",
                    str(envfile),
                    "-v",
                    secret_volume + ":/run/secrets:ro",
                    "-v",
                    public_volume + ":/work:ro",
                    "--entrypoint",
                    binary,
                    frozen["runtime"],
                    mode,
                    check=False,
                )
                exit_code = record["commands"][-1]["exit_code"]
                record["runs"].append(
                    dict(
                        binary=binary,
                        mode=mode,
                        container=current,
                        exit_code=exit_code,
                        output=output,
                    )
                )
                assert exit_code == 0, (binary, mode, output)
                print(binary, mode, "PASS", flush=True)

            app("seed")
            run("restart", redis, postgres)
            wait_ready(redis, postgres)
            app("verify")
            run("stop", redis)
            app("cache-unavailable")
            run("start", redis)
            wait_ready(redis, postgres)
            run("stop", postgres)
            app("catalog-unavailable")
            run("start", postgres)
            wait_ready(redis, postgres)
            app("verify")
            record["service_info"] = dict(
                redis=run("exec", redis, "redis-cli", "INFO", "server"),
                postgres=run("exec", postgres, "postgres", "--version"),
            )
            # The verifier has public material only and no network or credential volume.
            run(
                "run",
                "-d",
                "--name",
                offline,
                "--network",
                "none",
                "--cpus",
                "1",
                "--memory",
                "256m",
                "--entrypoint",
                "sleep",
                record["images"]["checker"]["id"],
                "infinity",
            )
            for source, target in [
                (application / "engine_verify.py", "engine_verify.py"),
                (suite / "python/negative_denial.py", "negative_denial.py"),
                (suite / "python/recursive_evidence.py", "recursive_evidence.py"),
            ]:
                run("cp", str(source), offline + ":/suite/" + target)
            packet_file = evidence / "public-replies.json"
            packet_file.write_text(json.dumps(dict(public=public, runs=record["runs"])))
            run("cp", str(packet_file), offline + ":/public-replies.json")
            record["offline_verification"] = json.loads(
                run(
                    "exec",
                    offline,
                    "python",
                    "/suite/engine_verify.py",
                    "/public-replies.json",
                )
            )
            record["complete"] = True
        except Exception as error:
            record["error"] = repr(error)
            raise
        finally:
            run(
                "rm",
                "-fv",
                *application_containers,
                offline,
                redis,
                postgres,
                carrier,
                check=False,
            )
            run("network", "rm", network, check=False)
            run(
                "volume",
                "rm",
                redis_volume,
                postgres_volume,
                secret_volume,
                public_volume,
                check=False,
            )
            if not args.keep_images:
                for tag in owned_images:
                    run("image", "rm", tag, check=False)
            record["cleanup"] = (
                "All task containers/network/volumes removed; no signing/sealing/database secrets exported. Unrelated resources preserved."
            )
            record["resources"] = dict(
                application="1CPU/256MiB/oneworker",
                redis=".2CPU/192MiB/maxmemory96MiB/noeviction",
                postgres=".3CPU/256MiB/shared_buffers32MiB",
                offline="1CPU/256MiB/no network",
                builder="jobs1/1CPU/1GiB; databases absent while building",
            )
            save(args, record, evidence, application)


if __name__ == "__main__":
    main()
