"""Serialize public adapter evidence while keeping credentials out of archives."""

import gzip
import hashlib
import json
from pathlib import Path
import tarfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(args, record, evidence, application):
    sources = [
        "run_engine.py",
        "engine_build.py",
        "engine_evidence.py",
        "engine_fixture.py",
        "engine_verify.py",
        "engine_lua_test.py",
        "Dockerfile",
        "Dockerfile.runtime",
        "Cargo.toml",
        "Cargo.lock",
    ]
    sources += [
        str(p.relative_to(application))
        for p in application.joinpath("src").rglob("*")
        if p.is_file()
    ]
    record["harness_sha256"] = {name: sha(application / name) for name in sources}
    for name in sources:
        dest = evidence / "application" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((application / name).read_bytes())
    if "build" in record:
        (evidence / "source-manifest.json").write_text(
            json.dumps(
                record["build"].get("source_manifest", {}),
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
        frozen_directory = Path(record["build"]["directory"])
        source_archive = (
            args.output.parent / "binaries" / (args.output.stem + "-source.tar.gz")
        )
        source_archive.parent.mkdir(exist_ok=True)
        with tarfile.open(source_archive, "w:gz") as archive:
            archive.add(frozen_directory / "context", arcname="source")
            archive.add(frozen_directory / "manifest.json", arcname="manifest.json")
        record["source_archive"] = dict(
            path=str(source_archive), sha256=sha(source_archive)
        )
    prefix = args.output.parent / "binaries" / args.output.stem
    prefix.parent.mkdir(exist_ok=True)
    commands = Path(str(prefix) + "-commands.json.gz")
    commands.write_bytes(
        gzip.compress(json.dumps(record.pop("commands")).encode(), mtime=0)
    )
    record["raw_commands"] = dict(path=str(commands), sha256=sha(commands))
    (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    capsule = Path(
        str(prefix)
        + ("-public.tar.gz" if record["complete"] else "-failed-public.tar.gz")
    )
    with tarfile.open(capsule, "w:gz") as archive:
        for path in evidence.iterdir():
            archive.add(path, arcname=path.name)
    record["public_archive"] = dict(path=str(capsule), sha256=sha(capsule))
    args.output.write_text(json.dumps(record, indent=2) + "\n")
