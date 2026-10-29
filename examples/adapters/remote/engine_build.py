"""Freeze exact sources before a locked Docker-only example build."""

import hashlib
import json
from pathlib import Path
import shutil

RUST = "sha256:e9da6f6c3ed5095fd5d33bf7cdf309830a178a8147888f1b2f76d5769bd9306c"
SLIM = "sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8"


def freeze(repo, directory):
    repo, directory = Path(repo), Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    context = directory / "context"
    context.mkdir()
    for name in (
        "crates", "src", "vendor", "examples/adapters/remote",
        "examples/interop/docker", "examples/interop/python", "examples/interop/fixtures",
    ):
        shutil.copytree(
            repo / name,
            context / name,
            ignore=shutil.ignore_patterns("target", "__pycache__", ".DS_Store", ".git"),
        )
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copy2(repo / name, context / name)
    manifest = {
        str(p.relative_to(context)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in context.rglob("*")
        if p.is_file()
    }
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    (directory / "manifest.json").write_bytes(raw)
    return context, manifest, hashlib.sha256(raw).hexdigest()


def build(repo, directory, run, name, owned_images):
    context, manifest, digest = freeze(repo, directory)
    builder = name + "-builder:local"
    runtime = name + ":local"
    owned_images.extend([runtime, builder])
    run(
        "build",
        "--force-rm",
        "--target",
        "builder",
        "--cpu-period",
        "100000",
        "--cpu-quota",
        "100000",
        "--memory",
        "1g",
        "--build-arg",
        "RUST_IMAGE=" + RUST,
        "--build-arg",
        "RUNTIME_IMAGE=" + SLIM,
        "-f",
        str(context / "examples/adapters/remote/Dockerfile"),
        "-t",
        builder,
        str(context),
    )
    builder_id = json.loads(run("image", "inspect", builder))[0]["Id"]
    run(
        "build",
        "--force-rm",
        "--build-arg",
        "BUILDER_IMAGE=" + builder_id,
        "--build-arg",
        "RUNTIME_IMAGE=" + SLIM,
        "-f",
        str(context / "examples/adapters/remote/Dockerfile.runtime"),
        "-t",
        runtime,
        str(context),
    )
    runtime_id = json.loads(run("image", "inspect", runtime))[0]["Id"]
    return dict(
        directory=str(directory),
        source_manifest=manifest,
        source_manifest_sha256=digest,
        source_files=len(manifest),
        builder=builder_id,
        runtime=runtime_id,
        owned_image_tags=[runtime, builder],
        build_bases=dict(rust=RUST, debian=SLIM),
        complete=True,
    )
