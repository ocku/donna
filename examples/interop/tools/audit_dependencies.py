#!/usr/bin/env python3
"""Inventory current locked package provenance without network or installations.

Repository metadata is evidence of a declared upstream, not a security audit.
Only organizations explicitly authorized by the user are classified trusted.
"""

import argparse
import hashlib
import json
import os
from support.paths import ROOT
from pathlib import Path
import tomllib
from urllib.parse import urlparse

MANIFESTS = [ROOT / "Cargo.toml", *sorted((ROOT / "crates").glob("*/Cargo.toml"))]
TRUSTED_GITHUB_ORGS = frozenset(("tokio-rs", "rustcrypto", "aws", "awslabs"))


def declared_repository(cargo_home, package):
    caches = cargo_home / "registry" / "src"
    matches = sorted(
        caches.glob(f"*/{package['name']}-{package['version']}/Cargo.toml")
    )
    repositories = set()
    for manifest in matches:
        metadata = tomllib.loads(manifest.read_text())
        repository = metadata.get("package", {}).get("repository")
        if repository:
            repositories.add(repository)
    return sorted(repositories)


def trusted_repository(repository):
    url = urlparse(repository.removesuffix(".git"))
    parts = url.path.strip("/").split("/")
    return (
        url.hostname == "github.com"
        and len(parts) >= 2
        and parts[0].lower() in TRUSTED_GITHUB_ORGS
    )


def manifest_dependencies():
    dependencies = []
    for manifest in MANIFESTS:
        data = tomllib.loads(manifest.read_text())
        scopes = [("all", data)]
        scopes.extend(sorted(data.get("target", {}).items()))
        for target, scope in scopes:
            for role in ("dependencies", "build-dependencies", "dev-dependencies"):
                for alias, entry in sorted(scope.get(role, {}).items()):
                    entry = {"version": entry} if isinstance(entry, str) else entry
                    dependencies.append(
                        {
                            "manifest": str(manifest.relative_to(ROOT)),
                            "target": target,
                            "role": role,
                            "alias": alias,
                            "package": entry.get("package", alias),
                            "requirement": entry.get("version"),
                            "path": entry.get("path"),
                            "optional": entry.get("optional", False),
                        }
                    )
    return dependencies


def inventory(cargo_home):
    lock_path = ROOT / "Cargo.lock"
    lock_bytes = lock_path.read_bytes()
    packages = []
    for package in tomllib.loads(lock_bytes.decode())["package"]:
        source = package.get("source")
        repositories = declared_repository(cargo_home, package) if source else []
        if not source:
            classification = "workspace-or-local-patch"
        elif not repositories:
            classification = "unverified-upstream"
        elif all(trusted_repository(repo) for repo in repositories):
            classification = "declared-repository-under-named-organization"
        else:
            classification = "outside-named-trusted-organizations"
        packages.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": source,
                "checksum": package.get("checksum"),
                "declared_repositories": repositories,
                "classification": classification,
            }
        )
    counts = {
        kind: sum(p["classification"] == kind for p in packages)
        for kind in sorted({p["classification"] for p in packages})
    }
    return {
        "status": "provenance inventory; trust-policy compliance is NOT proven",
        "trusted_organizations_explicitly_named_by_user": [
            "Tokio",
            "RustCrypto",
            "AWS",
        ],
        "trusted_github_organizations": sorted(TRUSTED_GITHUB_ORGS),
        "policy": "No exception for other organizations has been authorized. Existing presence is not authorization.",
        "scope": "All entries of current root Cargo.lock, including optional and development packages; example-only lockfiles excluded.",
        "limitations": "Cached Cargo.toml declared repository is not verified ownership, a maintainer audit, or proof of active target reachability. Local patches require separate source review.",
        "lockfile_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "classification_counts": counts,
        "direct_dependencies": manifest_dependencies(),
        "packages": packages,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "examples/interop/.artifacts/current-dependency-provenance.json",
    )
    args = parser.parse_args()
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    result = inventory(cargo_home)
    # One object per line keeps generated evidence reviewable and below 500
    # lines without hiding any package, checksum, role or declared repository.
    lines = ["{"]
    items = list(result.items())
    for index, (key, value) in enumerate(items):
        suffix = "," if index + 1 < len(items) else ""
        if isinstance(value, list):
            lines.append(f"  {json.dumps(key)}: [")
            lines.extend(
                "    "
                + json.dumps(item, sort_keys=True)
                + ("," if number + 1 < len(value) else "")
                for number, item in enumerate(value)
            )
            lines.append("  ]" + suffix)
        else:
            lines.append(
                "  "
                + json.dumps(key)
                + ": "
                + json.dumps(value, sort_keys=True)
                + suffix
            )
    lines.append("}")
    args.output.write_text("\n".join(lines) + "\n")
    print(json.dumps(result["classification_counts"], sort_keys=True))


if __name__ == "__main__":
    main()
