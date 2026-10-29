"""Docker CLI invocation shared by independent laboratory drivers."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def docker(*args, check=True, capture=False):
    result = subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"docker {' '.join(args)} failed ({result.returncode})\n{result.stdout or ''}"
        )
    return result.stdout.strip() if capture else result.returncode
