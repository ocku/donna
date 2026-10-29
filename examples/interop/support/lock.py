"""Serialize host-side jobs sharing laboratory containers, fixtures and CPUs."""

from contextlib import contextmanager
import fcntl
from functools import wraps
from pathlib import Path
import sys
import tempfile
import threading

_MUTEX = threading.RLock()
_DEPTH = 0


@contextmanager
def laboratory_lock():
    global _DEPTH
    # run.py calls the signed driver in-process; nested acquisition must not
    # deadlock on a second file descriptor for the same host process.
    with _MUTEX:
        if _DEPTH:
            _DEPTH += 1
            try:
                yield
            finally:
                _DEPTH -= 1
            return
        with (Path(tempfile.gettempdir()) / "donna-interop-laboratory.lock").open(
            "a+"
        ) as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(
                    "Waiting for the active Donna laboratory job to finish",
                    file=sys.stderr,
                    flush=True,
                )
                fcntl.flock(handle, fcntl.LOCK_EX)
            _DEPTH = 1
            try:
                yield
            finally:
                _DEPTH = 0
                fcntl.flock(handle, fcntl.LOCK_UN)


def exclusive_laboratory(function):
    @wraps(function)
    def exclusive(*args, **kwargs):
        with laboratory_lock():
            return function(*args, **kwargs)

    return exclusive
