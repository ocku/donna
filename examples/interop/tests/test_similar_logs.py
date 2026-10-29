"""Exact server-log bytes must survive the gate, including whitespace."""

import contextlib
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from labs.authority import similar


class ExactLogTests(unittest.TestCase):
    def check(self, value, expected=None):
        output = io.StringIO()
        with (
            patch.object(similar, "ROLES", {"current": ("fixture", "127.0.0.1")}),
            patch.object(
                similar.subprocess, "run", return_value=SimpleNamespace(stdout=value)
            ),
            contextlib.redirect_stdout(output),
        ):
            result = similar.quiet_logs(expected, mode="nsec", checkpoint="after")
        return result, json.loads(output.getvalue())

    def test_blank_line_is_detected_as_new_log_output(self):
        with self.assertRaisesRegex(RuntimeError, "emitted server logs"):
            self.check(b"\n", {"current": b""})

    def test_whitespace_and_non_utf8_bytes_are_preserved(self):
        value = b"  fixture\xff\n \n"
        result, row = self.check(value)
        self.assertEqual(result, {"current": value})
        self.assertEqual(
            row["logging_gate"]["current"],
            {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()},
        )

    def test_identical_bytes_pass(self):
        self.check(b"fixture\n", {"current": b"fixture\n"})


if __name__ == "__main__":
    unittest.main()
