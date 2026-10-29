"""Check that fresh-chain batches cannot silently prewarm their resolver."""

import contextlib
import io
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.flags
import dns.message

import chain_load


class ChainLoadTest(unittest.TestCase):
    def run_batch(self, cold, workload="positive"):
        arguments = [
            "chain_load.py",
            "--server",
            "donna",
            "--mode",
            "nsec",
            "--population",
            "2",
            "--load-client",
            "batched",
            "--workload",
            workload,
        ]
        if cold:
            arguments += [
                "--cold-chain-batch",
                "--expected-response-flags",
                str(0x81A0),
            ]
        query = dns.message.make_query(
            "www.example.test.", "A", want_dnssec=True, payload=1232
        )
        reply = dns.message.make_response(query)
        reply.flags = 0x81A0
        with (
            patch("sys.argv", arguments),
            patch.object(
                chain_load.socket, "create_connection", return_value=MagicMock()
            ),
            patch.object(chain_load.dns.query, "udp", return_value=reply) as udp,
            patch.object(chain_load, "verify") as verify,
            patch.object(
                chain_load, "verify_all", new_callable=AsyncMock
            ) as postverify,
            patch.object(chain_load, "measure") as measure,
            contextlib.redirect_stdout(io.StringIO()),
        ):

            def check_at_measure(*args, **kwargs):
                self.assertEqual(udp.call_count, 0 if cold else 1)
                self.assertEqual(len(args[2]), 2)
                self.assertEqual(kwargs["max_runs"], 1)
                self.assertEqual(
                    kwargs["expected_response_flags"],
                    0x81A3 if workload == "negative" else 0x81A0,
                )
                self.assertEqual(
                    str(args[2][0][0].question[0].name),
                    "n-0000-b.example.test."
                    if workload == "negative"
                    else "host-0000.example.test.",
                )
                self.assertEqual(kwargs["load_client"], "batched")
                self.assertFalse(postverify.called)

            measure.side_effect = check_at_measure
            chain_load.main()
            measure.assert_called_once()
            postverify.assert_awaited_once()
            self.assertEqual(verify.call_count, 0 if cold else 1)

    def test_fresh_chain_has_no_dns_preflight(self):
        self.run_batch(True)

    def test_default_retains_chain_warming_control(self):
        self.run_batch(False)

    def test_fresh_negative_preserves_control_flags_except_rcode(self):
        self.run_batch(True, "negative")

    def test_fresh_chain_requires_separate_control_flags(self):
        with (
            patch(
                "sys.argv",
                [
                    "chain_load.py",
                    "--server",
                    "donna",
                    "--mode",
                    "nsec",
                    "--cold-chain-batch",
                ],
            ),
            patch.object(chain_load.socket, "create_connection") as connect,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as error:
                chain_load.main()
            self.assertEqual(error.exception.code, 2)
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
