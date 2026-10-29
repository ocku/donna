"""Synthetic rows exercise the oversized-SOA evidence checker, without a lab."""

import copy
import unittest

from oversized_soa_checks import validate


def observations():
    rows = []
    for protocol in ("udp", "tcp"):
        rows.append(
            dict(
                server="authority",
                protocol=protocol,
                stage="direct",
                rcode="NXDOMAIN",
                soa_ttl=20,
                minimum=6,
            )
        )
        for server in ("donna", "bind"):
            for stage, before, after, ttl in (
                ("cold", 0, 1, 6),
                ("warm", 1, 1, 5),
                ("after-minimum", 1, 2, 0),
            ):
                recovered = stage == "after-minimum"
                rows.append(
                    dict(
                        server=server,
                        protocol=protocol,
                        stage=stage,
                        rcode="NOERROR" if recovered else "NXDOMAIN",
                        upstream_before=before,
                        upstream_after=after,
                        answers=[
                            [
                                f"oversized-soa-{server}-{protocol}.example.test.",
                                "192.0.2.99",
                            ]
                        ]
                        if recovered
                        else [],
                        soas=[] if recovered else [["example.test.", ttl, 6]],
                    )
                )
    return rows


class OversizedSoaChecks(unittest.TestCase):
    def setUp(self):
        self.rows = observations()

    def test_consistent_model_passes(self):
        validate(self.rows)

    def test_rejects_malformed_fixture_lost_cache_and_false_recovery(self):
        for server, stage, field, value in (
            ("authority", "direct", "minimum", 20),
            ("donna", "cold", "rcode", "NOERROR"),
            ("donna", "warm", "upstream_after", 2),
            ("donna", "warm", "soas", [["example.test.", 19, 6]]),
            ("donna", "after-minimum", "upstream_after", 1),
            ("donna", "after-minimum", "answers", []),
        ):
            rows = copy.deepcopy(self.rows)
            row = next(
                row
                for row in rows
                if (row["server"], row["protocol"], row["stage"])
                == (server, "udp", stage)
            )
            row[field] = value
            with (
                self.subTest(server=server, stage=stage, field=field),
                self.assertRaises(AssertionError),
            ):
                validate(rows)

    def test_rejects_missing_and_duplicate_rows(self):
        for rows in (self.rows[:-1], self.rows[:-1] + [self.rows[0]]):
            with self.assertRaises(AssertionError):
                validate(rows)


if __name__ == "__main__":
    unittest.main()
