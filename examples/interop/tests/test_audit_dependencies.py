"""Organization authorization never propagates through dependency edges."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import audit_dependencies as audit


class ProvenanceTests(unittest.TestCase):
    def test_exact_authorized_organizations(self):
        for repository in (
            "https://github.com/tokio-rs/tokio",
            "https://github.com/RustCrypto/hashes.git",
            "https://github.com/aws/aws-lc-rs",
            "https://github.com/aws/aws-lc",
            "https://github.com/awslabs/aws-sdk-rust",
        ):
            with self.subTest(repository=repository):
                self.assertTrue(audit.trusted_repository(repository))

    def test_names_and_similar_hosts_do_not_authorize_projects(self):
        for repository in (
            "https://github.com/aws-community/aws-lc-rs",
            "https://github.com/other/aws-sdk",
            "https://github.com/aws",
            "https://github.com.evil.test/aws/aws-lc-rs",
            "https://github.com@evil.test/aws/aws-lc-rs",
            "https://github.com/alexcrichton/cmake-rs",
            "https://github.com/rust-random/getrandom",
            "https://github.com/briansmith/ring",
        ):
            with self.subTest(repository=repository):
                self.assertFalse(audit.trusted_repository(repository))

    def test_aws_dependency_does_not_authorize_its_transitive_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("Cargo.lock").write_text("""version = 4
[[package]]
name = "aws-lc-sys"
version = "1.0.0"
source = "registry+fixture"
dependencies = ["cmake"]
[[package]]
name = "cmake"
version = "1.0.0"
source = "registry+fixture"
[[package]]
name = "aws-looking-name"
version = "1.0.0"
source = "registry+fixture"
""")
            repositories = {
                "aws-lc-sys": ["https://github.com/aws/aws-lc-rs"],
                "cmake": ["https://github.com/alexcrichton/cmake-rs"],
                "aws-looking-name": ["https://github.com/other/aws-looking-name"],
            }
            with (
                patch.object(audit, "ROOT", root),
                patch.object(audit, "manifest_dependencies", return_value=[]),
                patch.object(
                    audit,
                    "declared_repository",
                    side_effect=lambda _, package: repositories[package["name"]],
                ),
            ):
                result = audit.inventory(root)
            by_name = {
                package["name"]: package["classification"]
                for package in result["packages"]
            }
            self.assertEqual(
                by_name["aws-lc-sys"], "declared-repository-under-named-organization"
            )
            self.assertEqual(by_name["cmake"], "outside-named-trusted-organizations")
            self.assertEqual(
                by_name["aws-looking-name"], "outside-named-trusted-organizations"
            )


if __name__ == "__main__":
    unittest.main()
