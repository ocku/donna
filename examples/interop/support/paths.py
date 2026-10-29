"""Stable filesystem locations shared by host drivers."""

from .docker import ROOT

SUITE = ROOT / "examples/interop"
FIXTURES = SUITE / "fixtures"
