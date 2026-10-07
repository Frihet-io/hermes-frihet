"""Pytest fixtures shared by the Frihet plugin test suite."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Make sure no real Frihet credential affects test outcomes.

    Each test starts from a known-clean env. Individual tests opt in to
    FRIHET_API_KEY or FRIHET_MCP_URL when they want them.
    """
    for var in ("FRIHET_API_KEY", "FRIHET_MCP_URL", "FRIHET_MCP_TIMEOUT_SECONDS"):
        monkeypatch.delenv(var, raising=False)
    yield