"""Regression tests for the PyYAML runtime dependency.

frihet.mcp_server_block_present() imports yaml inside a
try/except to parse the user's ``~/.hermes/config.yaml``.
Without PyYAML installed, the function silently returns
``unknown`` even when a valid block is present. That
silent degradation broke 5 tests in test_frihet.py (see
the 5 ``test_mcp_*`` tests in the existing suite).

These tests pin the dependency contract: PyYAML must be
importable, must be declared in pyproject.toml, and the
degraded path must NOT return ``unknown`` when yaml is
available (it returns ``unknown`` only when yaml is missing
OR the YAML is malformed).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = PLUGIN_ROOT / "pyproject.toml"


def test_pyyaml_is_importable() -> None:
    """If this test fails, the install is broken in a way that
    breaks the production code path. Fail fast."""
    try:
        import yaml  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        pytest.fail(
            f"PyYAML is not importable but frihet.py depends on it. "
            f"Install with `pip install PyYAML>=6.0` or activate a venv "
            f"that has it. Original error: {exc}"
        )


def test_pyyaml_declared_in_pyproject() -> None:
    """The runtime dependency must be declared explicitly so a
    fresh install does not silently degrade."""
    text = PYPROJECT.read_text(encoding="utf-8")
    # Find the dependencies = [...] block
    m = re.search(r"dependencies\s*=\s*\[([^\]]*)\]", text)
    assert m, "pyproject.toml has no dependencies = [...] block"
    block = m.group(1).lower()
    assert "pyyaml" in block, (
        f"PyYAML is not declared in pyproject.toml's dependencies. "
        f"frihet.py uses yaml.safe_load() and silently degrades to "
        f"returning 'unknown' when the import fails. Declared deps: "
        f"{block!r}"
    )


def test_mcp_block_present_returns_configured_when_yaml_available(
    tmp_path, monkeypatch
) -> None:
    """The happy path: a valid YAML config with an mcp_servers.frihet
    block must return 'configured' (not 'unknown' and not 'missing')."""
    # Write a config that has the mcp_servers.frihet block with auth=str
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "mcp_servers:\n  frihet:\n    url: https://mcp.frihet.io/mcp\n"
        "    auth: oauth\n",
        encoding="utf-8",
    )
    # Point HERMES_HOME at tmp_path so frihet.mcp_server_block_present
    # reads our file
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    from frihet import mcp_server_block_present
    result = mcp_server_block_present()
    assert result == "configured", (
        f"Expected 'configured' for a valid block, got {result!r}. "
        f"This regression means PyYAML silently failed or the "
        f"function was changed."
    )
