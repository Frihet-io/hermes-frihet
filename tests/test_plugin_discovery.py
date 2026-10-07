"""End-to-end smoke test that loads the plugin via the official Hermes
``PluginManager`` discovery path against a throwaway ``HERMES_HOME``.

This test intentionally imports ``hermes_cli.plugins`` so the plugin's
real loader is exercised. If the Hermes internals are not importable in
the test environment, the test is skipped rather than failed — the unit
tests in ``test_frihet.py`` cover the plugin's behaviour in isolation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _hermes_importable() -> bool:
    try:
        import hermes_cli.plugins  # noqa: F401
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(
    not _hermes_importable(),
    reason="hermes_cli.plugins not importable in this environment",
)


def test_plugin_discovers_and_registers(tmp_path, monkeypatch):
    """Drop the repo into ``HERMES_HOME/plugins/frihet`` and let Hermes discover it."""
    hermes_home = tmp_path / "hermes"
    plugin_dir = hermes_home / "plugins" / "frihet"
    plugin_dir.parent.mkdir(parents=True)
    # Symlink so we don't copy.
    os.symlink(ROOT, str(plugin_dir))

    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_e2e_12345")

    from hermes_cli import plugins as plugins_mod

    manager = plugins_mod.PluginManager()
    discovered = list(manager.list_plugins())
    matches = [p for p in discovered if getattr(p, "name", "") == "frihet" or getattr(getattr(p, "manifest", None), "name", "") == "frihet"]
    assert matches, f"Frihet plugin was not discovered (found: {[getattr(p, 'name', '?') for p in discovered]})"
    # The discovery path may return a Plugin or a PluginManifest depending on
    # the Hermes version. Pick whichever shape carries the manifest.
    first = matches[0]
    manifest = getattr(first, "manifest", first)
    assert manifest.kind == "standalone"
    # The plugin does not require env vars — credentials live on the
    # ``mcp_servers.frihet`` block in config.yaml (Bearer API key OR OAuth).
    assert manifest.requires_env == []
    assert manifest.provides_hooks == ["pre_tool_call"]
    assert manifest.provides_tools == []