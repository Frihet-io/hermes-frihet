"""End-to-end smoke tests that load the plugin via the official Hermes
``PluginManager`` discovery path against a throwaway ``HERMES_HOME``.

Run with the same Python interpreter Hermes uses (its own venv):

    PYTHONPATH=/path/to/hermes-agent /path/to/hermes-agent/venv/bin/python -m pytest tests/

Unit tests in ``test_frihet.py`` cover behaviour in isolation and do not
require the Hermes source on ``PYTHONPATH``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _hermes_importable() -> bool:
    try:
        import hermes_cli.plugins  # noqa: F401
    except Exception:
        return False
    return True


# Skip ONLY when Hermes source is genuinely not importable. When the test is
# run inside Hermes's own venv (the canonical case), it runs for real.
pytestmark = pytest.mark.skipif(
    not _hermes_importable(),
    reason="hermes_cli.plugins not importable in this environment — "
    "run via Hermes's own venv (PYTHONPATH=$HERMES_HOME/hermes-agent)",
)


def _enable_plugin(home: Path) -> None:
    """Write a minimal ``config.yaml`` that auto-enables the frihet plugin.

    ``PluginManager.discover_and_load`` discovers any plugin under
    ``$HERMES_HOME/plugins/<name>/`` but it stays ``enabled=False`` until
    ``config.yaml``'s ``plugins.enabled`` list contains it. Without an
    enable, the registration surface shows ``hooks: 0, commands: 0`` even
    though ``register(ctx)`` did run during discovery.
    """
    cfg = home / "config.yaml"
    cfg.write_text("plugins:\n  enabled:\n    - frihet\n", encoding="utf-8")


def _boot_manager(home: Path):
    """Drop the repo into ``$HERMES_HOME/plugins/frihet`` and boot the manager."""
    plugin_dir = home / "plugins" / "frihet"
    plugin_dir.parent.mkdir(parents=True)
    os.symlink(ROOT, str(plugin_dir))
    _enable_plugin(home)

    from hermes_cli import plugins as plugins_mod

    manager = plugins_mod.PluginManager()
    manager.discover_and_load()
    return manager


def _find_frihet(manager) -> dict | None:
    for entry in manager.list_plugins():
        if isinstance(entry, dict) and entry.get("name") == "frihet":
            return entry
    return None


def test_plugin_discovers_and_registers(tmp_path, monkeypatch):
    """Drop the repo into ``HERMES_HOME/plugins/frihet`` and let Hermes discover it."""
    hermes_home = tmp_path / "hermes"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    manager = _boot_manager(hermes_home)
    summary = _find_frihet(manager)
    assert summary, (
        "Frihet plugin was not discovered "
        f"(found: {[e.get('name') if isinstance(e, dict) else '?' for e in manager.list_plugins()]})"
    )
    assert summary["kind"] == "standalone"
    assert summary["source"] == "user"
    assert summary["enabled"] is True
    # The plugin registers exactly one hook (pre_tool_call) and one slash
    # command (/frihet). Tools stay at zero — the canonical Frihet surface
    # lives in the MCP, not in this plugin.
    assert summary["hooks"] == 1, f"expected 1 hook, got {summary['hooks']}"
    assert summary["commands"] == 1, f"expected 1 command, got {summary['commands']}"
    assert summary["tools"] == 0, "plugin must not register any tools"


def test_register_wires_skill(tmp_path, monkeypatch):
    """The skill loaded from ``skills/frihet/SKILL.md`` must be discoverable."""
    hermes_home = tmp_path / "hermes"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    manager = _boot_manager(hermes_home)
    skill_names = manager.list_plugin_skills("frihet")
    assert "frihet" in skill_names, f"frihet skill not loaded (got {skill_names})"


def test_validate_local_repo_passes(monkeypatch, tmp_path):
    """Smoke test: the validate command's subprocess-isolated capability probe
    against this very repo must return ok=True with the live Hermes runtime.
    """
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    from hermes_cli.plugin_validate import validate_plugin_dir

    report = validate_plugin_dir(ROOT)
    failures = report.failures if hasattr(report, "failures") else []
    warnings = report.warnings if hasattr(report, "warnings") else []
    assert report.ok, f"validate failed: {failures}\nwarnings: {warnings}"
    check_names = [name for name, _ok, _detail in report.checks]
    # The capability probe (subprocess-isolated) must have actually run.
    assert "capability probe" in check_names, f"checks: {check_names}"