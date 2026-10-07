"""Hermes Agent plugin registration for the official Frihet integration.

This module follows the public ``PluginContext`` API documented in
``hermes_cli.plugins``. The plugin is deliberately thin: it does NOT
re-implement the 158 Frihet MCP operations — the canonical surface stays
in ``@frihet/mcp-server`` (npm) and the remote endpoint
``https://mcp.frihet.io/mcp``.

What the plugin adds on top of the MCP itself:

* A skill (``skills/frihet/SKILL.md``) that teaches Hermes the Frihet
  operating contract (read-before-write, draft-first, Idempotency-Key,
  redaction, Frihet-server authority for workspace/scopes/roles).
* A slash command ``/frihet`` with three sub-actions:
    - ``status`` — local snapshot (no network).
    - ``setup``  — guided validation of a candidate ``FRIHET_API_KEY``.
    - ``doctor`` — live MCP handshake.
* A ``pre_tool_call`` hook that flags Frihet operations whose names imply
  irreversibility, so downstream policy or the model itself can pause and
  request human confirmation.

The plugin is loaded by Hermes from
``~/.hermes/plugins/frihet/`` once installed via the catalog.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Support both package-style and direct-file loading used by tests/Hermes.
try:
    from . import frihet as _frihet
except ImportError:  # pragma: no cover - direct-file loading path
    import frihet as _frihet  # type: ignore[no-redef]


# Names of Frihet MCP tool invocations this hook should look at. The Hermes
# MCP convention is ``mcp__<server>__<operation>`` — when the Frihet MCP
# server is configured as ``frihet``, that becomes ``mcp__frihet__<op>``.
_FRIHET_TOOL_PREFIX = "mcp__frihet__"


def _pre_tool_call(tool_name: str = "", **_: Any) -> dict[str, Any] | None:
    """Hook payload: surface safety hints for irreversible Frihet writes."""
    if not tool_name or not tool_name.startswith(_FRIHET_TOOL_PREFIX):
        return None
    operation = tool_name[len(_FRIHET_TOOL_PREFIX):]
    return _frihet.pre_tool_call_gate(operation)


def _command(raw_args: str) -> str:
    """Slash-command handler for ``/frihet <status|setup|doctor>``.

    Returns a JSON string. Failures carry an ``error`` code so the user
    (and the host adapter) can branch on it. Secrets are never echoed.
    """
    parts = raw_args.strip().split()
    action = parts[0].lower() if parts else "status"
    if action == "status":
        result = _frihet.status()
    elif action == "setup":
        # Two layouts supported:
        #   /frihet setup                  -> validate the currently configured key.
        #   /frihet setup <api_key_value>  -> validate a candidate pasted in-chat
        #                                    (NOT recommended — the key then lives
        #                                    in the transcript. Prefer /frihet
        #                                    status -> heres auth path.)
        candidate = parts[1] if len(parts) > 1 else None
        result = _frihet.setup(api_key_value=candidate)
    elif action == "doctor":
        result = _frihet.doctor()
    elif action in {"help", "--help", "-h"}:
        result = {
            "success": True,
            "usage": "/frihet <status|setup|doctor>",
            "subcommands": {
                "status": "Show local plugin config (no network).",
                "setup": "Validate FRIHET_API_KEY and print the MCP server block.",
                "doctor": (
                    "Live MCP probe — reports endpoint_reachable, "
                    "mcp_configured_in_hermes, authenticated, and "
                    "tools_available as tri-state (true / false / "
                    "unknown). Never a single 'connected' flag."
                ),
            },
        }
    else:
        result = {
            "success": False,
            "error": "unknown_subcommand",
            "subcommand": action,
            "usage": "/frihet <status|setup|doctor>",
        }
    return json.dumps(result, indent=2, ensure_ascii=False, default=str)


def register(ctx: Any) -> None:
    """Register the Frihet integration with a Hermes ``PluginContext``."""
    # ── Skill: operating guidance + safety contract ────────────────────────
    skills_dir = Path(__file__).resolve().parent / "skills"
    for child in sorted(skills_dir.iterdir()):
        skill_md = child / "SKILL.md"
        if child.is_dir() and skill_md.exists():
            ctx.register_skill(child.name, skill_md)

    # ── Hook: pre_tool_call ────────────────────────────────────────────────
    # We declare `pre_tool_call` in plugin.yaml; here we hand Hermes the
    # actual callback. Tools that match the Frihet MCP prefix get a safety
    # advisory; everyone else is left alone (the hook is cheap and
    # idempotent).
    ctx.register_hook("pre_tool_call", _pre_tool_call)

    # ── Slash command: /frihet ─────────────────────────────────────────────
    # Plugins can register either a slash command (``/frihet``) or a CLI
    # subcommand (``hermes frihet``). The slash form is the one users
    # discover in-chat, so we register that.
    ctx.register_command(
        "frihet",
        _command,
        description="Frihet integration: status, setup, doctor.",
        args_hint="<status|setup|doctor>",
    )