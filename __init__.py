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
    """Plugin ``pre_tool_call`` hook dispatcher.

    **Pass the full tool name to the gate.** The earlier version stripped
    the ``mcp__frihet__`` prefix here and passed only the bare operation
    (``markInvoicePaid``). The gate then refused the call because its
    namespace check looked for ``"frihet"`` in the input, which the bare
    operation never contained. Result: every irreversible Frihet
    operation bypassed the approval gate. This was a silent safety
    regression — the unit tests on the classifier never crossed the
    dispatcher boundary.

    The contract is now:

      1. Foreign tools (no ``mcp__frihet__`` prefix) — ``None``, the
         caller is not ours, let it flow.
      2. Frihet tools — pass the *full* name to
         ``_frihet.pre_tool_call_gate`` which owns the namespace check,
         classification, and approval-payload shape.

    Hermes dispatches every ``pre_tool_call`` to this function across
    plugins; the gate is the single source of truth for the safety
    decision.
    """
    if not tool_name or not tool_name.startswith(_FRIHET_TOOL_PREFIX):
        return None
    return _frihet.pre_tool_call_gate(tool_name)


def _make_command(ctx: Any):
    """Build the ``/frihet`` slash-command handler bound to this plugin's
    live ``PluginContext``.

    Binding via closure is the documented pattern: ``register_command``
    takes a handler with signature ``(raw_args: str) -> str | None``,
    but the handler needs the ``ctx`` to authoritatively call
    ``ctx.call_mcp`` from inside ``/frihet doctor``. We capture the
    outer ``ctx`` here at registration time.

    The bound function is the only way to authoritatively verify
    authentication against the canonical Frihet MCP: ``ctx.call_mcp``
    uses Hermes's own native MCP client (with its OAuth cache, breaker,
    and reconnect) — the plugin itself never reads tokens.
    """
    def _command(raw_args: str) -> str:
        """Slash-command handler for ``/frihet <status|setup|doctor>``.

        ``/frihet setup`` no longer accepts an inline key argument. Passing
        a key in chat would leave it in the transcript and in any host log
        that captures slash-command output. Authentication is a host-only
        concern: use ``hermes mcp login frihet`` (OAuth/PKCE) or
        ``hermes auth add frihet`` for unattended API keys. The slash
        command therefore only prints guidance — it does not accept,
        validate, or store credentials.

        Returns a JSON string. Failures carry an ``error`` code so the user
        (and the host adapter) can branch on it. Secrets are never echoed.
        """
        parts = raw_args.strip().split()
        action = parts[0].lower() if parts else "status"
        extra = parts[1:]
        if extra:
            # Refuse extra positional arguments across every subcommand.
            # This is the single guardrail for "user pasted an API key in
            # chat" — we reject it loudly instead of swallowing it.
            result = {
                "success": False,
                "error": "unexpected_arguments",
                "subcommand": action,
                "unexpected_args": extra,
                "usage": "/frihet <status|setup|doctor>",
                "hint": (
                    "This plugin never accepts credentials as slash-command "
                    "arguments — they would land in the chat transcript. "
                    "Authenticate with `hermes mcp login frihet` (OAuth/PKCE) "
                    "or `hermes auth add frihet` (unattended API key)."
                ),
            }
        elif action == "status":
            result = _frihet.status()
        elif action == "setup":
            result = _frihet.setup()
        elif action == "doctor":
            # Pass ctx so the doctor can authoritatively verify auth via
            # ``ctx.call_mcp``. Without ctx, doctor() reports
            # authenticated="unknown" / tools_available="unknown" and
            # tells the user to run from inside Hermes.
            result = _frihet.doctor(ctx=ctx)
        elif action in {"help", "--help", "-h"}:
            result = {
                "success": True,
                "usage": "/frihet <status|setup|doctor>",
                "subcommands": {
                    "status": "Show local plugin config (no network).",
                    "setup": (
                        "Print guidance for authenticating against the "
                        "canonical Frihet MCP via the host. Does not accept "
                        "credentials as arguments."
                    ),
                    "doctor": (
                        "Live MCP probe — reports endpoint_reachable, "
                        "mcp_configured_in_hermes, authenticated, and "
                        "tools_available as tri-state (true / false / "
                        "unknown / allowlist_not_granted). Auth and tools "
                        "evidence comes from Hermes's native MCP client, "
                        "never from the plugin reading tokens."
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
    return _command


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
    # Bind ctx via closure so the doctor subcommand can authoritatively
    # verify authentication through ``ctx.call_mcp``.
    ctx.register_command(
        "frihet",
        _make_command(ctx),
        description="Frihet integration: status, setup, doctor.",
        args_hint="<status|setup|doctor>",
    )