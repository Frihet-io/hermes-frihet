"""Frihet integration helpers for the Hermes Agent plugin.

This module is intentionally small and stdlib-only. It does NOT register
duplicate Frihet tools — the canonical Frihet surface (158 MCP operations)
lives in the official ``@frihet/mcp-server`` and the remote endpoint at
``https://mcp.frihet.io/mcp``. What this module provides:

* ``status`` — read-only snapshot of plugin config and MCP endpoint reachability.
* ``setup`` — guided writing of ``FRIHET_API_KEY`` into the user's Hermes
  secret directory (never ``config.yaml``; never stdout).
* ``doctor`` — liveness check that exercises the MCP ``initialize`` handshake
  using a deliberately non-destructive probe.
* ``redact`` — strip API keys, bearer tokens, and known auth headers from any
  string before it leaves the plugin (used by the ``pre_tool_call`` hook so a
  misconfigured tool call that mentions a secret never bubbles it up).
* ``pre_tool_call_gate`` — early-warning gate that flags Frihet tool calls
  whose names match reversible-vs-irreversible patterns, so a downstream
  policy or the model itself can pause and require human confirmation.

Public API: every function returns a JSON-serialisable ``dict`` with a
``success`` boolean. Failures carry an ``error`` key with a short code
(``no_api_key``, ``mcp_unreachable``, ``mcp_unauthorized``, ``mcp_timeout``,
``malformed_response``); the slash command surfaces these without leaking
secret material.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

# ─── Canonical surface (single source of truth) ──────────────────────────────

DEFAULT_MCP_URL = "https://mcp.frihet.io/mcp"
DEFAULT_TIMEOUT_SECONDS = 10
PROTOCOL_VERSION = "2025-06-18"  # MCP protocol version we speak.
CLIENT_NAME = "hermes-frihet-plugin"
CLIENT_VERSION = "0.1.0"

# ─── Public env contract ────────────────────────────────────────────────────


def api_key() -> str:
    """Return the configured Frihet API key, or ``''`` if not set.

    The caller MUST treat the returned value as a secret: never log, never
    print, never include in error messages, never echo into ``__repr__``.
    """
    return os.getenv("FRIHET_API_KEY", "").strip()


def mcp_url() -> str:
    """Return the configured MCP endpoint URL, defaulting to the canonical one."""
    raw = os.getenv("FRIHET_MCP_URL", "").strip()
    return raw or DEFAULT_MCP_URL


def timeout_seconds() -> float:
    raw = os.getenv("FRIHET_MCP_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return float(DEFAULT_TIMEOUT_SECONDS)
    try:
        value = float(raw)
        return value if value > 0 else float(DEFAULT_TIMEOUT_SECONDS)
    except ValueError:
        return float(DEFAULT_TIMEOUT_SECONDS)


# ─── Redaction (defence in depth) ───────────────────────────────────────────

# Patterns are intentionally conservative. A substring of any of these in a
# candidate string is sufficient to mask the entire token in place.
# Order matters: more specific patterns first, generic last. The Bearer rule
# runs before the generic Authorization rule so a "Bearer ..." payload keeps
# its label (the generic rule would otherwise redact the whole header line,
# hiding the fact that a Bearer token was present).
_REDACT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"fri_[A-Za-z0-9_\-]{8,}"), "[REDACTED:FRIHET_API_KEY]"),
    (re.compile(r"FRIHET_API_KEY\s*=\s*\S+"), "FRIHET_API_KEY=[REDACTED]"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9_\-\.=]+"),
     r"\1[REDACTED:TOKEN]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{8,}"), "Bearer [REDACTED:TOKEN]"),
    (re.compile(r"(?i)(authorization\s*:\s*)[^\n\r]+"), r"\1[REDACTED]"),
)


def redact(value: str) -> str:
    """Return ``value`` with any embedded Frihet secret material masked.

    Used by the ``pre_tool_call`` hook so a misconfigured tool invocation
    whose argument happened to contain a key never bubbles it up to the
    model or the session transcript.
    """
    if not value:
        return value
    out = value
    for pattern, replacement in _REDACT_RULES:
        # Skip the generic ``Authorization: ...`` redactor if a more specific
        # rule already produced a ``[REDACTED`` marker on this segment —
        # otherwise the generic rule would clobber ``Bearer [REDACTED:TOKEN]``
        # back into ``Authorization: [REDACTED]``, losing the token-kind label.
        pat = pattern.pattern
        is_generic_auth = "authorization" in pat.lower() and "bearer" not in pat.lower()
        if is_generic_auth and "[REDACTED" in out:
            continue
        out = pattern.sub(replacement, out)
    return out


def has_redaction_problem(value: str) -> bool:
    """Return ``True`` if ``value`` contained a token we had to redact."""
    if not value:
        return False
    return any(pattern.search(value) for pattern, _ in _REDACT_RULES)


# ─── Irreversibility hints (safety contract) ────────────────────────────────

# These tool names match Frihet MCP operations that produce external effects:
# VeriFactu filings, fiscal-number issuance, payments, deletions. The
# `pre_tool_call` hook flags any such call so downstream policy or the user
# can require explicit human confirmation. The plugin does NOT block the
# call — it surfaces a structured warning the model can read.
IRREVERSIBLE_PATTERNS: tuple[str, ...] = (
    "send",
    "markPaid",
    "mark_paid",
    "finalize",
    "issue",
    "delete",
    "destroy",
    "revoke",
    "cancelInvoice",
    "cancel_invoice",
    "registerVerifactu",
    "register_verifactu",
    "createPayment",
    "create_payment",
    "applyCreditNote",
    "apply_credit_note",
)

# Operations that should always produce a draft (never a finalised document).
# Read more: https://github.com/Frihet-io/frihet-sdk/blob/main/AGENTS.md
# Note: ``createPayment`` is intentionally NOT listed here — a payment, once
# recorded on the Frihet side, is irreversible (financial effect). It lives in
# ``IRREVERSIBLE_PATTERNS`` instead.
DRAFT_FIRST_OPERATIONS: tuple[str, ...] = (
    "createInvoice",
    "create_invoice",
    "createQuote",
    "create_quote",
    "createCreditNote",
    "create_credit_note",
)


def classify_tool_call(tool_name: str) -> dict[str, Any]:
    """Classify a Frihet MCP tool name against the safety contract.

    Returns a dict with ``kind`` (``"read"`` | ``"draft-write"`` |
    ``"irreversible-write"`` | ``"unknown"``), and a ``hint`` carrying
    operating guidance. The plugin uses this in ``pre_tool_call`` and the
    skill references it for documentation.
    """
    if not tool_name:
        return {"kind": "unknown", "hint": "No tool name provided."}
    normalised = tool_name.lower()
    if any(pat.lower() in normalised for pat in IRREVERSIBLE_PATTERNS):
        return {
            "kind": "irreversible-write",
            "hint": (
                "This Frihet operation produces an external effect "
                "(send, payment, VeriFactu, deletion). Re-read the "
                "target record, confirm the human authorised it, "
                "honour any Idempotency-Key, and do NOT retry blindly."
            ),
        }
    if any(pat.lower() in normalised for pat in DRAFT_FIRST_OPERATIONS):
        return {
            "kind": "draft-write",
            "hint": (
                "Prefer creating a draft first and presenting the "
                "totals for human approval before any send/mark-paid."
            ),
        }
    if normalised.startswith(("get", "list", "search", "describe", "schema", "fetch")):
        return {"kind": "read", "hint": "Read-only — safe to call."}
    return {
        "kind": "unknown",
        "hint": (
            "Treat as write until proven read-only. Re-read the Frihet "
            "AGENTS.md guidance before issuing."
        ),
    }


# ─── Hook payload ───────────────────────────────────────────────────────────


def pre_tool_call_gate(tool_name: str = "", **_: Any) -> dict[str, Any] | None:
    """Plugin hook payload for ``pre_tool_call``.

    Contract (per ``hermes_cli/plugins.py`` line ~2044):

    * For ``read`` — ``None`` (no gating, call flows through).
    * For ``draft-write`` — ``None`` (Hermes already lets the user approve
      on tool-call time; we lean on the bundled skill instead).
    * For ``irreversible-write`` — ``{"action": "approve", "message": ...,
      "rule_key": "frihet:<operation>"}``. This escalates the tool call to
      Hermes's approval gate so a human has to confirm before a fiscal
      action lands.

    Any other return shape is ignored by Hermes, so a wrong key here is a
    silent safety hole. We only return one of the three documented shapes.
    """
    if not tool_name:
        return None
    # Only act on Frihet MCP tools: mcp__frihet__<operation> is the Hermes
    # naming convention for MCP-provided tools.
    if "frihet" not in tool_name.lower():
        return None
    # Strip any MCP-server prefix (``mcp__frihet__``, ``mcp__<anything>__``)
    # before classification so a "list_*" prefix is detectable. Preserve the
    # original case in ``operation`` — the safety contract uses the same case
    # the canonical Frihet MCP advertises (``markPaid``, ``sendInvoice``, …).
    operation = (
        tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name
    )
    classification = classify_tool_call(operation)
    kind = classification.get("kind")
    if kind in ("read", "draft-write", None):
        # Reads and draft-writes flow through. The skill tells the model to
        # pause and show totals for draft-writes; the hook stays out of the
        # way so we don't block unattended reads.
        return None
    if kind == "irreversible-write":
        return {
            "action": "approve",
            "message": (
                f"Frihet MCP operation `{operation}` is irreversible — it "
                f"reaches a tax authority, moves money, or deletes state. "
                f"{classification.get('hint', '')}"
            ).strip(),
            "rule_key": f"frihet:{operation}",
        }
    # Unknown operation: be conservative and escalate to human approval.
    # Hermes's gate defaults to a prompt, which is the right default for
    # "the plugin can't prove this is safe".
    return {
        "action": "approve",
        "message": (
            f"Frihet MCP operation `{operation}` is not in the plugin's "
            f"safety table. Defaulting to human approval."
        ),
        "rule_key": f"frihet:unknown:{operation}",
    }


# ─── MCP liveness probe ─────────────────────────────────────────────────────


def _build_initialize_request(url: str) -> urllib.request.Request:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        },
    }
    key = api_key()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )


def _parse_sse_or_json(body: str) -> dict[str, Any]:
    """Parse either an MCP JSON response or an SSE stream carrying one."""
    body = body.strip()
    if not body:
        raise ValueError("empty response body")
    if body.startswith("{"):
        return json.loads(body)
    # SSE: events separated by blank lines; each event has ``data: <json>``.
    for chunk in body.split("\n\n"):
        for line in chunk.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    return json.loads(payload)
    raise ValueError("no JSON payload found in response")


def probe_mcp(
    *,
    url: str | None = None,
    timeout: float | None = None,
    opener: Callable[[urllib.request.Request, float], Any] | None = None,
) -> dict[str, Any]:
    """Send an MCP ``initialize`` and surface the MCP server's ``serverInfo``.

    Read-only: the ``initialize`` handshake never mutates Frihet state. The
    probe verifies that:

    * the endpoint URL is reachable,
    * the API key (if configured) authenticates successfully,
    * the server speaks a recognisable MCP shape.

    Parameters
    ----------
    url, timeout:
        Override the configured endpoint and timeout. Used by tests.
    opener:
        Replace ``urlopen`` for tests (avoids any real network call).
    """
    target = (url or mcp_url()).strip() or DEFAULT_MCP_URL
    seconds = timeout if timeout is not None else timeout_seconds()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {
            "success": False,
            "error": "malformed_url",
            "url": redact(target),
            "hint": "FRIHET_MCP_URL must be a full https:// URL.",
        }
    request = _build_initialize_request(target)
    open_fn = opener or urllib.request.urlopen
    started = time.monotonic()
    try:
        with open_fn(request, seconds) as response:  # type: ignore[arg-type]
            raw = response.read().decode("utf-8", errors="replace")
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        elapsed = round((time.monotonic() - started) * 1000)
        if exc.code in (401, 403):
            return {
                "success": False,
                "error": "mcp_unauthorized",
                "url": redact(target),
                "status": exc.code,
                "elapsed_ms": elapsed,
                "hint": (
                    "FRIHET_API_KEY is missing or rejected. Generate one at "
                    "https://app.frihet.io/settings/api and store it in "
                    "your Hermes secret directory."
                ),
            }
        return {
            "success": False,
            "error": "mcp_http_error",
            "url": redact(target),
            "status": exc.code,
            "elapsed_ms": elapsed,
        }
    except urllib.error.URLError as exc:
        elapsed = round((time.monotonic() - started) * 1000)
        reason = getattr(exc, "reason", "")
        return {
            "success": False,
            "error": "mcp_unreachable",
            "url": redact(target),
            "elapsed_ms": elapsed,
            "reason": redact(str(reason)),
            "hint": (
                "Cannot reach the Frihet MCP endpoint. Check your network "
                "and that https://mcp.frihet.io/mcp is not blocked by a "
                "firewall or proxy."
            ),
        }
    except TimeoutError:
        return {
            "success": False,
            "error": "mcp_timeout",
            "url": redact(target),
            "timeout_s": seconds,
            "hint": (
                "The MCP probe exceeded the configured timeout. Increase "
                "FRIHET_MCP_TIMEOUT_SECONDS or check your network latency."
            ),
        }
    elapsed = round((time.monotonic() - started) * 1000)
    try:
        parsed_body = _parse_sse_or_json(raw)
    except (ValueError, json.JSONDecodeError):
        return {
            "success": False,
            "error": "malformed_response",
            "url": redact(target),
            "elapsed_ms": elapsed,
            "preview": redact(raw[:200]),
        }
    server_info = (parsed_body.get("result") or {}).get("serverInfo") or {}
    protocol = (parsed_body.get("result") or {}).get("protocolVersion") or ""
    return {
        "success": True,
        "url": redact(target),
        "elapsed_ms": elapsed,
        "status": status,
        "server": {
            "name": str(server_info.get("name") or ""),
            "version": str(server_info.get("version") or ""),
            "protocol_version": protocol,
        },
    }


# ─── High-level commands (consumed by ``__init__.py``) ─────────────────────


def status() -> dict[str, Any]:
    """Read-only snapshot of plugin state — never calls the network."""
    key_present = bool(api_key())
    target = mcp_url()
    parsed = urlparse(target)
    return {
        "success": True,
        "plugin": {"name": "frihet", "version": CLIENT_VERSION},
        "mcp": {
            "url": target,
            "is_canonical": target.rstrip("/") == DEFAULT_MCP_URL.rstrip("/"),
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "timeout_seconds": timeout_seconds(),
        },
        "auth": {
            "api_key_configured": key_present,
            "api_key_source": "env" if key_present else "missing",
        },
        "safety": {
            "irreversible_patterns": list(IRREVERSIBLE_PATTERNS),
            "draft_first_operations": list(DRAFT_FIRST_OPERATIONS),
        },
    }


def doctor(
    *,
    url: str | None = None,
    timeout: float | None = None,
    opener: Callable[[urllib.request.Request, float], Any] | None = None,
) -> dict[str, Any]:
    """Run the liveness probe and return a structured report.

    Combines :func:`status` with :func:`probe_mcp` so a single ``/frihet
    doctor`` call answers "is the plugin configured AND can it talk to
    Frihet right now?".

    The probe is ALWAYS run. When ``FRIHET_API_KEY`` is unset we send the
    handshake without an Authorization header — the canonical Frihet MCP may
    answer (demo mode, OAuth discovery probe) or reject with 401, and either
    outcome is information the user needs.
    """
    snapshot = status()
    snapshot["probe"] = probe_mcp(url=url, timeout=timeout, opener=opener)
    snapshot["ok"] = bool(snapshot["probe"].get("success"))
    return snapshot


def setup(
    *,
    api_key_value: str | None = None,
    opener: Callable[[urllib.request.Request, float], Any] | None = None,
    url: str | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Validate a candidate API key without storing it.

    The plugin does NOT write secrets to disk. ``setup`` is a guided
    *validation* step: the caller (typically the ``/frihet setup`` slash
    command) is expected to persist the value into the user's Hermes secret
    directory using the host's public APIs (``hermes auth add`` for example,
    or the ``mcp_servers.frihet.env`` block). This function returns whether
    the candidate key authenticates, and what scope/name it has, so the
    operator can decide where to persist it.

    Parameters
    ----------
    api_key_value:
        A candidate key. If ``None``, ``setup`` checks the currently
        configured key. Never echoed in the response.
    opener, url, timeout:
        Forwarded to :func:`probe_mcp` for testing.
    """
    original = api_key()
    try:
        if api_key_value:
            os.environ["FRIHET_API_KEY"] = api_key_value
        report = probe_mcp(opener=opener, url=url, timeout=timeout)
    finally:
        # Restore the prior value even if validation raised.
        if api_key_value:
            if original:
                os.environ["FRIHET_API_KEY"] = original
            else:
                os.environ.pop("FRIHET_API_KEY", None)
    if not report.get("success"):
        return {
            "success": False,
            "error": report.get("error", "unknown"),
            "hint": report.get("hint", ""),
        }
    server = (report.get("server") or {})
    return {
        "success": True,
        "validated": True,
        "server": server,
        "endpoint": report.get("url"),
        "next_step": (
            "Persist the API key in your Hermes secret directory and "
            "add the MCP server block below to your config.yaml:\n"
            "\n"
            "  mcp_servers:\n"
            "    frihet:\n"
            "      url: https://mcp.frihet.io/mcp\n"
            "      auth: api_key   # or `oauth` if you prefer the OAuth flow\n"
            "      env:\n"
            "        FRIHET_API_KEY: ${FRIHET_API_KEY}\n"
        ),
    }


def to_json(payload: Any) -> str:
    """Render a dict result as pretty JSON suitable for slash-command output."""
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)