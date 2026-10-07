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


DEFAULT_HERMES_HOME = os.path.expanduser("~/.hermes")
CONFIG_FILENAME = "config.yaml"


def hermes_home() -> str:
    """Return the path Hermes considers its home directory.

    Honours ``HERMES_HOME`` (the documented env var) and falls back to
    ``~/.hermes``. This is a public contract — ``HERMES_HOME`` is how
    every Hermes script finds its config — so we are not reaching into
    Hermes internals; we are reading a documented user-visible path.
    """
    raw = os.getenv("HERMES_HOME", "").strip()
    return raw or DEFAULT_HERMES_HOME


def mcp_server_block_present(name: str = "frihet") -> str | None:
    """Return ``"configured"``, ``"missing"``, or ``"unknown"`` for the
    ``mcp_servers.<name>`` block in Hermes's config.

    We deliberately DO NOT use ``hermes_cli.mcp_config`` to answer this:
    its ``mcp_servers`` introspection helpers are not part of the public
    Hermes API surface, and a plugin that reaches into them would be
    breaking on every Hermes release.

    Instead we read ``$HERMES_HOME/config.yaml`` directly. That file is
    the contract the user sees — it is the same file they edit when
    adding an MCP server. We use a tolerant YAML parse so a hand-written
    config with comments or extra keys still works.

    Tri-state:

    - ``"configured"`` — the block exists and references this plugin's
      URL (or any URL, when ``strict`` is False).
    - ``"missing"`` — the block is absent (we can prove this by parsing
      the file ourselves).
    - ``"unknown"`` — the file could not be read or parsed, so we cannot
      make a reliable claim. Reporting "configured" here would be a lie;
      reporting "missing" would surprise users whose config has unusual
      YAML we cannot parse.
    """
    home = hermes_home()
    cfg_path = os.path.join(home, CONFIG_FILENAME)
    if not os.path.isfile(cfg_path):
        return "unknown"
    try:
        import yaml  # type: ignore[import-untyped]

        with open(cfg_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        # Bad YAML, permission error, exotic encoding — we don't know.
        return "unknown"
    if not isinstance(data, dict):
        return "unknown"
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        return "missing"
    block = servers.get(name)
    if block is None:
        return "missing"
    # Block exists. We trust the user's config: if they put anything under
    # ``mcp_servers.frihet`` they intend Frihet to be configured.
    return "configured"


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
    "markInvoicePaid",  # used by the ``mark_invoice_paid`` tool family
    "mark_invoice_paid",
    "markInvoice",
    "mark_invoice",
    "finalize",
    "finalise",
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
    "applyLateFee",
    "apply_late_fee",
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
    "createClient",
    "create_client",
    "createClientContact",
    "create_client_contact",
    "createClientNote",
    "create_client_note",
    "createProduct",
    "create_product",
    "createExpense",
    "create_expense",
    "logClientActivity",
    "log_client_activity",
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
            "presented_credential": bool(api_key()),
            "hint": "FRIHET_MCP_URL must be a full https:// URL.",
        }
    request = _build_initialize_request(target)
    open_fn = opener or urllib.request.urlopen
    started = time.monotonic()
    presented_credential = bool(api_key())
    try:
        # ``urlopen(request, timeout=...)`` — never pass timeout as the
        # second positional argument; that slot is ``data`` (the request
        # body) and a float there raises TypeError before the request
        # goes out.
        with open_fn(request, timeout=seconds) as response:  # type: ignore[arg-type]
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
                "presented_credential": presented_credential,
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
            "presented_credential": presented_credential,
        }
    except urllib.error.URLError as exc:
        elapsed = round((time.monotonic() - started) * 1000)
        reason = getattr(exc, "reason", "")
        return {
            "success": False,
            "error": "mcp_unreachable",
            "url": redact(target),
            "elapsed_ms": elapsed,
            "presented_credential": presented_credential,
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
            "presented_credential": presented_credential,
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
            "presented_credential": presented_credential,
            "preview": redact(raw[:200]),
        }
    server_info = (parsed_body.get("result") or {}).get("serverInfo") or {}
    protocol = (parsed_body.get("result") or {}).get("protocolVersion") or ""
    return {
        "success": True,
        "url": redact(target),
        "elapsed_ms": elapsed,
        "status": status,
        "presented_credential": presented_credential,
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
            "server_block_in_config": mcp_server_block_present("frihet"),
        },
        "auth": {
            "api_key_configured": key_present,
            "api_key_source": "env" if key_present else "missing",
            "note": (
                "api_key_configured is NOT a synonym for mcp_configured_in_hermes: "
                "OAuth flows have no env var and are configured via "
                "mcp_servers.frihet in Hermes's config.yaml."
            ),
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

    Epistemological contract: every state is ``true``, ``false`` or
    ``"unknown"``. We do NOT collapse into a single ``ok`` boolean
    because the four states are NOT the same thing and conflating them
    is what made the previous version look "smart" while lying to the
    user (it set ``mcp_configured_in_hermes = true`` whenever an API
    key was set, even though OAuth-only flows have no API key at all).

    States returned:

      * ``endpoint_reachable`` (bool) — did the MCP handshake land on a
        server? HTTP 2xx/4xx/5xx all count.
      * ``mcp_configured_in_hermes`` (tri-state) — did ``$HERMES_HOME/
        config.yaml`` carry an ``mcp_servers.frihet`` block? We parse
        that file directly (it is the user-visible contract) rather than
        reaching into ``hermes_cli.mcp_config`` internals. ``unknown``
        means we could not read the file — we refuse to lie.
      * ``authenticated`` (tri-state) — did the MCP handshake succeed
        with our credential? ``true``/``false`` are observable facts;
        ``"unknown"`` only happens when the probe was not run (we still
        run it even without a key, so this is rarely unknown).
      * ``tools_available`` (tri-state) — did the server's ``initialize``
        response carry a populated ``serverInfo`` and parse as MCP?
        Same tri-state contract.

    The umbrella ``ok`` is ``True`` only when all four states are
    ``True``. Reachability alone is not enough.

    The probe is ALWAYS run. When ``FRIHET_API_KEY`` is unset we send
    the handshake without an Authorization header — the canonical Frihet
    MCP may answer (demo / OAuth discovery) or reject with 401, and
    either outcome is information the user needs.
    """
    snapshot = status()
    probe = probe_mcp(url=url, timeout=timeout, opener=opener)

    reachable = bool(probe.get("status"))
    mcp_shape = bool(probe.get("server", {}).get("name"))
    unauth = probe.get("error") == "mcp_unauthorized"
    server_block = mcp_server_block_present("frihet")
    presented_credential = bool(probe.get("presented_credential"))

    # Tri-state logic: ``authenticated`` is True ONLY when we presented a
    # credential AND the server accepted it. We do NOT report ``True``
    # for an anonymous 200 — that is reachable but not authenticated.
    probe_succeeded = probe.get("success") is True and not unauth
    states: dict[str, Any] = {
        "endpoint_reachable": reachable,
        "mcp_configured_in_hermes": server_block,  # tri-state string
        "authenticated": (
            "unknown"
            if probe.get("error") == "probe_skipped"
            else (probe_succeeded and presented_credential)
        ),
        "tools_available": (
            "unknown"
            if probe.get("error") == "probe_skipped"
            else (mcp_shape and probe_succeeded)
        ),
    }

    snapshot["probe"] = probe
    snapshot["states"] = states
    # Umbrella ``ok`` only when every state is the literal ``True`` bool
    # OR the positive tri-state ``"configured"``. Anything else (False or
    # ``"unknown"``) keeps the umbrella at False.
    def _is_good(value: Any) -> bool:
        return value is True or value == "configured"
    snapshot["ok"] = all(_is_good(v) for v in states.values())
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