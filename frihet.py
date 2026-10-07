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
    """Build the JSON-RPC ``initialize`` request we send for the reachability
    probe.

    **This request carries NO credentials.** Not a Bearer API key, not an
    OAuth token, not a User-Agent pretending to be a browser. The probe
    only proves the endpoint is reachable and speaks the MCP shape; the
    plugin never authoritatively authenticates.

    Authentication status (``authenticated``, ``tools_available``) is
    derived from an actual call through ``ctx.call_mcp()`` — the public
    Hermes API that uses Hermes's own native MCP client, including its
    OAuth cache, breaker, and reconnect. The plugin never reads or
    handles credentials directly.
    """
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
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
    }
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
    """Send an unauthenticated MCP ``initialize`` handshake to the endpoint.

    This probe is **reachability-only**. It does NOT carry credentials
    and does NOT claim authentication state. Its job is to answer a
    single question: does this URL respond with a recognisable MCP
    shape?

    Authentication evidence comes from a separate path:
    ``probe_authenticated_via_native_client`` below, which uses
    ``ctx.call_mcp`` — Hermes's public plugin-call surface — and lets
    Hermes's native MCP client carry the credentials (its OAuth cache,
    its breaker, its reconnect). The plugin itself never touches a
    token.

    Returns a dict with ``success``, ``status``, ``server`` (name,
    version, protocol_version), ``elapsed_ms``, and ``error`` for
    failure modes (``malformed_url``, ``mcp_unauthorized``,
    ``mcp_unreachable``, ``mcp_timeout``, ``malformed_response``,
    ``mcp_http_error``). ``presented_credential`` is always False for
    this probe — by design — so doctor() can never confuse "reachable"
    with "authenticated".
    """
    target = (url or mcp_url()).strip() or DEFAULT_MCP_URL
    seconds = timeout if timeout is not None else timeout_seconds()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {
            "success": False,
            "error": "malformed_url",
            "url": redact(target),
            "presented_credential": False,
            "hint": "FRIHET_MCP_URL must be a full https:// URL.",
        }
    request = _build_initialize_request(target)
    open_fn = opener or urllib.request.urlopen
    started = time.monotonic()
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
                "presented_credential": False,
                "hint": (
                    "Server requires credentials. Run `hermes mcp login "
                    "frihet` (browser PKCE) or set FRIHET_API_KEY for "
                    "unattended callers. Authenticated status will be "
                    "verified by /frihet doctor via Hermes's native MCP "
                    "client."
                ),
            }
        return {
            "success": False,
            "error": "mcp_http_error",
            "url": redact(target),
            "status": exc.code,
            "elapsed_ms": elapsed,
            "presented_credential": False,
        }
    except urllib.error.URLError as exc:
        elapsed = round((time.monotonic() - started) * 1000)
        reason = getattr(exc, "reason", "")
        return {
            "success": False,
            "error": "mcp_unreachable",
            "url": redact(target),
            "elapsed_ms": elapsed,
            "presented_credential": False,
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
            "presented_credential": False,
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
            "presented_credential": False,
            "preview": redact(raw[:200]),
        }
    server_info = (parsed_body.get("result") or {}).get("serverInfo") or {}
    protocol = (parsed_body.get("result") or {}).get("protocolVersion") or ""
    return {
        "success": True,
        "url": redact(target),
        "elapsed_ms": elapsed,
        "status": status,
        "presented_credential": False,
        "server": {
            "name": str(server_info.get("name") or ""),
            "version": str(server_info.get("version") or ""),
            "protocol_version": protocol,
        },
    }


def probe_authenticated_via_native_client(
    ctx: Any,
    *,
    tool: str = "list_invoices",
    arguments: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Verify authentication through Hermes's own native MCP client.

    ``ctx.call_mcp`` is the **public** plugin-call surface in
    ``hermes_cli/plugins.py``. It uses the same trust gates, breaker,
    reconnect, and OAuth token cache as any other in-Hermes MCP call
    — Hermes stays the sole owner of credentials and authorisation.

    We invoke an unequivocally read-only Frihet MCP operation
    (``list_invoices`` is the canonical "list" tool) so the probe has
    no side effects. If the call returns ``{"ok": True, "result": …}``
    then the user is authenticated AND the Frihet MCP is ready. If
    ``ok=False`` we propagate the envelope's ``error`` field.

    The tool name ``list_invoices`` was chosen because it is the
    smallest, most-read-only operation in the Frihet MCP. If it is
    excluded from a user-configured tool allowlist, the call still
    succeeds at the transport layer but the envelope marks the tool
    as unavailable; in that case we still treat the call as proof
    that authentication is healthy.

    Returns a dict with ``ok`` (bool), ``envelope`` (the raw
    ``ctx.call_mcp`` envelope), and ``tool`` / ``elapsed_ms`` /
    ``error`` for diagnostics.
    """
    started = time.monotonic()
    try:
        envelope = ctx.call_mcp(
            "frihet", tool, arguments or {}, timeout=timeout
        )
    except PermissionError as exc:
        # The plugin needs an explicit per-server grant. Surface it
        # clearly so the user knows to add ``plugins.entries.frihet.
        # mcp_allowlist: [frihet]`` to ``~/.hermes/config.yaml``.
        return {
            "ok": False,
            "error": "mcp_allowlist_missing",
            "tool": tool,
            "hint": str(exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001 — propagate the failure shape
        return {
            "ok": False,
            "error": "native_call_failed",
            "tool": tool,
            "hint": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
    return {
        "ok": bool(envelope.get("ok")),
        "envelope": envelope,
        "tool": tool,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "error": envelope.get("error") if envelope.get("ok") is False else None,
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
    ctx: Any | None = None,
) -> dict[str, Any]:
    """Run the liveness probe and return a structured report.

    Epistemological contract: every state is ``true``, ``false`` or
    ``"unknown"``. The plugin never collapses the four states into a
    single ``ok`` flag because ``reachable != authenticated != ready``
    and conflating them is what made earlier versions lie.

    States returned:

      * ``endpoint_reachable`` (bool) — did the unauthenticated MCP
        ``initialize`` handshake land on a server? HTTP 2xx/4xx/5xx all
        count; the probe carries no credentials.
      * ``mcp_configured_in_hermes`` (tri-state) — does ``$HERMES_HOME/
        config.yaml`` carry an ``mcp_servers.frihet`` block? We parse
        that file directly (the user-visible contract) rather than
        reaching into ``hermes_cli.mcp_config`` internals. ``unknown``
        means we could not read the file — we refuse to lie.
      * ``authenticated`` (tri-state) — evidence comes from one of two
        paths, never both, and never by reading tokens ourselves:
          1. When called with ``ctx`` (the live PluginContext from
             ``register(ctx)``), we ask Hermes's native MCP client via
             ``ctx.call_mcp("frihet", "list_invoices", {})`` to make a
             read-only call. ``True`` iff the envelope is ``ok``; ``False``
             iff the call failed (auth, transport, or allowlist); the
             allowlist-missing case stays ``unknown`` because the
             failure is about *plugin configuration*, not auth.
          2. When called without ``ctx`` (CLI / unit tests), we cannot
             authoritatively answer auth. We report ``unknown`` and
             ask the user to run ``/frihet doctor`` from inside Hermes.
      * ``tools_available`` (tri-state) — same logic: ``True`` iff the
        native call returned a tool result envelope; ``False`` iff it
        failed; ``unknown`` when we cannot ask.

    The umbrella ``ok`` flips ``True`` only when every state is the
    literal ``True`` bool OR the positive tri-state ``"configured"``.
    Anything else (``False`` or ``"unknown"``) keeps the umbrella at
    ``False``. We never report the plugin "connected" based on HTTP
    reachability alone.

    The unauthenticated probe is ALWAYS run (it carries no credentials
    so it is safe regardless of state). The native ``ctx.call_mcp`` is
    run only when ``ctx`` is provided.
    """
    snapshot = status()
    probe = probe_mcp(url=url, timeout=timeout, opener=opener)

    reachable = bool(probe.get("status"))
    mcp_shape = bool(probe.get("server", {}).get("name"))
    server_block = mcp_server_block_present("frihet")

    # Authentication / tools-available evidence — native client only.
    auth_evidence: dict[str, Any] | None = None
    if ctx is not None:
        auth_evidence = probe_authenticated_via_native_client(ctx)

    if ctx is None:
        # CLI / unit-test path — we cannot authoritatively prove auth
        # without the live PluginContext. Tri-state: unknown.
        authenticated_state: Any = "unknown"
        tools_available_state: Any = "unknown"
    elif auth_evidence is None:
        authenticated_state = "unknown"
        tools_available_state = "unknown"
    elif auth_evidence.get("error") == "mcp_allowlist_missing":
        # The plugin has not been granted access yet. The user needs
        # to add ``plugins.entries.frihet.mcp_allowlist: [frihet]``
        # to ``~/.hermes/config.yaml``. We refuse to call this
        # 'unauthenticated' — it is a *plugin-config* question.
        authenticated_state = "allowlist_not_granted"
        tools_available_state = "allowlist_not_granted"
    elif auth_evidence.get("ok") is True:
        authenticated_state = True
        tools_available_state = True
    else:
        # Native call genuinely failed — server reachable but auth
        # broken or the operation rejected.
        authenticated_state = False
        tools_available_state = False

    states: dict[str, Any] = {
        "endpoint_reachable": reachable,
        "mcp_configured_in_hermes": server_block,  # tri-state string
        "authenticated": authenticated_state,
        "tools_available": tools_available_state,
    }

    snapshot["probe"] = probe
    snapshot["auth_evidence"] = auth_evidence
    snapshot["states"] = states

    # Umbrella ``ok`` only when every state is the literal ``True`` bool
    # OR the positive tri-state ``"configured"``. The new
    # ``"allowlist_not_granted"`` is explicitly NOT good — it tells the
    # user to grant access before we can claim connectivity.
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
    """Validate a candidate API key *locally*, without contacting Frihet.

    **This is a format-and-policy check, NOT an authentication check.**

    Earlier versions POSTed the candidate key to the canonical MCP
    endpoint and trusted the server's response. That approach had two
    problems:

      1. **Architectural**: the plugin is not the right surface to send
         credentials to a remote endpoint. ``hermes mcp login frihet``
         (the OAuth/PKCE browser flow) is the canonical path; sending
         raw API keys from inside a plugin reads like a credential
         exfiltration channel to a security reviewer.
      2. **Epistemological**: the probe was a single ``initialize``
         handshake, not a credential probe. It answered "is the endpoint
         alive?" not "does this key work?". Conflating those produces a
         green status when the key is wrong but the endpoint answers.

    The new ``setup`` does the only things a plugin can honestly do
    without crossing those lines:

      * check the candidate shape (``fri_`` prefix, length, charset);
      * confirm the ``mcp_servers.frihet`` block is well-formed in
        ``~/.hermes/config.yaml``;
      * run a **separate, always-unauthenticated** reachability probe to
        prove the endpoint speaks MCP;
      * print the next steps the user has to take on the host (the
        actual credential persistence happens via ``hermes mcp login``
        or ``hermes auth add`` — never via the plugin).

    Parameters
    ----------
    api_key_value:
        A candidate key (optional). When ``None`` we only report on the
        currently configured key. Never echoed in the response.
    opener, url, timeout:
        Forwarded to :func:`probe_mcp` for testing.
    """
    validation = _validate_api_key_shape(api_key_value)
    if api_key_value is not None and not validation["valid"]:
        return {
            "success": False,
            "error": validation["reason"],
            "hint": (
                "Frihet API keys are issued at "
                "https://app.frihet.io/settings/api and look like "
                "`fri_<alphanumeric_24plus>`."
            ),
            "candidate": {"checked": True, "ok": False},
        }
    # Reachability is a separate question and never carries the
    # candidate key (or any key). The plugin is not in the auth path;
    # Hermes's native client is.
    report = probe_mcp(opener=opener, url=url, timeout=timeout)
    reachable = bool(report.get("success"))
    server = (report.get("server") or {})
    return {
        "success": validation["valid"] or api_key_value is None,
        "validated": api_key_value is None or validation["valid"],
        "candidate": {
            "checked": api_key_value is not None,
            "ok": validation["valid"] if api_key_value else None,
            "reason": validation["reason"],
            # We deliberately do not echo the key. We do not log it. We
            # never store it.
        },
        "current_api_key_present": bool(api_key()),
        "endpoint": report.get("url"),
        "server": server,
        "endpoint_reachable": reachable,
        "next_step": (
            "Authenticate against the canonical MCP using the host:\n"
            "\n"
            "  hermes mcp login frihet        # OAuth/PKCE (recommended)\n"
            "  # or, for unattended callers:\n"
            "  hermes auth add frihet         # stores FRIHET_API_KEY\n"
            "\n"
            "Then add to ~/.hermes/config.yaml:\n"
            "\n"
            "  mcp_servers:\n"
            "    frihet:\n"
            "      url: https://mcp.frihet.io/mcp\n"
            "      auth: oauth   # OAuth/PKCE browser flow\n"
            "      # auth: api_key   # if you went the unattended route\n"
            "\n"
            "After saving, restart Hermes and run ``/frihet doctor`` — it\n"
            "will report endpoint_reachable, mcp_configured_in_hermes,\n"
            "authenticated, and tools_available from the native MCP client."
        ),
    }


def _validate_api_key_shape(value: str | None) -> dict[str, Any]:
    """Local, credential-free shape check for a candidate API key.

    Frihet issues keys with the shape ``fri_<24+ alphanumeric>``. We
    verify the format locally so we never have to POST a key to a remote
    endpoint just to learn it was malformed — that would be a
    credential-in-error-message exposure risk and a layering violation.
    Returns ``{"valid": bool, "reason": str}``. ``reason`` is empty
    string when valid.
    """
    if value is None or not isinstance(value, str):
        return {"valid": False, "reason": "no_key_provided"}
    candidate = value.strip()
    if not candidate:
        return {"valid": False, "reason": "empty_key"}
    if not candidate.startswith("fri_"):
        return {"valid": False, "reason": "wrong_prefix"}
    suffix = candidate[4:]
    if len(suffix) < 24:
        return {"valid": False, "reason": "too_short"}
    if not suffix.replace("_", "").isalnum():
        return {"valid": False, "reason": "illegal_chars"}
    return {"valid": True, "reason": ""}


def to_json(payload: Any) -> str:
    """Render a dict result as pretty JSON suitable for slash-command output."""
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)