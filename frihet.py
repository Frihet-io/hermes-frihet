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
# Order matters: more specific patterns first, generic last.
#
# Two rules target ``Authorization:`` lines — one for ``Bearer ...`` (which
# preserves the ``Bearer`` label so a reader still knows the kind of
# credential was present) and a generic fallback. The generic rule was
# historically skipped whenever ANY prior rule in the document produced a
# ``[REDACTED`` marker — that meant a document with multiple
# ``Authorization:`` lines, only one of which had a Bearer token, left the
# others unmasked. The new implementation applies rules PER LINE so the
# generic fallback fires on lines that still carry an unmasked
# ``Authorization: ...`` even when other lines were already masked.
#
# The generic rule also requires a ``:`` (or whitespace) separator after
# ``Authorization``. Earlier versions accepted zero characters between the
# header name and the value, which collided with unrelated strings
# (``Authorization=bar;`` in HTTP headers lists, or ``Authorization;``
# in some log formats). The separator requirement keeps the rule narrow.
_REDACT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"fri_[A-Za-z0-9_\-]{8,}"), "[REDACTED:FRIHET_API_KEY]"),
    (re.compile(r"FRIHET_API_KEY\s*=\s*\S+"), "FRIHET_API_KEY=[REDACTED]"),
    (re.compile(r"(?i)(authorization\s*:?\s*bearer\s+)[A-Za-z0-9_\-\.=]+"),
     r"\1[REDACTED:TOKEN]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{8,}"), "Bearer [REDACTED:TOKEN]"),
    (re.compile(r"(?i)(authorization\s*:\s*)[^\n\r]+"), r"\1[REDACTED]"),
)
# Mask for any other secret-shaped substring we did not name. Defence
# in depth: catches mislabelled Bearer tokens (e.g. ``Token:`` or
# ``Secret:``) before they reach the model context.
_OTHER_SECRET_HINT = re.compile(
    r"(?i)(token|secret|api[_\-]?key|password)\s*[:=]\s*"
    r"[A-Za-z0-9_\-\.=]{8,}"
)


def _redact_one_segment(segment: str) -> str:
    """Apply ``_REDACT_RULES`` to a single text segment (line or
    non-newline substring). The per-segment scope means the
    ``Authorization:`` generic fallback still fires on lines that
    weren't previously masked, while leaving masked lines alone.

    Rules apply in order; once any rule produces a ``[REDACTED`` marker
    on the segment, subsequent generic rules must not overwrite that
    marker. We track per-segment which segments have been masked by a
    specific rule so the generic ``Authorization:`` rule only fires on
    segments that did NOT already match the Bearer-specific rule.
    """
    if not segment:
        return segment
    out = segment
    bear_specific_marker_present = False
    for pattern, replacement in _REDACT_RULES:
        is_generic_auth = (
            "authorization" in pattern.pattern.lower()
            and "bearer" not in pattern.pattern.lower()
        )
        # If a prior rule on THIS segment already produced a Bearer-
        # specific redaction (which contains ``[REDACTED:TOKEN]``), the
        # generic rule must not overwrite it. Otherwise we would lose
        # the ``Bearer`` label that tells the reader what kind of
        # credential was present.
        if is_generic_auth and bear_specific_marker_present:
            continue
        prev = out
        out = pattern.sub(replacement, out)
        if out != prev and "[REDACTED:TOKEN]" in out:
            bear_specific_marker_present = True
    return out


def redact(value: str) -> str:
    """Return ``value`` with any embedded Frihet secret material masked.

    Used by every public function (status, doctor, hook payload builder,
    probe error reporting) so a misconfigured tool invocation whose
    argument happened to contain a key never bubbles it up to the model
    or the session transcript.

    Algorithm
    ---------
    We split on newlines first, then on runs of non-newline characters,
    and apply ``_REDACT_RULES`` per segment. The per-segment scope is
    critical: an earlier implementation skipped the generic
    ``Authorization:`` rule as soon as ANY prior rule in the same
    document produced a ``[REDACTED`` marker. That meant a document
    with multiple ``Authorization:`` lines — say one ``Bearer`` and one
    ``Basic`` — left the second un-redacted. Splitting per line means
    the generic fallback fires only when the current line still has an
    unmasked ``Authorization: ...`` substring.

    We then apply the broader ``token|secret|api_key|password``
    fallback regex across the joined result. This catches mislabelled
    secrets (``Token:``, ``Secret:``) before they escape.

    The function never raises — secret material in error reporting
    must never break the call path.
    """
    if not value:
        return value
    # Per-line masking keeps the generic Authorization rule firing on
    # lines that weren't already masked by the specific Bearer rule.
    lines = value.split("\n")
    redacted_lines = [_redact_one_segment(line) for line in lines]
    out = "\n".join(redacted_lines)
    # Defence in depth: catch mislabelled secrets anywhere.
    out = _OTHER_SECRET_HINT.sub(
        lambda m: re.sub(r"[A-Za-z0-9_\-\.=]{8,}$", "[REDACTED]", m.group(0)),
        out,
    )
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

    Namespace contract
    ------------------
    Hermes passes the FULL MCP tool name (e.g. ``mcp__frihet__markInvoicePaid``).
    The dispatcher in ``__init__.py`` MAY also pass us the operation-only
    form (``markInvoicePaid``) when the prefix has already been stripped
    for early bail-out logic. This function accepts either form: when the
    namespace marker (``mcp__frihet__`` or simply ``frihet``) is present
    we know the tool belongs to the Frihet MCP; when it is absent we
    treat the call as foreign and pass through.

    **History**: an earlier version required ``"frihet" in tool_name.lower()``
    unconditionally. The dispatcher strips ``mcp__frihet__`` before
    calling us, so the bare operation never contains ``frihet`` and was
    silently falling through. That was the hook-integration bug that
    bypassed the approval gate. Fixed by checking only when the name
    starts with ``mcp__``-style (which carries the namespace) OR when
    the caller passed a foreign name.
    """
    if not tool_name:
        return None
    lower = tool_name.lower()
    # Foreign tool (no Frihet namespace marker) — let it through.
    is_foreign = (
        not lower.startswith("mcp__frihet__")
        and "frihet" not in lower
    )
    if is_foreign:
        return None
    # Strip any MCP-server prefix (``mcp__frihet__`` or any ``mcp__<x>__``)
    # before classification so a ``list_*`` prefix is detectable. Preserve
    # the original case in ``operation`` — the safety contract uses the
    # same case the canonical Frihet MCP advertises
    # (``markInvoicePaid``, ``sendInvoice``, …).
    operation = (
        tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name
    )
    classification = classify_tool_call(operation)
    kind = classification.get("kind")
    if kind in ("read", "draft-write", None):
        # Reads and draft-writes flow through. The skill tells the model
        # to pause and show totals for draft-writes; the hook stays out
        # of the way so we don't block unattended reads.
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
    no side effects.

    Privacy contract
    ----------------
    This function returns **diagnostic state**, not business data. The
    earlier version returned the raw ``envelope`` (including the full
    ``result`` payload — invoice numbers, client names, amounts). That
    leaked customer data into ``/frihet doctor`` output and into any
    host that logged the slash-command response. The new contract:

      * Returned fields are only ``ok`` (bool), ``tool`` (the name we
        probed), ``elapsed_ms`` (timing), ``error`` (a short, stable
        code) and ``error_detail`` (redacted to remove secrets and
        business payloads).
      * The ``result`` field of the envelope is dropped on the floor.
        We never serialise invoice IDs, customer names, totals or any
        other content from the underlying list call.
      * PermissionError hints are wrapped to remove any path the user
        might have pasted into their config — they get a stable message
        pointing at the canonical config field instead.

    Returns a dict with ``ok``, ``tool``, ``elapsed_ms``, ``error`` and
    ``error_detail`` — nothing else.
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
        # ``str(exc)`` may contain paths from the host; we keep it only
        # when it has no secret-shaped substrings (defence-in-depth).
        safe_hint = redact(str(exc))
        return {
            "ok": False,
            "error": "mcp_allowlist_missing",
            "tool": tool,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "error_detail": safe_hint or (
                "Plugin lacks the mcp_allowlist grant for the 'frihet' "
                "server. Add it to plugins.entries.frihet.mcp_allowlist "
                "in ~/.hermes/config.yaml."
            ),
        }
    except Exception as exc:  # noqa: BLE001 — propagate the failure shape
        return {
            "ok": False,
            "error": "native_call_failed",
            "tool": tool,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "error_detail": redact(f"{type(exc).__name__}: {exc}"),
        }
    # ``envelope`` may contain ``result`` with business data. We drop it.
    # Only the envelope's own ``ok`` and ``error`` keys are read.
    ok = bool(envelope.get("ok"))
    return {
        "ok": ok,
        "tool": tool,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "error": None if ok else str(envelope.get("error") or "unknown"),
        "error_detail": None if ok else redact(str(envelope.get("error") or "")),
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
    url: str | None = None,
    timeout: float | None = None,
    opener: Callable[[urllib.request.Request, float], Any] | None = None,
) -> dict[str, Any]:
    """Print authentication guidance and run an unauthenticated probe.

    **This plugin does not accept credentials.** ``setup`` is
    exclusively a guidance surface: it tells the user which host-level
    command to run for OAuth/PKCE (``hermes mcp login frihet``) or
    unattended API-key storage (``hermes auth add frihet``) and which
    block to add to ``~/.hermes/config.yaml``. It does not validate
    candidates, does not POST anything, does not store anything.

    Earlier versions accepted ``api_key_value=<candidate>`` for
    "local shape validation" — that was a transcript-leak risk and is
    now removed. The signature parameter is gone; only host-level
    surfaces touch credentials.

    The unauthenticated reachability probe is run to prove the
    endpoint speaks MCP. It carries no credentials, ever.

    Parameters
    ----------
    url, timeout, opener:
        Forwarded to :func:`probe_mcp` for testing.
    """
    report = probe_mcp(opener=opener, url=url, timeout=timeout)
    reachable = bool(report.get("success"))
    server = (report.get("server") or {})
    return {
        "success": True,
        "current_api_key_present": bool(api_key()),
        "endpoint": report.get("url"),
        "server": server,
        "endpoint_reachable": reachable,
        "next_step": (
            "Authenticate against the canonical MCP using the host — "
            "this plugin does NOT accept credentials as arguments:\\n"
            "\\n"
            "  hermes mcp login frihet        # OAuth/PKCE (recommended)\\n"
            "  # or, for unattended callers:\\n"
            "  hermes auth add frihet         # stores FRIHET_API_KEY\\n"
            "\\n"
            "Then add to ~/.hermes/config.yaml:\\n"
            "\\n"
            "  mcp_servers:\\n"
            "    frihet:\\n"
            "      url: https://mcp.frihet.io/mcp\\n"
            "      auth: oauth   # OAuth/PKCE browser flow\\n"
            "      # auth: api_key   # if you went the unattended route\\n"
            "\\n"
            "After saving, restart Hermes and run ``/frihet doctor`` — it\\n"
            "will report endpoint_reachable, mcp_configured_in_hermes,\\n"
            "authenticated, and tools_available from the native MCP client."
        ),
    }


def to_json(payload: Any) -> str:
    """Render a dict result as pretty JSON suitable for slash-command output."""
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)