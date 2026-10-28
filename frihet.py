"""Frihet integration helpers for the Hermes Agent plugin.

This module is intentionally small and stdlib-only. It does NOT register
duplicate Frihet tools — the canonical Frihet MCP surface
lives in the official ``@frihet/mcp-server`` and the remote endpoint at
``https://mcp.frihet.io/mcp``. What this module provides:

* ``status`` — read-only snapshot of plugin config and MCP endpoint reachability.
* ``setup`` — guided writing of ``FRIHET_API_KEY`` into the user's Hermes
  secret directory (never ``config.yaml``; never stdout).
* ``doctor`` — liveness check that exercises the MCP ``initialize`` handshake
  using a deliberately non-destructive probe.
* ``brief`` — read-only Daily/Weekly Operational Business Brief answering
  *"¿Qué debería revisar hoy en mi negocio y por qué?"* (due dates, pending
  collections, expiring quotes, expenses to review, CRM follow-ups, and
  suggested actions gated by human approval).
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
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

# ─── Canonical surface (single source of truth) ──────────────────────────────

DEFAULT_MCP_URL = "https://mcp.frihet.io/mcp"
DEFAULT_TIMEOUT_SECONDS = 10
PROTOCOL_VERSION = "2025-06-18"  # MCP protocol version we speak.
CLIENT_NAME = "hermes-frihet-plugin"
CLIENT_VERSION = "0.2.2"

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
    "createReservation",
    "create_reservation",
    "createRecurringInvoice",
    "create_recurring_invoice",
    "createDeposit",
    "create_deposit",
    "createVendor",
    "create_vendor",
)

# Read-only tools whose names do not start with a read verb. Exact names
# only: each one is declared with ``READ_ONLY_ANNOTATIONS`` in
# Frihet-io/frihet-mcp (``anomaly_list``: src/tools/hr.ts).
READ_ONLY_TOOLS: frozenset[str] = frozenset({"anomaly_list"})


# ─── Canonical Frihet safety contract (vendor source of truth) ─────────────
# The Frihet MCP publishes its own authoritative safety contract at
# ``docs/agent-onboarding.json``. The plugin vendors a frozen copy of
# that contract and uses it as the source of truth for
# ``externalSideEffects`` classification. This is more reliable than
# guessing from operation names alone: the Frihet server's
# ``_meta["io.frihet/capability"]`` declares that ``create_client``
# has a ``webhook_delivery_or_configuration`` effect even though the
# verb is "create".
#
# We load the JSON lazily and tolerate missing/malformed files by
# falling back to the conservative name-pattern lists above. The
# plugin NEVER fails because of a missing vendor file — it just
# becomes a stricter classifier.
_ONBOARDING_JSON_PATH = (
    Path(__file__).resolve().parent / "vendor" / "frihet-mcp-onboarding.json"
)


def _load_external_side_effects() -> frozenset[str] | None:
    """Return the set of Frihet tool names declared as having
    ``externalSideEffects`` in the canonical onboarding contract, or
    ``None`` if the vendor file is missing / unreadable. The caller
    treats ``None`` as 'degrade gracefully to name-pattern rules'.
    """
    try:
        with _ONBOARDING_JSON_PATH.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    humanAuthority = data.get("humanAuthority") or {}
    entries = humanAuthority.get("externalSideEffects") or []
    if not isinstance(entries, list):
        return None
    out: set[str] = set()
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("tool"), str):
            out.add(entry["tool"])
    if not out:
        return None
    return frozenset(out)


_EXTERNAL_SIDE_EFFECTS_TOOLS: frozenset[str] | None = _load_external_side_effects()


def external_side_effects_tools() -> frozenset[str]:
    """Public accessor for the canonical ``externalSideEffects`` set.

    The classifier uses this to decide whether a Frihet operation
    should escalate to approval. Returning ``frozenset()`` (empty)
    means "vendor file missing — fall back to name patterns only".
    Returning a populated ``frozenset`` means "these tools have
    declared external effects, treat them as irreversible".

    Tests can monkeypatch this via ``_EXTERNAL_SIDE_EFFECTS_TOOLS``.
    """
    return _EXTERNAL_SIDE_EFFECTS_TOOLS or frozenset()


def classify_tool_call(tool_name: str) -> dict[str, Any]:
    """Classify a Frihet MCP tool name against the safety contract.

    Returns a dict with ``kind`` (``"read"`` | ``"draft-write"`` |
    ``"irreversible-write"`` | ``"unknown"``), and a ``hint`` carrying
    operating guidance.

    Source-of-truth ordering
    -----------------------

    The classification uses **two** sources of truth, applied in order:

      1. The canonical Frihet MCP contract
         (``vendor/frihet-mcp-onboarding.json`` —
         ``Frihet-io/frihet-mcp/docs/agent-onboarding.json``). If a tool
         is in ``humanAuthority.externalSideEffects`` it is treated as
         ``"irreversible-write"`` regardless of the verb in its name.
         This is the authoritative classifier: the Frihet server itself
         publishes this metadata, so a plugin reviewer can audit the
         decision.
      2. Local pattern lists (``IRREVERSIBLE_PATTERNS`` and
         ``DRAFT_FIRST_OPERATIONS``). These are belt-and-braces for
         tools the vendor file does not yet name, and they default to
         fail-closed when the operation shape is unknown.
    """
    if not tool_name:
        return {"kind": "unknown", "hint": "No tool name provided."}
    normalised = tool_name.lower()
    # Strip the ``mcp__<server>__`` prefix when present, to compare
    # against the canonical tool names in the contract.
    bare = tool_name.rsplit("__", 1)[-1] if "__" in tool_name else tool_name
    # 1. Canonical externalSideEffects — source of truth.
    canonical_external = external_side_effects_tools()
    if bare in canonical_external or bare.lower() in {n.lower() for n in canonical_external}:
        return {
            "kind": "irreversible-write",
            "hint": (
                f"Per the canonical Frihet MCP contract, `{bare}` has "
                f"declared externalSideEffects. Re-read the target, confirm "
                "human authorisation, honour any Idempotency-Key, and do "
                "NOT retry blindly."
            ),
            "source": "canonical_external_side_effects",
        }
    # 2. Local pattern fallback.
    if any(pat.lower() in normalised for pat in IRREVERSIBLE_PATTERNS):
        return {
            "kind": "irreversible-write",
            "hint": (
                "This Frihet operation produces an external effect "
                "(send, payment, VeriFactu, deletion). Re-read the "
                "target record, confirm the human authorised it, "
                "honour any Idempotency-Key, and do NOT retry blindly."
            ),
            "source": "name_pattern",
        }
    if any(pat.lower() in normalised for pat in DRAFT_FIRST_OPERATIONS):
        return {
            "kind": "draft-write",
            "hint": (
                "Prefer creating a draft first and presenting the "
                "totals for human approval before any send/mark-paid."
            ),
            "source": "name_pattern",
        }
    # Read-shape check uses the bare operation (post-prefix-strip), not
    # the full ``mcp__server__op`` string, otherwise ``mcp__frihet__
    # list_invoices`` would fail the startswith check. ``bare`` is
    # already defined earlier in this function.
    if bare.lower() in READ_ONLY_TOOLS or bare.lower().startswith(
        ("get", "list", "search", "describe", "schema", "fetch")
    ):
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


# ─── Daily / Weekly Operational Business Brief ──────────────────────────────

BRIEF_QUESTION_ES = "¿Qué debería revisar hoy en mi negocio y por qué?"
BRIEF_ORCHESTRATED_READ_TOOLS = (
    "get_business_context",
    "list_invoices",
    "list_quotes",
    "list_expenses",
    "list_clients",
    "list_client_activities",
)
UNPAID_NOMINAL_LABEL_ES = (
    "Importe nominal de facturas no marcadas como pagadas "
    "(saldo pendiente real no determinable sin cobros parciales)"
)
UNPAID_NOMINAL_SEMANTICS = "nominal_unpaid_invoice_totals_without_partial_payments"
TEMPORAL_SCOPE_ID = "unfiltered_operational_sample_as_of_date"


def _round_currency(value: float) -> float:
    """Round half-up to 2 decimal places matching JS ``Math.round(v * 100) / 100``."""
    import math as _math

    return _math.floor(float(value) * 100.0 + 0.5) / 100.0


def _is_finite_number(value: Any) -> bool:
    """Return True if ``value`` is an int/float (excluding bool, NaN, inf)."""
    import math as _math

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and _math.isfinite(float(value))
    )


def _parse_iso_date_prefix(value: Any) -> tuple[int, int, int] | None:
    """Parse ``YYYY-MM-DD`` prefix into ``(year, month, day)`` or ``None``."""
    if not isinstance(value, str) or len(value) < 10:
        return None
    prefix = value[:10]
    parts = prefix.split("-")
    if len(parts) != 3:
        return None
    try:
        year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
        if not (1970 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
            return None
        return (year, month, day)
    except ValueError:
        return None


def _days_between_iso(start_iso: str, end_iso: str) -> int | None:
    """Return ``(end - start).days`` for two ``YYYY-MM-DD`` strings."""
    import datetime as _dt

    start_parts = _parse_iso_date_prefix(start_iso)
    end_parts = _parse_iso_date_prefix(end_iso)
    if not start_parts or not end_parts:
        return None
    try:
        start_d = _dt.date(*start_parts)
        end_d = _dt.date(*end_parts)
        return (end_d - start_d).days
    except ValueError:
        return None


def _is_in_period_month(date_str: Any, period_month: str) -> bool:
    """Return True if ``date_str`` starts with ``YYYY-MM`` equal to ``period_month``."""
    if not isinstance(date_str, str) or not isinstance(period_month, str):
        return False
    return len(date_str) >= 7 and date_str[:7] == period_month[:7]


def _compute_canonical_document_total(doc: dict[str, Any]) -> float | None:
    """Derive a document total from ``items[]`` using the canonical Frihet ERP formula.

    Applies line-level ``discount``, document-level ``discountRate``, ``taxRate``
    (or per-line ``taxRate``), ``equivalenceSurchargeRate``, and ``irpfRate``
    over the discounted tax-exclusive base. Fails closed (returns ``None``)
    when ``items`` is missing/empty or when unsupported calculation modifiers
    are present (``pricesIncludeTax=True``, ``deductLineDiscountAmounts=True``,
    non-empty ``compoundTaxes``, non-zero ``prepayment``, or non-zero line
    ``discountAmount``).
    """
    if not isinstance(doc, dict):
        return None
    raw_items = doc.get("items")
    if not isinstance(raw_items, list) or len(raw_items) == 0:
        return None

    if doc.get("pricesIncludeTax") is True or doc.get("deductLineDiscountAmounts") is True:
        return None
    compound_taxes = doc.get("compoundTaxes")
    if isinstance(compound_taxes, list) and len(compound_taxes) > 0:
        return None
    prepayment = doc.get("prepayment")
    if prepayment is not None and prepayment != 0:
        return None

    def _rate_or_zero(key: str) -> float | None:
        raw = doc.get(key)
        if raw is None:
            return 0.0
        if not _is_finite_number(raw):
            return None
        val = float(raw)
        if val < 0.0 or val > 100.0:
            return None
        return val

    doc_discount_pct = _rate_or_zero("discountRate")
    doc_tax_rate = _rate_or_zero("taxRate")
    doc_irpf_rate = _rate_or_zero("irpfRate")
    doc_surcharge_rate = _rate_or_zero("equivalenceSurchargeRate")
    if (
        doc_discount_pct is None
        or doc_tax_rate is None
        or doc_irpf_rate is None
        or doc_surcharge_rate is None
    ):
        return None

    base_by_rate: dict[float, float] = {}
    subtotal_before_discount = 0.0

    for item in raw_items:
        if not isinstance(item, dict):
            return None
        qty_raw = item.get("quantity")
        unit_price_raw = item.get("unitPrice")
        if not _is_finite_number(qty_raw) or not _is_finite_number(unit_price_raw):
            return None
        qty = float(qty_raw)
        unit_price = float(unit_price_raw)
        if qty < 0.0 or unit_price < 0.0:
            return None

        disc_amt = item.get("discountAmount")
        if disc_amt is not None and disc_amt != 0:
            return None

        line_disc_raw = item.get("discount")
        if line_disc_raw is None:
            line_discount_pct = 0.0
        elif _is_finite_number(line_disc_raw):
            line_discount_pct = float(line_disc_raw)
            if line_discount_pct < 0.0 or line_discount_pct > 100.0:
                return None
        else:
            return None

        line_tax_raw = item.get("taxRate")
        if line_tax_raw is None:
            effective_rate = doc_tax_rate
        elif _is_finite_number(line_tax_raw):
            effective_rate = float(line_tax_raw)
            if effective_rate < 0.0 or effective_rate > 100.0:
                return None
        else:
            return None

        effective_unit_price = _round_currency(
            unit_price * (1.0 - line_discount_pct / 100.0)
        )
        line_base = _round_currency(qty * effective_unit_price)
        base_by_rate[effective_rate] = _round_currency(
            base_by_rate.get(effective_rate, 0.0) + line_base
        )
        subtotal_before_discount = _round_currency(subtotal_before_discount + line_base)

    document_discount = _round_currency(
        subtotal_before_discount * (doc_discount_pct / 100.0)
    )
    subtotal = _round_currency(subtotal_before_discount - document_discount)

    discounted_base_by_rate: dict[float, float] = {}
    sorted_rates = sorted(base_by_rate.keys(), reverse=True)
    if doc_discount_pct > 0.0 and subtotal_before_discount > 0.0 and sorted_rates:
        discount_factor = 1.0 - doc_discount_pct / 100.0
        other_groups_total = 0.0
        for idx, rate in enumerate(sorted_rates):
            base = base_by_rate[rate]
            if idx < len(sorted_rates) - 1:
                discounted = _round_currency(base * discount_factor)
                discounted_base_by_rate[rate] = discounted
                other_groups_total = _round_currency(other_groups_total + discounted)
            else:
                discounted_base_by_rate[rate] = _round_currency(
                    subtotal - other_groups_total
                )
    else:
        for rate in sorted_rates:
            discounted_base_by_rate[rate] = base_by_rate[rate]

    total_tax = 0.0
    for rate, base in discounted_base_by_rate.items():
        tax = _round_currency(base * (rate / 100.0))
        total_tax = _round_currency(total_tax + tax)

    irpf = _round_currency(subtotal * (doc_irpf_rate / 100.0))
    surcharge = _round_currency(subtotal * (doc_surcharge_rate / 100.0))
    return _round_currency(subtotal + total_tax + surcharge - irpf)


def _resolve_doc_amount(
    record: dict[str, Any],
    default_currency: str = "EUR",
) -> dict[str, Any]:
    """Extract a provenanced amount from a document without fabricating totals.

    Enforces Rules 1 & 3 of the Canonical Monetary & Temporal Brief Contract:
    * Missing ``total``, ``amount``, and valid ``items`` -> ``amount=None``,
      ``provenance="unavailable"``, ``unavailableCount=1`` (never ``0.0``).
    * Stored numeric ``total`` or ``amount`` -> ``provenance="stored_field"``.
    * Canonical ``items[]`` derivation -> ``provenance="derived_from_items"``.
    """
    if not isinstance(record, dict):
        return {
            "amount": None,
            "currency": default_currency,
            "provenance": "unavailable",
            "amount_provenance": "unavailable",
            "fieldOrFormula": "missing:total|amount|supported_canonical_items",
            "unavailableCount": 1,
        }
    currency_raw = record.get("currency")
    currency = (
        str(currency_raw).strip().upper()
        if isinstance(currency_raw, str) and currency_raw.strip()
        else default_currency
    )
    if _is_finite_number(record.get("total")):
        return {
            "amount": _round_currency(float(record["total"])),
            "currency": currency,
            "provenance": "stored_field",
            "amount_provenance": "stored_field",
            "fieldOrFormula": "doc.total",
        }
    if _is_finite_number(record.get("amount")):
        return {
            "amount": _round_currency(float(record["amount"])),
            "currency": currency,
            "provenance": "stored_field",
            "amount_provenance": "stored_field",
            "fieldOrFormula": "doc.amount",
        }

    derived = _compute_canonical_document_total(record)
    if derived is not None:
        return {
            "amount": derived,
            "currency": currency,
            "provenance": "derived_from_items",
            "amount_provenance": "derived_from_items",
            "fieldOrFormula": (
                "canonical:round2(subtotal_after_line_and_doc_discount + tax + surcharge - irpf)"
            ),
        }

    return {
        "amount": None,
        "currency": currency,
        "provenance": "unavailable",
        "amount_provenance": "unavailable",
        "fieldOrFormula": "missing:total|amount|supported_canonical_items",
        "unavailableCount": 1,
    }


# Public & internal aliases for contract parity across tests and callers
resolve_document_amount = _resolve_doc_amount
_resolve_document_amount = _resolve_doc_amount


def _sum_provenanced_amounts(
    amounts: list[dict[str, Any]],
    default_currency: str = "EUR",
) -> dict[str, Any]:
    """Aggregate provenanced amounts without mixing currencies or treating None as 0.

    Enforces Rules 1 & 2 of the Canonical Monetary & Temporal Brief Contract:
    * Empty bucket -> ``amount=0``, ``provenance="stored_field"``, ``unavailableCount=0``.
    * Any ``unavailable`` / ``amount=None`` item -> bucket ``amount=None``,
      ``provenance="unavailable"``, ``unavailableCount >= 1``.
    * Multiple currencies -> ``amount=None``, ``currency="MIXED"``,
      ``provenance="mixed_currency_unconverted"``, ``totalsByCurrency`` populated.
    """
    if not amounts:
        return {
            "amount": 0,
            "currency": default_currency,
            "provenance": "stored_field",
            "amount_provenance": "stored_field",
            "fieldOrFormula": "sum(0 items)",
            "totalsByCurrency": {},
            "unavailableCount": 0,
        }

    totals_by_currency: dict[str, dict[str, Any]] = {}
    unavailable_count = 0
    any_derived = False

    for item in amounts:
        if not isinstance(item, dict):
            unavailable_count += 1
            continue
        amt = item.get("amount")
        prov = item.get("provenance") or item.get("amount_provenance")
        if amt is None or prov == "unavailable" or not _is_finite_number(amt):
            inc = item.get("unavailableCount")
            unavailable_count += int(inc) if isinstance(inc, int) and inc > 0 else 1
            continue

        curr = str(item.get("currency") or default_currency).strip().upper() or default_currency
        bucket = totals_by_currency.get(curr) or {
            "amount": 0.0,
            "count": 0,
            "provenance": "stored_field",
        }
        bucket["amount"] = _round_currency(float(bucket["amount"]) + float(amt))
        bucket["count"] = int(bucket["count"]) + 1
        if prov == "derived_from_items":
            bucket["provenance"] = "derived_from_items"
            any_derived = True
        totals_by_currency[curr] = bucket

    currencies = list(totals_by_currency.keys())

    if unavailable_count > 0:
        bucket_currency = (
            currencies[0]
            if len(currencies) == 1
            else ("MIXED" if len(currencies) > 1 else default_currency)
        )
        return {
            "amount": None,
            "currency": bucket_currency,
            "provenance": "unavailable",
            "amount_provenance": "unavailable",
            "fieldOrFormula": (
                f"unavailable({unavailable_count} of {len(amounts)} documents missing canonical amount)"
            ),
            "totalsByCurrency": totals_by_currency,
            "unavailableCount": unavailable_count,
        }

    if len(currencies) > 1:
        return {
            "amount": None,
            "currency": "MIXED",
            "provenance": "mixed_currency_unconverted",
            "amount_provenance": "mixed_currency_unconverted",
            "fieldOrFormula": (
                f"mixed_currencies({','.join(currencies)}):no_fx_conversion_applied"
            ),
            "totalsByCurrency": totals_by_currency,
            "unavailableCount": 0,
        }

    single_curr = currencies[0]
    single_bucket = totals_by_currency[single_curr]
    final_prov = "derived_from_items" if any_derived else "stored_field"
    return {
        "amount": single_bucket["amount"],
        "currency": single_curr,
        "provenance": final_prov,
        "amount_provenance": final_prov,
        "fieldOrFormula": f"sum({len(amounts)} items in {single_curr})",
        "totalsByCurrency": totals_by_currency,
        "unavailableCount": 0,
    }


sum_provenanced_amounts = _sum_provenanced_amounts


def _format_provenanced_amount(pa: dict[str, Any]) -> str:
    """Format a ``ProvenancedAmount`` dict for human-readable Markdown output."""
    prov = pa.get("provenance") or pa.get("amount_provenance")
    totals_by_curr = pa.get("totalsByCurrency") or {}
    if prov == "mixed_currency_unconverted" and isinstance(totals_by_curr, dict):
        parts = [
            f"{b['amount']:.2f} {curr} ({b['count']} doc(s), {b['provenance']})"
            for curr, b in totals_by_curr.items()
            if isinstance(b, dict) and _is_finite_number(b.get("amount"))
        ]
        return f"Multi-divisa sin convertir [{'; '.join(parts)}]"
    amt = pa.get("amount")
    if amt is None or prov == "unavailable" or not _is_finite_number(amt):
        partial_parts = [
            f"{b['amount']:.2f} {curr} ({b['count']} doc(s))"
            for curr, b in (totals_by_curr.items() if isinstance(totals_by_curr, dict) else [])
            if isinstance(b, dict) and _is_finite_number(b.get("amount"))
        ]
        partial_suffix = (
            f" — subtotal parcial verificado: {'; '.join(partial_parts)}"
            if partial_parts
            else ""
        )
        unavail_cnt = pa.get("unavailableCount") or 1
        return (
            f"No disponible ({unavail_cnt} doc(s) sin importe determinable "
            f"[{pa.get('fieldOrFormula', 'unavailable')}]{partial_suffix})"
        )
    return f"{float(amt):.2f} {pa.get('currency', 'EUR')} ({prov})"


format_provenanced_amount = _format_provenanced_amount


def _extract_mcp_payload(raw_response: Any) -> dict[str, Any]:
    """Normalise a ``ctx.call_mcp`` or ``client.callTool`` return value into ``{ok, data, error}``."""
    if not isinstance(raw_response, dict):
        return {
            "ok": False,
            "data": {},
            "error": redact(f"unexpected_mcp_response:{type(raw_response).__name__}"),
        }
    if raw_response.get("ok") is False or raw_response.get("isError") is True:
        err = raw_response.get("error")
        if not err and isinstance(raw_response.get("content"), list):
            for entry in raw_response["content"]:
                if isinstance(entry, dict) and isinstance(entry.get("text"), str):
                    err = entry["text"]
                    break
        return {"ok": False, "data": {}, "error": redact(str(err or "mcp_call_failed"))}

    payload: Any = raw_response.get("result", raw_response)
    if isinstance(payload, dict):
        if payload.get("isError") is True:
            err_text = "mcp_tool_error"
            if isinstance(payload.get("content"), list):
                for entry in payload["content"]:
                    if isinstance(entry, dict) and isinstance(entry.get("text"), str):
                        err_text = entry["text"]
                        break
            return {"ok": False, "data": {}, "error": redact(str(err_text))}
        if isinstance(payload.get("structuredContent"), dict):
            payload = payload["structuredContent"]
        elif isinstance(payload.get("content"), list):
            for entry in payload["content"]:
                if isinstance(entry, dict) and isinstance(entry.get("text"), str):
                    try:
                        parsed = json.loads(entry["text"])
                        if isinstance(parsed, dict):
                            payload = parsed
                            break
                    except ValueError:
                        pass
    if not isinstance(payload, dict):
        payload = {"data": payload}
    return {"ok": True, "data": payload, "error": None}


def _extract_list_and_total(
    payload: dict[str, Any],
    fallback_keys: tuple[str, ...],
) -> tuple[list[dict[str, Any]], int | None, bool]:
    """Return ``(items, total_available, is_truncated)`` from a paginated MCP response."""
    items_raw: Any = None
    for key in ("data", "items", *fallback_keys):
        candidate = payload.get(key)
        if isinstance(candidate, list):
            items_raw = candidate
            break
    if not isinstance(items_raw, list):
        items_raw = []
    items = [item for item in items_raw if isinstance(item, dict)]
    total_raw = payload.get("total")
    if total_raw is None:
        total_raw = payload.get("totalCount")
    total_available: int | None = None
    if _is_finite_number(total_raw):
        total_available = max(int(total_raw), len(items))
    has_more = payload.get("hasMore") is True or bool(payload.get("nextCursor"))
    truncated = (
        (total_available is not None and total_available > len(items))
        or has_more
    )
    return items, total_available, truncated


def _render_daily_brief_markdown(brief_obj: dict[str, Any]) -> str:
    """Render the bilingual Spanish/English Markdown brief with all 5 canonical rules."""
    lines: list[str] = []
    lines.append(
        f"# Brief Operativo del Negocio — {brief_obj['asOfDate']}"
    )
    lines.append(
        "> *¿Qué debería revisar hoy en mi negocio y por qué?* / "
        "*What should I review in my business today and why?*"
    )
    lines.append("")
    lines.append(f"**Resumen ejecutivo:** {brief_obj['executiveSummary']}")
    lines.append("")

    cov = brief_obj["coverage"]
    lines.append(
        f"## 1. Cobertura de lectura (`{cov['overallStatus'].upper()}`) "
        f"y alcance temporal (`{cov['temporalScope']}`)"
    )
    lines.append(f"- **Alcance temporal:** {cov['temporalScopeNote']}")
    for sr in cov["subReads"]:
        total_str = (
            f"/{sr['totalAvailable']}"
            if sr.get("totalAvailable") is not None
            else " (total global no reportado por el endpoint)"
        )
        lines.append(
            f"- **{sr['resource']}** (`{sr['tool']}`): `{sr['status']}` — "
            f"{sr['fetchedCount']}{total_str} registros. {sr['note']}"
        )
    for w in cov.get("truncationWarnings", []):
        lines.append(f"- ⚠️ **Aviso de cobertura:** {w}")
    lines.append("")

    col = brief_obj["collectionsAndDueDates"]
    lines.append("## 2. Cobros y vencimientos (facturas emitidas vs borradores)")
    lines.append(f"- **Regla aplicada:** {col['ruleApplied']}")
    lines.append(
        f"- **Facturas vencidas (`{col['overdueCount']}`):** "
        f"{_format_provenanced_amount(col['overdueTotal'])}"
    )
    for inv in col["overdueInvoices"]:
        lines.append(
            f"  - `{inv['invoiceNumber']}` · {inv['clientName']} · "
            f"vencida hace {inv['daysFromDueDate']} día(s) ({inv.get('dueDate') or 's/f'}) · "
            f"{_format_provenanced_amount(inv['amount'])}"
        )
    lines.append(
        f"- **Próximos vencimientos ≤7 días (`{col['upcomingDueWithin7DaysCount']}`):** "
        f"{_format_provenanced_amount(col['upcomingDueWithin7DaysTotal'])}"
    )
    for inv in col["upcomingDueInvoices"]:
        lines.append(
            f"  - `{inv['invoiceNumber']}` · {inv['clientName']} · "
            f"vence en {inv['daysFromDueDate']} día(s) ({inv.get('dueDate') or 's/f'}) · "
            f"{_format_provenanced_amount(inv['amount'])}"
        )
    lines.append(
        f"- **{UNPAID_NOMINAL_LABEL_ES} (`{col['openIssuedCount']}`):** "
        f"{_format_provenanced_amount(col['openIssuedNominalTotal'])}"
    )
    lines.append(
        f"- **Borradores no emitidos excluidos de cuentas por cobrar "
        f"(`{col['draftExcludedCount']}`):** "
        f"{_format_provenanced_amount(col['draftExcludedTotal'])}"
    )
    lines.append("")

    quo = brief_obj["quotesToFollowUp"]
    lines.append("## 3. Presupuestos a seguir")
    lines.append(
        f"- **Pendientes de seguimiento (`{quo['actionableCount']}`):** "
        f"{_format_provenanced_amount(quo['actionableTotal'])}"
    )
    for q in quo["quotes"]:
        lines.append(
            f"  - `{q['quoteNumber']}` · {q['clientName']} · estado `{q['status']}` · "
            f"{q['reason']} · {_format_provenanced_amount(q['amount'])}"
        )
    lines.append("")

    exp = brief_obj["expensesToReview"]
    lines.append("## 4. Gastos a revisar")
    lines.append(f"- **Regla fiscal:** {exp['taxDeductibleRuleNote']}")
    lines.append(
        f"- **Total gastos en muestra (`{exp['totalSampledCount']}`):** "
        f"{_format_provenanced_amount(exp['totalSampledAmount'])} "
        f"(no deducibles válidos: `{exp['nonDeductibleValidCount']}`, "
        f"con campos incompletos: `{exp['missingMetadataCount']}`)"
    )
    for e in exp["expensesToReview"]:
        lines.append(
            f"  - `{e['id']}` · {e['description']} · {e['reviewReason']} · "
            f"{_format_provenanced_amount(e['amount'])}"
        )
    lines.append("")

    crm = brief_obj["crmFollowUps"]
    lines.append("## 5. Seguimientos comerciales / CRM")
    lines.append(
        f"- **Clientes priorizados inspeccionados:** {crm['clientsInspectedCount']} "
        f"(con seguimiento sugerido: `{crm['followUpsCount']}`)"
    )
    for f in crm["followUps"]:
        lines.append(
            f"  - **{f['clientName']}** (`{f['clientId']}`): {f['reason']} -> "
            f"{f['suggestedNextStep']}"
        )
    lines.append("")

    cma = brief_obj["currentMonthActivity"]
    lines.append(
        f"## 6. Actividad del mes en curso (`{cma['referenceMonth']}`) "
        "vs muestra operativa acumulada"
    )
    lines.append(f"- **Alcance:** {cma['scopeNote']}")
    lines.append(
        f"- **Facturas emitidas en `{cma['referenceMonth']}` "
        f"(`{cma['issuedInvoicesInMonthCount']}`):** "
        f"{_format_provenanced_amount(cma['issuedInvoicesInMonthTotal'])}"
    )
    lines.append(
        f"- **Borradores fechados en `{cma['referenceMonth']}` "
        f"(`{cma['draftInvoicesInMonthCount']}`):** "
        f"{_format_provenanced_amount(cma['draftInvoicesInMonthTotal'])}"
    )
    lines.append(
        f"- **Presupuestos creados en `{cma['referenceMonth']}` "
        f"(`{cma['quotesCreatedInMonthCount']}`):** "
        f"{_format_provenanced_amount(cma['quotesCreatedInMonthTotal'])}"
    )
    lines.append(
        f"- **Gastos fechados en `{cma['referenceMonth']}` "
        f"(`{cma['expensesInMonthCount']}`):** "
        f"{_format_provenanced_amount(cma['expensesInMonthTotal'])}"
    )
    lines.append("")

    lines.append(
        "## 7. Acciones sugeridas priorizadas (ejecución requiere aprobación humana)"
    )
    for act in brief_obj["PrioritizedSuggestedActions"]:
        lines.append(
            f"- **[{act['priority']}] {act['title']}** (`{act['category']}`): "
            f"{act['why']} -> *{act['suggestedNextStep']}* "
            f"[`humanApprovalRequired={act['humanApprovalRequired']}`, "
            f"`mutatingToolExecuted={act['mutatingToolExecuted']}`]"
        )
    lines.append("")

    lines.append("## 8. Incógnitas conocidas y límites de datos (`Known Unknowns`)")
    for ku in brief_obj["knownUnknowns"]:
        lines.append(f"- {ku}")

    return "\n".join(lines)


def frihet_daily_brief(
    client_or_ctx: Any = None,
    *,
    ctx: Any = None,
    as_of_date: str | None = None,
    asOfDate: str | None = None,
    period_month: str | None = None,
    periodMonth: str | None = None,
    sample_limit: int | None = None,
    sampleLimit: int | None = None,
    page_limit: int = 20,
    max_crm_clients_to_inspect: int = 5,
    maxCrmClientsToInspect: int | None = None,
) -> dict[str, Any]:
    """Build a read-only Daily/Weekly Operational Business Brief.

    Enforces the 5 rules of the Canonical Monetary & Temporal Brief Contract
    (``Frihet-io/frihet-mcp#257``, ``badefc4``):
    1. Absent != 0: missing ``total``, ``amount``, and valid ``items`` ->
       ``amount=None``, ``provenance="unavailable"``, ``unavailableCount >= 1``.
    2. Multi-currency separation: ``100 EUR`` + ``100 USD`` -> ``amount=None``,
       ``currency="MIXED"``, ``provenance="mixed_currency_unconverted"``,
       ``totalsByCurrency={"EUR": ..., "USD": ...}``.
    3. Canonical discounts & taxes: line ``discount``, document ``discountRate``,
       ``taxRate``, ``equivalenceSurchargeRate``, and ``irpfRate`` over the
       discounted tax-exclusive base; fail closed on unsupported modifiers.
    4. Honest unpaid nominal wording: ``realOutstandingBalanceDeterminable=False``,
       ``unpaidNominalSemantics="nominal_unpaid_invoice_totals_without_partial_payments"``,
       and Markdown label ``Importe nominal de facturas no marcadas como pagadas
       (saldo pendiente real no determinable sin cobros parciales)``.
    5. Explicit temporal scope: ``coverage.temporalScope =
       "unfiltered_operational_sample_as_of_date"`` plus ``currentMonthActivity``
       separating the operational sample as of ``asOfDate`` from the
       ``periodMonth`` subset.
    """
    import datetime as _dt

    target = ctx if ctx is not None else client_or_ctx
    effective_date_arg = asOfDate or as_of_date
    today_iso = (
        effective_date_arg[:10]
        if (effective_date_arg and _parse_iso_date_prefix(effective_date_arg))
        else _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    )
    effective_month = (periodMonth or period_month or today_iso[:7])[:7]
    raw_limit = (
        sampleLimit
        if sampleLimit is not None
        else (sample_limit if sample_limit is not None else page_limit)
    )
    bounded_limit = max(1, min(int(raw_limit or 20), 50))
    crm_cap = max(
        0,
        min(
            int(
                maxCrmClientsToInspect
                if maxCrmClientsToInspect is not None
                else max_crm_clients_to_inspect
            ),
            10,
        ),
    )

    provenance_block = {
        "tier": "community",
        "maintained_by": "Frihet",
        "nous_endorsement": False,
        "plugin_catalog_prs": [
            "NousResearch/hermes-agent#135038",
            "NousResearch/hermes-agent#144210",
        ],
        "connectors_ui_pr": {
            "ref": "NousResearch/hermes-agent#134790",
            "status": "open",
            "note": (
                "Plugin Catalog (merged) and Connectors UI / optional-mcps "
                "(open) are distinct surfaces."
            ),
        },
    }

    has_call_mcp = callable(getattr(target, "call_mcp", None))
    has_call_tool = callable(getattr(target, "callTool", None)) or callable(
        getattr(target, "call_tool", None)
    )
    is_callable_fn = callable(target) and not has_call_mcp and not has_call_tool

    if target is None or not (has_call_mcp or has_call_tool or is_callable_fn):
        return {
            "success": False,
            "ok": False,
            "mode": "offline_guidance",
            "question": BRIEF_QUESTION_ES,
            "as_of_date": today_iso,
            "asOfDate": today_iso,
            "error": "no_plugin_context",
            "message": (
                "Run `/frihet brief` inside an active Hermes Agent session so "
                "the plugin can invoke read-only Frihet MCP tools through "
                "`ctx.call_mcp(\"frihet\", ...)`. When invoked outside Hermes "
                "(CLI / unit test without ctx), no workspace figures are "
                "fabricated."
            ),
            "orchestrated_read_tools": list(BRIEF_ORCHESTRATED_READ_TOOLS),
            "safety_contract": {
                "read_only_execution": True,
                "human_approval_required": True,
                "auto_executed": False,
            },
            "safetyContract": {
                "workflowReadOnly": True,
                "mutatingToolsCalledCount": 0,
                "allSuggestedActionsRequireHumanApproval": True,
                "orchestratedTools": list(BRIEF_ORCHESTRATED_READ_TOOLS),
            },
            "provenance": provenance_block,
        }

    tool_timeout = timeout_seconds()
    orchestrated_tools_called: list[str] = []

    def _safe_mcp_read(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        orchestrated_tools_called.append(tool_name)
        try:
            if has_call_mcp:
                raw = getattr(target, "call_mcp")(
                    "frihet", tool_name, arguments, timeout=tool_timeout
                )
            elif callable(getattr(target, "callTool", None)):
                raw = getattr(target, "callTool")(tool_name, arguments)
            elif callable(getattr(target, "call_tool", None)):
                raw = getattr(target, "call_tool")(tool_name, arguments)
            else:
                raw = target(tool_name, arguments)
        except PermissionError as exc:
            return {
                "ok": False,
                "data": {},
                "error": "mcp_allowlist_missing",
                "detail": redact(str(exc)),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "data": {},
                "error": redact(f"{type(exc).__name__}: {exc}"),
            }
        return _extract_mcp_payload(raw)

    ctx_res = _safe_mcp_read("get_business_context", {"period": effective_month})
    if ctx_res.get("error") == "mcp_allowlist_missing":
        return {
            "success": False,
            "ok": False,
            "question": BRIEF_QUESTION_ES,
            "as_of_date": today_iso,
            "asOfDate": today_iso,
            "error": "mcp_allowlist_missing",
            "message": (
                "Plugin `frihet` is not in `plugins.entries.frihet.mcp_allowlist`. "
                "Grant `[frihet]` in `~/.hermes/config.yaml` and re-run `/frihet brief`."
            ),
            "provenance": provenance_block,
        }

    inv_res = _safe_mcp_read("list_invoices", {"limit": bounded_limit})
    quo_res = _safe_mcp_read("list_quotes", {"limit": bounded_limit})
    exp_res = _safe_mcp_read("list_expenses", {"limit": bounded_limit})
    cli_res = _safe_mcp_read("list_clients", {"limit": bounded_limit})

    if not any(r["ok"] for r in (ctx_res, inv_res, quo_res, exp_res, cli_res)):
        first_err = (
            inv_res.get("error")
            or ctx_res.get("error")
            or "mcp_unavailable"
        )
        return {
            "success": False,
            "ok": False,
            "question": BRIEF_QUESTION_ES,
            "as_of_date": today_iso,
            "asOfDate": today_iso,
            "error": redact(str(first_err)),
            "message": (
                "Could not read workspace data from the Frihet MCP server. "
                "Run `/frihet doctor` to verify reachability and authentication."
            ),
            "provenance": provenance_block,
        }

    business_ctx = ctx_res["data"] if ctx_res["ok"] else {}
    default_currency = "EUR"
    if isinstance(business_ctx, dict):
        for candidate_key in ("currency", "defaultCurrency"):
            val = business_ctx.get(candidate_key)
            if isinstance(val, str) and val.strip():
                default_currency = val.strip().upper()
                break
        for nested_key in ("company", "profile", "taxConfig"):
            nested = business_ctx.get(nested_key)
            if isinstance(nested, dict):
                val = nested.get("currency") or nested.get("defaultCurrency")
                if isinstance(val, str) and val.strip():
                    default_currency = val.strip().upper()
                    break

    invoices, inv_total, inv_trunc = _extract_list_and_total(
        inv_res["data"] if inv_res["ok"] else {}, ("invoices",)
    )
    quotes, quo_total, quo_trunc = _extract_list_and_total(
        quo_res["data"] if quo_res["ok"] else {}, ("quotes",)
    )
    expenses, exp_total, exp_trunc = _extract_list_and_total(
        exp_res["data"] if exp_res["ok"] else {}, ("expenses",)
    )
    clients, cli_total, cli_trunc = _extract_list_and_total(
        cli_res["data"] if cli_res["ok"] else {}, ("clients",)
    )

    sub_reads: list[dict[str, Any]] = []
    truncation_warnings: list[str] = []
    coverage_notes: list[str] = []

    if ctx_res["ok"]:
        sub_reads.append(
            {
                "tool": "get_business_context",
                "resource": "business_context",
                "status": "complete",
                "fetchedCount": 1,
                "totalAvailable": 1,
                "isTruncated": False,
                "paginationComplete": True,
                "note": f"Contexto fiscal y de negocio leído para el periodo {effective_month}.",
            }
        )
    else:
        err_msg = redact(str(ctx_res.get("error") or "failed"))
        sub_reads.append(
            {
                "tool": "get_business_context",
                "resource": "business_context",
                "status": "failed",
                "fetchedCount": 0,
                "totalAvailable": None,
                "isTruncated": False,
                "paginationComplete": False,
                "note": f"No se pudo obtener get_business_context: {err_msg}",
                "error": err_msg,
            }
        )
        truncation_warnings.append(f"get_business_context falló: {err_msg}")
        coverage_notes.append(f"business_context read failed ({err_msg}).")

    def _record_list_subread(
        tool_name: str,
        resource_name: str,
        res_obj: dict[str, Any],
        items_list: list[dict[str, Any]],
        total_avail: int | None,
        is_trunc: bool,
    ) -> str:
        if not res_obj["ok"]:
            err_msg = redact(str(res_obj.get("error") or "failed"))
            sub_reads.append(
                {
                    "tool": tool_name,
                    "resource": resource_name,
                    "status": "failed",
                    "fetchedCount": 0,
                    "totalAvailable": None,
                    "isTruncated": False,
                    "paginationComplete": False,
                    "note": f"Falló la lectura de {resource_name}: {err_msg}",
                    "error": err_msg,
                }
            )
            truncation_warnings.append(f"{resource_name} ({tool_name}) falló: {err_msg}")
            coverage_notes.append(f"{resource_name} read failed ({err_msg}).")
            return "unavailable"

        fetched_cnt = len(items_list)
        hit_sample_cap_without_total = (
            total_avail is None and fetched_cnt >= bounded_limit
        )
        pagination_complete = (not is_trunc) and (not hit_sample_cap_without_total)
        status_str = "complete" if pagination_complete else "partial"

        if is_trunc:
            note = (
                f"Muestra parcial: se leyeron {fetched_cnt} de "
                f"{total_avail if total_avail is not None else 'más'} registros disponibles "
                f"(límite={bounded_limit})."
            )
            truncation_warnings.append(f"{resource_name}: {note}")
            coverage_notes.append(
                f"{resource_name} list is partial ({fetched_cnt} of "
                f"{total_avail if total_avail is not None else 'more'} records inspected)."
            )
        elif hit_sample_cap_without_total:
            note = (
                f"Se alcanzó el límite de muestra ({fetched_cnt}/{bounded_limit}) sin total "
                "global reportado; pueden existir registros adicionales."
            )
            truncation_warnings.append(f"{resource_name}: {note}")
            coverage_notes.append(
                f"{resource_name} list is partial ({fetched_cnt} of unknown total records inspected)."
            )
        else:
            note = f"Cobertura completa ({fetched_cnt} registros inspeccionados)."

        sub_reads.append(
            {
                "tool": tool_name,
                "resource": resource_name,
                "status": status_str,
                "fetchedCount": fetched_cnt,
                "totalAvailable": total_avail if total_avail is not None else fetched_cnt,
                "isTruncated": is_trunc or hit_sample_cap_without_total,
                "paginationComplete": pagination_complete,
                "note": note,
            }
        )
        return status_str

    inv_cov_status = _record_list_subread(
        "list_invoices", "invoices", inv_res, invoices, inv_total, inv_trunc
    )
    quo_cov_status = _record_list_subread(
        "list_quotes", "quotes", quo_res, quotes, quo_total, quo_trunc
    )
    exp_cov_status = _record_list_subread(
        "list_expenses", "expenses", exp_res, expenses, exp_total, exp_trunc
    )
    cli_cov_status = _record_list_subread(
        "list_clients", "clients", cli_res, clients, cli_total, cli_trunc
    )

    # ── 1. Invoices: strictly separate issued receivables vs drafts ─────────
    overdue_invoices_canonical: list[dict[str, Any]] = []
    upcoming_due_invoices_canonical: list[dict[str, Any]] = []
    open_issued_invoices_canonical: list[dict[str, Any]] = []
    draft_invoices_canonical: list[dict[str, Any]] = []

    overdue_items_snake: list[dict[str, Any]] = []
    upcoming_due_items_snake: list[dict[str, Any]] = []
    draft_invoices_snake: list[dict[str, Any]] = []
    priority_client_ids: list[str] = []

    for inv in invoices:
        inv_id = str(inv.get("id") or "unknown")
        doc_num = str(
            inv.get("documentNumber")
            or inv.get("invoiceNumber")
            or inv.get("number")
            or inv.get("seriesNumber")
            or inv_id
        )
        status_raw = str(inv.get("status") or "unknown").lower()
        client_name = str(
            inv.get("clientName")
            or inv.get("customerName")
            or (inv.get("client") or {}).get("name")
            if isinstance(inv.get("client"), dict)
            else (inv.get("clientName") or inv.get("customerName") or "Cliente sin nombre")
        )
        client_id_raw = inv.get("clientId") or (
            inv.get("client", {}).get("id") if isinstance(inv.get("client"), dict) else None
        )
        client_id = str(client_id_raw) if client_id_raw else ""
        issue_date = (
            str(inv.get("issueDate") or inv.get("date") or "")[:10] or None
        )
        due_date = str(inv.get("dueDate") or "")[:10] or None
        amt_info = _resolve_doc_amount(inv, default_currency)
        amt = amt_info["amount"]
        curr = amt_info["currency"]
        prov = amt_info["provenance"]

        days_to_due = _days_between_iso(today_iso, due_date) if due_date else None

        if status_raw == "draft":
            draft_invoices_canonical.append(
                {
                    "id": inv_id,
                    "invoiceNumber": doc_num,
                    "clientName": client_name,
                    "clientId": client_id or None,
                    "status": status_raw,
                    "issueDate": issue_date,
                    "dueDate": due_date,
                    "daysFromDueDate": days_to_due,
                    "amount": amt_info,
                    "classification": "draft_excluded_from_receivables",
                }
            )
            draft_invoices_snake.append(
                {
                    "id": inv_id,
                    "document_number": doc_num,
                    "client_name": client_name,
                    "amount": amt,
                    "currency": curr,
                    "amount_provenance": prov,
                    "fiscal_status": "draft_not_issued",
                }
            )
            continue

        if status_raw in {"paid", "cancelled", "void", "voided"}:
            continue

        is_overdue = status_raw == "overdue" or (
            days_to_due is not None and days_to_due < 0
        )
        is_upcoming = (not is_overdue) and (
            days_to_due is not None and 0 <= days_to_due <= 7
        )

        classification = (
            "overdue_receivable"
            if is_overdue
            else ("upcoming_due_receivable" if is_upcoming else "open_issued_receivable")
        )
        canonical_item = {
            "id": inv_id,
            "invoiceNumber": doc_num,
            "clientName": client_name,
            "clientId": client_id or None,
            "status": status_raw,
            "issueDate": issue_date,
            "dueDate": due_date,
            "daysFromDueDate": (
                abs(days_to_due)
                if (is_overdue and days_to_due is not None)
                else days_to_due
            ),
            "amount": amt_info,
            "classification": classification,
        }
        open_issued_invoices_canonical.append(canonical_item)

        if is_overdue:
            overdue_invoices_canonical.append(canonical_item)
            days_overdue = (
                abs(days_to_due)
                if (days_to_due is not None and days_to_due < 0)
                else None
            )
            overdue_items_snake.append(
                {
                    "id": inv_id,
                    "document_number": doc_num,
                    "client_id": client_id or None,
                    "client_name": client_name,
                    "due_date": due_date,
                    "days_overdue": days_overdue,
                    "amount": amt,
                    "currency": curr,
                    "amount_provenance": prov,
                    "status": status_raw,
                }
            )
            if client_id and client_id not in priority_client_ids:
                priority_client_ids.append(client_id)
        elif is_upcoming:
            upcoming_due_invoices_canonical.append(canonical_item)
            upcoming_due_items_snake.append(
                {
                    "id": inv_id,
                    "document_number": doc_num,
                    "client_id": client_id or None,
                    "client_name": client_name,
                    "due_date": due_date,
                    "days_until_due": days_to_due,
                    "amount": amt,
                    "currency": curr,
                    "amount_provenance": prov,
                    "status": status_raw,
                }
            )
            if client_id and client_id not in priority_client_ids:
                priority_client_ids.append(client_id)

    overdue_total_pa = _sum_provenanced_amounts(
        [i["amount"] for i in overdue_invoices_canonical], default_currency
    )
    upcoming_total_pa = _sum_provenanced_amounts(
        [i["amount"] for i in upcoming_due_invoices_canonical], default_currency
    )
    open_issued_nominal_pa = _sum_provenanced_amounts(
        [i["amount"] for i in open_issued_invoices_canonical], default_currency
    )
    draft_excluded_pa = _sum_provenanced_amounts(
        [i["amount"] for i in draft_invoices_canonical], default_currency
    )

    def _flat_currency_map(pa: dict[str, Any]) -> dict[str, float]:
        tbc = pa.get("totalsByCurrency") or {}
        return {
            curr: float(b["amount"])
            for curr, b in tbc.items()
            if isinstance(b, dict) and _is_finite_number(b.get("amount"))
        }

    # ── 2. Quotes: expiring or expired open quotes ──────────────────────────
    actionable_quotes_canonical: list[dict[str, Any]] = []
    quotes_to_follow_up_snake: list[dict[str, Any]] = []

    for quo in quotes:
        quo_id = str(quo.get("id") or "unknown")
        doc_num = str(
            quo.get("documentNumber")
            or quo.get("quoteNumber")
            or quo.get("number")
            or quo_id
        )
        status_raw = str(quo.get("status") or "unknown").lower()
        if status_raw in {"accepted", "rejected", "invoiced", "cancelled", "converted"}:
            continue
        client_name = str(quo.get("clientName") or quo.get("customerName") or "Cliente sin nombre")
        client_id_raw = quo.get("clientId")
        client_id = str(client_id_raw) if client_id_raw else None
        issue_date = str(quo.get("issueDate") or quo.get("date") or "")[:10] or None
        valid_until = (
            str(quo.get("validUntil") or quo.get("expiryDate") or quo.get("expirationDate") or "")[:10]
            or None
        )
        days_left = _days_between_iso(today_iso, valid_until) if valid_until else None
        amt_info = _resolve_doc_amount(quo, default_currency)

        if days_left is not None and days_left < 0:
            reason = f"Validez vencida hace {abs(days_left)} día(s) ({valid_until}) sin respuesta registrada"
        elif days_left is not None and days_left <= 7:
            reason = f"Expira en {days_left} día(s) ({valid_until})"
        elif status_raw == "draft":
            reason = "Borrador de presupuesto pendiente de envío al cliente"
        else:
            reason = "Presupuesto enviado pendiente de decisión comercial"

        actionable_quotes_canonical.append(
            {
                "id": quo_id,
                "quoteNumber": doc_num,
                "clientName": client_name,
                "clientId": client_id,
                "status": status_raw,
                "issueDate": issue_date,
                "validUntil": valid_until,
                "daysUntilExpiry": days_left,
                "amount": amt_info,
                "reason": reason,
            }
        )
        if client_id and client_id not in priority_client_ids:
            priority_client_ids.append(client_id)

        if status_raw in {"sent", "draft", "pending", "open"} and (
            days_left is None or days_left <= 7 or status_raw == "draft"
        ):
            quotes_to_follow_up_snake.append(
                {
                    "id": quo_id,
                    "document_number": doc_num,
                    "client_name": client_name,
                    "status": status_raw,
                    "valid_until": valid_until,
                    "days_until_expiry": days_left,
                    "amount": amt_info["amount"],
                    "currency": amt_info["currency"],
                    "amount_provenance": amt_info["provenance"],
                }
            )

    actionable_quotes_pa = _sum_provenanced_amounts(
        [q["amount"] for q in actionable_quotes_canonical], default_currency
    )

    # ── 3. Expenses to review (never treat taxDeductible=False as error) ────
    expenses_to_review_canonical: list[dict[str, Any]] = []
    expenses_to_review_snake: list[dict[str, Any]] = []
    all_expense_amounts: list[dict[str, Any]] = []
    non_deductible_valid_count = 0
    missing_metadata_count = 0

    for exp in expenses:
        exp_id = str(exp.get("id") or "unknown")
        desc = str(exp.get("description") or exp.get("concept") or exp.get("notes") or exp_id)
        vendor_raw = exp.get("vendor") or exp.get("supplier") or exp.get("vendorName")
        vendor = str(vendor_raw).strip() if isinstance(vendor_raw, str) and vendor_raw.strip() else None
        category_raw = exp.get("category")
        category = str(category_raw).strip() if isinstance(category_raw, str) and category_raw.strip() else None
        exp_date = str(exp.get("date") or exp.get("expenseDate") or "")[:10] or None
        tax_deductible_raw = exp.get("taxDeductible")
        tax_deductible = tax_deductible_raw if isinstance(tax_deductible_raw, bool) else None

        amt_info = _resolve_doc_amount(exp, default_currency)
        all_expense_amounts.append(amt_info)

        if tax_deductible is False:
            non_deductible_valid_count += 1

        missing_fields: list[str] = []
        reasons_snake: list[str] = []
        if not category:
            missing_fields.append("category")
            reasons_snake.append("missing_category")
        if not vendor:
            missing_fields.append("vendor")
            reasons_snake.append("missing_vendor")
        if amt_info["provenance"] == "unavailable":
            missing_fields.append("amount")
            reasons_snake.append("missing_amount")

        if missing_fields:
            missing_metadata_count += 1
            expenses_to_review_canonical.append(
                {
                    "id": exp_id,
                    "description": desc,
                    "vendorName": vendor,
                    "category": category,
                    "date": exp_date,
                    "amount": amt_info,
                    "taxDeductible": tax_deductible,
                    "reviewReason": f"Metadatos incompletos para cierre contable: {', '.join(missing_fields)}",
                }
            )
        elif tax_deductible is False:
            expenses_to_review_canonical.append(
                {
                    "id": exp_id,
                    "description": desc,
                    "vendorName": vendor,
                    "category": category,
                    "date": exp_date,
                    "amount": amt_info,
                    "taxDeductible": False,
                    "reviewReason": (
                        "Marcado como no deducible fiscalmente (taxDeductible=false; "
                        "estado válido, verificar soporte documental)"
                    ),
                }
            )

        if tax_deductible is False:
            reasons_snake.append(
                "marked_non_deductible (valid state; confirm fiscal deductibility before quarterly close)"
            )
        elif tax_deductible is None and ("taxDeductible" not in exp):
            reasons_snake.append("tax_deductibility_unclassified")

        if reasons_snake:
            expenses_to_review_snake.append(
                {
                    "id": exp_id,
                    "description": desc,
                    "date": exp_date,
                    "amount": amt_info["amount"],
                    "currency": amt_info["currency"],
                    "amount_provenance": amt_info["provenance"],
                    "tax_deductible": tax_deductible,
                    "review_reasons": reasons_snake,
                }
            )

    total_expenses_pa = _sum_provenanced_amounts(all_expense_amounts, default_currency)

    # ── 4. CRM follow-ups for priority clients ──────────────────────────────
    crm_follow_ups_canonical: list[dict[str, Any]] = []
    crm_follow_ups_snake: list[dict[str, Any]] = []
    client_lookup = {
        str(c.get("id")): c for c in clients if isinstance(c, dict) and c.get("id")
    }
    for c in clients:
        cid = str(c.get("id") or "")
        if cid and cid not in priority_client_ids and len(priority_client_ids) < crm_cap:
            priority_client_ids.append(cid)

    clients_to_inspect = priority_client_ids[:crm_cap]
    activities_fetched_total = 0
    activities_failed_count = 0
    activities_any_truncated = False

    for cid in clients_to_inspect:
        act_res = _safe_mcp_read(
            "list_client_activities", {"clientId": cid, "limit": 5}
        )
        client_doc = client_lookup.get(cid, {})
        client_name = str(client_doc.get("name") or cid)
        has_overdue = any(i.get("clientId") == cid for i in overdue_invoices_canonical)
        has_quote = any(q.get("clientId") == cid for q in actionable_quotes_canonical)

        if act_res["ok"]:
            acts, act_total, act_trunc = _extract_list_and_total(
                act_res["data"], ("activities",)
            )
            activities_fetched_total += len(acts)
            if act_trunc:
                activities_any_truncated = True
            latest = acts[0] if acts else None
            last_date = (
                str(latest.get("timestamp") or latest.get("date") or latest.get("createdAt") or "")[:10]
                if isinstance(latest, dict)
                else None
            ) or None
            last_summary = (
                str(latest.get("title") or latest.get("description") or latest.get("type") or "")
                if isinstance(latest, dict)
                else None
            ) or None

            crm_follow_ups_snake.append(
                {
                    "client_id": cid,
                    "client_name": client_name,
                    "activity_count": act_total if act_total is not None else len(acts),
                    "latest_activity_type": latest.get("type") if isinstance(latest, dict) else None,
                    "latest_activity_title": latest.get("title") if isinstance(latest, dict) else None,
                    "latest_activity_at": (
                        latest.get("timestamp") or latest.get("createdAt")
                        if isinstance(latest, dict)
                        else None
                    ),
                }
            )

            if len(acts) == 0 or has_overdue or has_quote:
                reason = (
                    "Cliente con factura vencida pendiente de gestión de cobro"
                    if has_overdue
                    else (
                        "Cliente con presupuesto abierto pendiente de cierre"
                        if has_quote
                        else "Sin actividades recientes registradas en CRM"
                    )
                )
                next_step = (
                    "Contactar para confirmar fecha de pago y registrar la gestión en actividades del cliente (requiere aprobación)."
                    if has_overdue
                    else (
                        "Hacer seguimiento comercial del presupuesto enviado (requiere aprobación)."
                        if has_quote
                        else "Revisar estado de cuenta y programar contacto comercial."
                    )
                )
                crm_follow_ups_canonical.append(
                    {
                        "clientId": cid,
                        "clientName": client_name,
                        "reason": reason,
                        "recentActivitiesCount": len(acts),
                        "lastActivityDate": last_date,
                        "lastActivitySummary": last_summary,
                        "suggestedNextStep": next_step,
                    }
                )
        else:
            activities_failed_count += 1
            err_msg = redact(str(act_res.get("error") or "failed"))
            coverage_notes.append(
                f"client_activities[{cid}] read failed ({err_msg})."
            )
            crm_follow_ups_canonical.append(
                {
                    "clientId": cid,
                    "clientName": client_name,
                    "reason": (
                        f"No se pudo leer el historial de actividades CRM ({err_msg})"
                    ),
                    "recentActivitiesCount": 0,
                    "lastActivityDate": None,
                    "lastActivitySummary": None,
                    "suggestedNextStep": (
                        "Verificar historial del cliente antes de ejecutar acciones comerciales."
                    ),
                }
            )

    if len(clients_to_inspect) > 0:
        all_failed = activities_failed_count == len(clients_to_inspect)
        any_failed = activities_failed_count > 0
        more_clients_uninspected = len(clients) > len(clients_to_inspect) or (
            cli_total is not None and cli_total > len(clients_to_inspect)
        )
        act_pagination_complete = (
            (not any_failed)
            and (not activities_any_truncated)
            and (not more_clients_uninspected)
        )
        act_status = (
            "failed"
            if all_failed
            else ("complete" if act_pagination_complete else "partial")
        )
        act_note = (
            f"Actividades CRM consultadas para {len(clients_to_inspect)} cliente(s) priorizados "
            f"({activities_fetched_total} actividades leídas"
            + (f", {activities_failed_count} lectura(s) fallida(s)" if any_failed else "")
            + ")."
        )
        sub_reads.append(
            {
                "tool": "list_client_activities",
                "resource": "client_activities",
                "status": act_status,
                "fetchedCount": activities_fetched_total,
                "totalAvailable": (
                    activities_fetched_total if act_pagination_complete else None
                ),
                "isTruncated": activities_any_truncated or more_clients_uninspected,
                "paginationComplete": act_pagination_complete,
                "note": act_note,
            }
        )
        if not act_pagination_complete:
            truncation_warnings.append(f"client_activities: {act_note}")

    overall_coverage = (
        "complete"
        if all(sr["status"] == "complete" for sr in sub_reads)
        else "partial"
    )

    resource_coverage = {
        "business_context": "complete" if ctx_res["ok"] else "unavailable",
        "invoices": {
            "fetched": len(invoices),
            "total": inv_total if inv_total is not None else len(invoices),
            "status": inv_cov_status,
        },
        "quotes": {
            "fetched": len(quotes),
            "total": quo_total if quo_total is not None else len(quotes),
            "status": quo_cov_status,
        },
        "expenses": {
            "fetched": len(expenses),
            "total": exp_total if exp_total is not None else len(expenses),
            "status": exp_cov_status,
        },
        "clients": {
            "fetched": len(clients),
            "total": cli_total if cli_total is not None else len(clients),
            "status": cli_cov_status,
        },
    }

    # ── 5. Current-month activity vs unfiltered operational sample (Rule 5) ─
    issued_invoices_in_month = [
        inv
        for inv in invoices
        if str(inv.get("status") or "").lower() not in {"draft", "cancelled", "void", "voided"}
        and _is_in_period_month(inv.get("issueDate") or inv.get("date"), effective_month)
    ]
    draft_invoices_in_month = [
        inv
        for inv in invoices
        if str(inv.get("status") or "").lower() == "draft"
        and _is_in_period_month(inv.get("issueDate") or inv.get("date"), effective_month)
    ]
    quotes_in_month = [
        quo
        for quo in quotes
        if _is_in_period_month(quo.get("issueDate") or quo.get("date"), effective_month)
    ]
    expenses_in_month = [
        exp
        for exp in expenses
        if _is_in_period_month(exp.get("date") or exp.get("expenseDate"), effective_month)
    ]

    current_month_activity = {
        "referenceMonth": effective_month,
        "scopeNote": (
            f"Subconjunto de registros dentro de la muestra leída cuya fecha de emisión/gasto "
            f"pertenece a {effective_month}. Los cobros vencidos y presupuestos por expirar "
            f"en las secciones superiores abarcan toda la muestra operativa abierta al "
            f"{today_iso} (incluyendo meses anteriores)."
        ),
        "issuedInvoicesInMonthCount": len(issued_invoices_in_month),
        "issuedInvoicesInMonthTotal": _sum_provenanced_amounts(
            [_resolve_doc_amount(inv, default_currency) for inv in issued_invoices_in_month],
            default_currency,
        ),
        "draftInvoicesInMonthCount": len(draft_invoices_in_month),
        "draftInvoicesInMonthTotal": _sum_provenanced_amounts(
            [_resolve_doc_amount(inv, default_currency) for inv in draft_invoices_in_month],
            default_currency,
        ),
        "quotesCreatedInMonthCount": len(quotes_in_month),
        "quotesCreatedInMonthTotal": _sum_provenanced_amounts(
            [_resolve_doc_amount(quo, default_currency) for quo in quotes_in_month],
            default_currency,
        ),
        "expensesInMonthCount": len(expenses_in_month),
        "expensesInMonthTotal": _sum_provenanced_amounts(
            [_resolve_doc_amount(exp, default_currency) for exp in expenses_in_month],
            default_currency,
        ),
    }

    # ── 6. Prioritized Suggested Actions (strictly human-approved) ──────────
    prioritized_actions_canonical: list[dict[str, Any]] = []
    suggested_actions_snake: list[dict[str, Any]] = []

    if overdue_invoices_canonical:
        prioritized_actions_canonical.append(
            {
                "priority": "P1",
                "category": "collections",
                "title": f"Gestionar {len(overdue_invoices_canonical)} factura(s) emitida(s) vencida(s)",
                "why": (
                    f"Existen {len(overdue_invoices_canonical)} factura(s) emitida(s) fuera de "
                    f"plazo por {_format_provenanced_amount(overdue_total_pa)}."
                ),
                "affectedRecords": [i["invoiceNumber"] for i in overdue_invoices_canonical],
                "suggestedNextStep": (
                    "Revisar cada factura vencida y, tras confirmación humana explícita, "
                    "enviar recordatorio o registrar el cobro si ya entró en banco."
                ),
                "candidateFollowUpToolsRequiresApproval": [
                    "send_invoice",
                    "mark_invoice_paid",
                    "log_client_activity",
                ],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    for item in overdue_items_snake:
        days_str = (
            f"{item['days_overdue']} days overdue"
            if item.get("days_overdue") is not None
            else "past due"
        )
        suggested_actions_snake.append(
            {
                "priority": "P1",
                "category": "overdue_collection",
                "target_id": item["id"],
                "document_number": item["document_number"],
                "client_name": item["client_name"],
                "why": (
                    f"Issued invoice {item['document_number']} for {item['client_name']} "
                    f"({item['amount']} {item['currency']}) is {days_str}."
                ),
                "recommended_next_step": (
                    "Review payment status and, if still unpaid, send a collection "
                    "reminder or log a follow-up call on the client timeline."
                ),
                "suggested_tool": "send_invoice",
                "secondary_tool": "log_client_activity",
                "human_approval_required": True,
                "auto_executed": False,
                "safety_note": (
                    "Sending an invoice reminder emails the client and triggers "
                    "webhooks; gated by `pre_tool_call` human approval."
                ),
            }
        )

    if upcoming_due_invoices_canonical:
        prioritized_actions_canonical.append(
            {
                "priority": "P2",
                "category": "collections",
                "title": (
                    f"Prevenir impago en {len(upcoming_due_invoices_canonical)} factura(s) "
                    "que vencen en ≤7 días"
                ),
                "why": (
                    f"Vencimientos próximos por {_format_provenanced_amount(upcoming_total_pa)}."
                ),
                "affectedRecords": [i["invoiceNumber"] for i in upcoming_due_invoices_canonical],
                "suggestedNextStep": (
                    "Confirmar recepción de factura con el cliente antes de la fecha de vencimiento."
                ),
                "candidateFollowUpToolsRequiresApproval": ["log_client_activity"],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    for item in upcoming_due_items_snake:
        suggested_actions_snake.append(
            {
                "priority": "P2",
                "category": "upcoming_maturity",
                "target_id": item["id"],
                "document_number": item["document_number"],
                "client_name": item["client_name"],
                "why": (
                    f"Issued invoice {item['document_number']} for {item['client_name']} "
                    f"({item['amount']} {item['currency']}) matures in "
                    f"{item['days_until_due']} day(s) ({item['due_date']})."
                ),
                "recommended_next_step": (
                    "Confirm the client has received the invoice and has no billing "
                    "blockers before the due date."
                ),
                "suggested_tool": "log_client_activity",
                "human_approval_required": True,
                "auto_executed": False,
                "safety_note": "Logging a CRM activity writes an immutable timeline entry.",
            }
        )

    if draft_invoices_canonical:
        prioritized_actions_canonical.append(
            {
                "priority": "P2",
                "category": "collections",
                "title": (
                    f"Revisar {len(draft_invoices_canonical)} borrador(es) de factura "
                    "no emitidos (excluidos de cuentas por cobrar)"
                ),
                "why": (
                    f"Hay {len(draft_invoices_canonical)} borrador(es) por "
                    f"{_format_provenanced_amount(draft_excluded_pa)} que no generan derecho "
                    "de cobro ni impacto fiscal hasta su emisión."
                ),
                "affectedRecords": [i["invoiceNumber"] for i in draft_invoices_canonical],
                "suggestedNextStep": (
                    "Validar conceptos e impuestos y decidir si deben emitirse/enviarse "
                    "o descartarse (requiere aprobación humana)."
                ),
                "candidateFollowUpToolsRequiresApproval": [
                    "update_invoice",
                    "send_invoice",
                    "delete_invoice",
                ],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    for draft in draft_invoices_snake:
        suggested_actions_snake.append(
            {
                "priority": "P2",
                "category": "unissued_draft_invoice",
                "target_id": draft["id"],
                "document_number": draft["document_number"],
                "client_name": draft["client_name"],
                "why": (
                    f"Draft invoice {draft['document_number']} for {draft['client_name']} "
                    f"({draft['amount']} {draft['currency']}) has not been issued yet "
                    "and is excluded from fiscal accounts receivable."
                ),
                "recommended_next_step": (
                    "Verify line items, tax rate, and NIF, then decide whether to "
                    "issue/send or discard the draft."
                ),
                "suggested_tool": "send_invoice",
                "human_approval_required": True,
                "auto_executed": False,
                "safety_note": (
                    "Issuing/sending a draft invoice assigns fiscal state and "
                    "requires explicit human confirmation."
                ),
            }
        )

    if actionable_quotes_canonical:
        prioritized_actions_canonical.append(
            {
                "priority": "P2",
                "category": "quotes",
                "title": (
                    f"Dar seguimiento a {len(actionable_quotes_canonical)} presupuesto(s) "
                    "abierto(s)"
                ),
                "why": (
                    f"Presupuestos en curso por {_format_provenanced_amount(actionable_quotes_pa)} "
                    "pendientes de aceptación o próximos a expirar."
                ),
                "affectedRecords": [q["quoteNumber"] for q in actionable_quotes_canonical],
                "suggestedNextStep": (
                    "Contactar al potencial cliente y, con confirmación explícita, "
                    "enviar presupuesto o registrar actividad CRM."
                ),
                "candidateFollowUpToolsRequiresApproval": [
                    "send_quote",
                    "update_quote",
                    "log_client_activity",
                ],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    for quo_item in quotes_to_follow_up_snake:
        suggested_actions_snake.append(
            {
                "priority": "P2",
                "category": "quote_follow_up",
                "target_id": quo_item["id"],
                "document_number": quo_item["document_number"],
                "client_name": quo_item["client_name"],
                "why": (
                    f"Sent quote {quo_item['document_number']} for {quo_item['client_name']} "
                    f"({quo_item['amount']} {quo_item['currency']}) has valid_until={quo_item['valid_until']}."
                ),
                "recommended_next_step": (
                    "Follow up with the prospect to close acceptance or extend validity."
                ),
                "suggested_tool": "log_client_activity",
                "human_approval_required": True,
                "auto_executed": False,
                "safety_note": "CRM follow-up requires user confirmation before writing.",
            }
        )

    if expenses_to_review_canonical:
        prioritized_actions_canonical.append(
            {
                "priority": "P3",
                "category": "expenses",
                "title": (
                    f"Revisar soporte y clasificación de {len(expenses_to_review_canonical)} gasto(s)"
                ),
                "why": (
                    f"Se detectaron {missing_metadata_count} gasto(s) con metadatos incompletos "
                    f"y {non_deductible_valid_count} gasto(s) marcados como no deducibles "
                    "(`taxDeductible=false`, estado válido)."
                ),
                "affectedRecords": [e["id"] for e in expenses_to_review_canonical],
                "suggestedNextStep": (
                    "Completar categoría/proveedor en gastos incompletos antes del cierre "
                    "trimestral (requiere aprobación humana)."
                ),
                "candidateFollowUpToolsRequiresApproval": ["update_expense"],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    for exp_item in expenses_to_review_snake:
        suggested_actions_snake.append(
            {
                "priority": "P3",
                "category": "expense_hygiene",
                "target_id": exp_item["id"],
                "description": exp_item["description"],
                "why": (
                    f"Expense '{exp_item['description']}' ({exp_item['amount']} {exp_item['currency']}) "
                    f"flagged for review: {', '.join(exp_item['review_reasons'])}."
                ),
                "recommended_next_step": (
                    "Review vendor metadata and fiscal deductibility classification "
                    "before the quarterly tax filing."
                ),
                "suggested_tool": "update_expense",
                "human_approval_required": True,
                "auto_executed": False,
                "safety_note": "Updating an expense record requires human confirmation.",
            }
        )

    if overall_coverage == "partial":
        prioritized_actions_canonical.append(
            {
                "priority": "P3",
                "category": "coverage_gap",
                "title": "Ampliar lectura paginada o reintentar sub-lecturas con cobertura parcial",
                "why": "El brief se generó con cobertura parcial en una o más fuentes.",
                "affectedRecords": [
                    sr["resource"] for sr in sub_reads if sr["status"] != "complete"
                ],
                "suggestedNextStep": (
                    "Ejecutar consultas paginadas específicas si se requiere conciliación exhaustiva."
                ),
                "candidateFollowUpToolsRequiresApproval": [],
                "humanApprovalRequired": True,
                "mutatingToolExecuted": False,
            }
        )

    known_unknowns: list[str] = [
        (
            "La conciliación bancaria en tiempo real y los pagos parciales no registrados "
            "en la factura no están incluidos en esta muestra; `openIssuedNominalTotal` "
            "suma el importe nominal íntegro de facturas emitidas no marcadas como `paid` "
            "(`realOutstandingBalanceDeterminable=false`)."
        ),
        (
            "Las facturas en estado `draft` se reportan por separado y no se incluyen en "
            "las cuentas por cobrar emitidas."
        ),
    ]
    if (
        overdue_total_pa["provenance"] == "mixed_currency_unconverted"
        or open_issued_nominal_pa["provenance"] == "mixed_currency_unconverted"
        or actionable_quotes_pa["provenance"] == "mixed_currency_unconverted"
        or total_expenses_pa["provenance"] == "mixed_currency_unconverted"
    ):
        known_unknowns.append(
            "Existen documentos en múltiples divisas; los importes se desglosan por divisa "
            "(`totalsByCurrency`) sin aplicar tipo de cambio implícito."
        )
    if (
        overdue_total_pa["provenance"] == "unavailable"
        or open_issued_nominal_pa["provenance"] == "unavailable"
        or draft_excluded_pa["provenance"] == "unavailable"
        or actionable_quotes_pa["provenance"] == "unavailable"
        or total_expenses_pa["provenance"] == "unavailable"
    ):
        known_unknowns.append(
            "Uno o más documentos carecen de `total`/`amount` almacenado o usan "
            "modificadores no soportados sin desglose; el agregado afectado se marca "
            "`unavailable` (`amount: null`) y nunca se asume 0."
        )
    for w in truncation_warnings:
        known_unknowns.append(f"Límite de cobertura: {w}")
    for note in coverage_notes:
        if note not in known_unknowns:
            known_unknowns.append(note)

    executive_summary = (
        f"Al {today_iso} (cobertura {overall_coverage.upper()}, muestra operativa abierta + "
        f"desglose del mes {effective_month}): "
        f"{len(overdue_invoices_canonical)} factura(s) emitida(s) vencida(s) "
        f"({_format_provenanced_amount(overdue_total_pa)}), "
        f"{len(upcoming_due_invoices_canonical)} factura(s) por vencer en ≤7 días "
        f"({_format_provenanced_amount(upcoming_total_pa)}), "
        f"{len(draft_invoices_canonical)} borrador(es) excluido(s) de cuentas por cobrar "
        f"({_format_provenanced_amount(draft_excluded_pa)}), "
        f"{len(actionable_quotes_canonical)} presupuesto(s) para seguimiento "
        f"({_format_provenanced_amount(actionable_quotes_pa)}), y "
        f"{len(expenses_to_review_canonical)} gasto(s) señalados para revisión documental. "
        "Ninguna acción mutante fue ejecutada automáticamente."
    )

    coverage_block = {
        "overallStatus": overall_coverage,
        "status": overall_coverage,
        "temporalScope": TEMPORAL_SCOPE_ID,
        "temporal_scope": TEMPORAL_SCOPE_ID,
        "temporalScopeNote": (
            f"Las colecciones listadas (`list_invoices`, `list_quotes`, `list_expenses`, "
            f"`list_clients`) son una muestra operativa sin filtro de fecha en el API "
            f"(hasta {bounded_limit} registros por recurso). Los cobros vencidos y "
            f"presupuestos abiertos reflejan el estado operativo acumulado al {today_iso}, "
            f"mientras que `currentMonthActivity` aísla exclusivamente los documentos "
            f"fechados en {effective_month}."
        ),
        "SampleCapPerResource": bounded_limit,
        "subReads": sub_reads,
        "truncationWarnings": truncation_warnings,
        "resources": resource_coverage,
        "notes": coverage_notes,
    }

    collections_block_canonical = {
        "overdueCount": len(overdue_invoices_canonical),
        "overdueTotal": overdue_total_pa,
        "upcomingDueWithin7DaysCount": len(upcoming_due_invoices_canonical),
        "upcomingDueWithin7DaysTotal": upcoming_total_pa,
        "openIssuedCount": len(open_issued_invoices_canonical),
        "openIssuedNominalTotal": open_issued_nominal_pa,
        "realOutstandingBalanceDeterminable": False,
        "unpaidNominalSemantics": UNPAID_NOMINAL_SEMANTICS,
        "unpaidNominalLabel": UNPAID_NOMINAL_LABEL_ES,
        "draftExcludedCount": len(draft_invoices_canonical),
        "draftExcludedTotal": draft_excluded_pa,
        "overdueInvoices": overdue_invoices_canonical,
        "upcomingDueInvoices": upcoming_due_invoices_canonical,
        "draftInvoicesExcluded": draft_invoices_canonical,
        "ruleApplied": (
            "Solo las facturas emitidas no pagadas (`sent`, `overdue`, `partially_paid`, "
            "`unpaid`, `issued`) cuentan como cuentas por cobrar; los borradores (`draft`) "
            "se excluyen estrictamente de ingresos/cobros devengados. Dado que el esquema "
            "público no expone cobros parciales por factura, `openIssuedNominalTotal` "
            "representa el importe nominal de facturas no marcadas como pagadas y "
            "`realOutstandingBalanceDeterminable` es `false`."
        ),
    }

    collections_block_snake = {
        "issued_open_totals_by_currency": _flat_currency_map(open_issued_nominal_pa),
        "open_issued_nominal_total": open_issued_nominal_pa,
        "real_outstanding_balance_determinable": False,
        "unpaid_nominal_semantics": UNPAID_NOMINAL_SEMANTICS,
        "unpaid_nominal_label": UNPAID_NOMINAL_LABEL_ES,
        "overdue_totals_by_currency": _flat_currency_map(overdue_total_pa),
        "overdue_total": overdue_total_pa,
        "overdue_count": len(overdue_items_snake),
        "overdue_items": overdue_items_snake,
        "upcoming_due_count": len(upcoming_due_items_snake),
        "upcoming_due_total": upcoming_total_pa,
        "upcoming_due_items": upcoming_due_items_snake,
        "draft_invoices_excluded_from_receivables": {
            "count": len(draft_invoices_snake),
            "totals_by_currency": _flat_currency_map(draft_excluded_pa),
            "total": draft_excluded_pa,
            "items": draft_invoices_snake,
        },
    }

    quotes_block_canonical = {
        "actionableCount": len(actionable_quotes_canonical),
        "actionableTotal": actionable_quotes_pa,
        "quotes": actionable_quotes_canonical,
    }
    quotes_block_snake = {
        "count": len(quotes_to_follow_up_snake),
        "actionable_count": len(actionable_quotes_canonical),
        "actionable_total": actionable_quotes_pa,
        "items": quotes_to_follow_up_snake,
        "quotes": actionable_quotes_canonical,
    }

    expenses_block_canonical = {
        "totalSampledCount": len(expenses),
        "totalSampledAmount": total_expenses_pa,
        "nonDeductibleValidCount": non_deductible_valid_count,
        "missingMetadataCount": missing_metadata_count,
        "expensesToReview": expenses_to_review_canonical,
        "taxDeductibleRuleNote": (
            "`taxDeductible=false` es un estado fiscal válido (gasto no deducible) "
            "y nunca se interpreta como error de API."
        ),
    }
    expenses_block_snake = {
        "count": len(expenses_to_review_snake),
        "total_sampled_count": len(expenses),
        "total_sampled_amount": total_expenses_pa,
        "non_deductible_valid_count": non_deductible_valid_count,
        "missing_metadata_count": missing_metadata_count,
        "items": expenses_to_review_snake,
    }

    crm_block_canonical = {
        "clientsInspectedCount": len(clients_to_inspect),
        "followUpsCount": len(crm_follow_ups_canonical),
        "followUps": crm_follow_ups_canonical,
    }

    safety_contract_canonical = {
        "workflowReadOnly": True,
        "mutatingToolsCalledCount": 0,
        "allSuggestedActionsRequireHumanApproval": True,
        "orchestratedTools": orchestrated_tools_called,
    }

    result: dict[str, Any] = {
        "success": True,
        "ok": True,
        "question": BRIEF_QUESTION_ES,
        "asOfDate": today_iso,
        "as_of_date": today_iso,
        "executiveSummary": executive_summary,
        "executive_summary": executive_summary,
        "coverage": coverage_block,
        "collectionsAndDueDates": collections_block_canonical,
        "collections_and_due_dates": collections_block_snake,
        "quotesToFollowUp": quotes_block_canonical,
        "quotes_to_follow_up": quotes_block_snake,
        "expensesToReview": expenses_block_canonical,
        "expenses_to_review": expenses_block_snake,
        "crmFollowUps": crm_block_canonical,
        "crm_follow_ups": crm_follow_ups_snake,
        "currentMonthActivity": current_month_activity,
        "current_month_activity": current_month_activity,
        "PrioritizedSuggestedActions": prioritized_actions_canonical,
        "suggested_actions": suggested_actions_snake,
        "knownUnknowns": known_unknowns,
        "known_unknowns": known_unknowns,
        "safetyContract": safety_contract_canonical,
        "safety_contract": {
            "read_only_execution": True,
            "human_approval_required": True,
            "auto_executed": False,
            "mutating_tools_called_count": 0,
            "orchestrated_tools": orchestrated_tools_called,
        },
        "provenance": provenance_block,
    }
    result["markdown"] = _render_daily_brief_markdown(result)
    return result


def brief(
    ctx: Any = None,
    *,
    as_of_date: str | None = None,
    period_month: str | None = None,
    page_limit: int = 20,
    max_crm_clients_to_inspect: int = 5,
) -> dict[str, Any]:
    """Slash-command entry point for ``/frihet brief`` delegating to ``frihet_daily_brief``."""
    return frihet_daily_brief(
        ctx=ctx,
        as_of_date=as_of_date,
        period_month=period_month,
        page_limit=page_limit,
        max_crm_clients_to_inspect=max_crm_clients_to_inspect,
    )


def build_scenario1_complete_workspace_client() -> Any:
    """Reference Scenario 1 fixture client (complete coverage) matching frihet-mcp#257."""

    class _Scenario1Client:
        def call_mcp(
            self,
            server: str,
            tool: str,
            arguments: dict[str, Any],
            timeout: float | None = None,
        ) -> dict[str, Any]:
            if tool == "get_business_context":
                return {
                    "ok": True,
                    "result": {
                        "company": {"name": "Estudio Atlántico SL", "currency": "EUR"},
                        "period": arguments.get("period") or "2026-10",
                    },
                }
            if tool == "list_invoices":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "inv_overdue_1",
                                "invoiceNumber": "F-2026-041",
                                "clientId": "cli_1",
                                "clientName": "Norte Digital SL",
                                "status": "overdue",
                                "issueDate": "2026-09-15",
                                "dueDate": "2026-10-15",
                                "total": 1210,
                                "currency": "EUR",
                            },
                            {
                                "id": "inv_upcoming_1",
                                "invoiceNumber": "F-2026-048",
                                "clientId": "cli_2",
                                "clientName": "Costa Verde SA",
                                "status": "sent",
                                "issueDate": "2026-10-20",
                                "dueDate": "2026-11-01",
                                "items": [
                                    {
                                        "description": "Consultoría técnica",
                                        "quantity": 2,
                                        "unitPrice": 500,
                                    }
                                ],
                                "taxRate": 21,
                                "irpfRate": 0,
                                "currency": "EUR",
                            },
                            {
                                "id": "inv_draft_1",
                                "invoiceNumber": "BORR-2026-009",
                                "clientId": "cli_1",
                                "clientName": "Norte Digital SL",
                                "status": "draft",
                                "issueDate": "2026-10-27",
                                "dueDate": "2026-11-27",
                                "total": 3630,
                                "currency": "EUR",
                            },
                            {
                                "id": "inv_paid_1",
                                "invoiceNumber": "F-2026-030",
                                "clientId": "cli_2",
                                "clientName": "Costa Verde SA",
                                "status": "paid",
                                "issueDate": "2026-09-01",
                                "dueDate": "2026-10-01",
                                "total": 900,
                                "currency": "EUR",
                            },
                        ],
                        "total": 4,
                    },
                }
            if tool == "list_quotes":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "quo_expiring_1",
                                "quoteNumber": "P-2026-014",
                                "clientId": "cli_1",
                                "clientName": "Norte Digital SL",
                                "status": "sent",
                                "issueDate": "2026-10-15",
                                "validUntil": "2026-10-31",
                                "total": 2420,
                                "currency": "EUR",
                            }
                        ],
                        "total": 1,
                    },
                }
            if tool == "list_expenses":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "exp_nondeductible_1",
                                "description": "Comida representación cliente",
                                "vendorName": "Restaurante Bahía",
                                "category": "meals",
                                "date": "2026-10-22",
                                "amount": 85.5,
                                "currency": "EUR",
                                "taxDeductible": False,
                            },
                            {
                                "id": "exp_missing_meta_1",
                                "description": "Suscripción cloud infraestructura",
                                "date": "2026-10-24",
                                "total": 149,
                                "currency": "EUR",
                                "taxDeductible": True,
                            },
                        ],
                        "total": 2,
                    },
                }
            if tool == "list_clients":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {"id": "cli_1", "name": "Norte Digital SL", "email": "pagos@nortedigital.es"},
                            {"id": "cli_2", "name": "Costa Verde SA", "email": "admin@costaverde.es"},
                        ],
                        "total": 2,
                    },
                }
            if tool == "list_client_activities":
                cid = arguments.get("clientId")
                return {
                    "ok": True,
                    "result": {
                        "data": (
                            [
                                {
                                    "id": "act_1",
                                    "type": "email",
                                    "title": "Envío de factura F-2026-041",
                                    "date": "2026-10-16",
                                }
                            ]
                            if cid == "cli_1"
                            else []
                        ),
                        "total": 1 if cid == "cli_1" else 0,
                    },
                }
            return {"ok": False, "error": f"Unknown tool: {tool}"}

    return _Scenario1Client()


def build_scenario2_partial_coverage_client() -> Any:
    """Reference Scenario 2 fixture client (partial coverage) matching frihet-mcp#257."""

    class _Scenario2Client:
        def call_mcp(
            self,
            server: str,
            tool: str,
            arguments: dict[str, Any],
            timeout: float | None = None,
        ) -> dict[str, Any]:
            if tool == "get_business_context":
                return {
                    "ok": True,
                    "result": {
                        "company": {"name": "Grupo Insular SL", "currency": "EUR"},
                    },
                }
            if tool == "list_invoices":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "inv_101",
                                "invoiceNumber": "F-2026-101",
                                "clientId": "cli_a",
                                "clientName": " Logística Sur SL",
                                "status": "overdue",
                                "dueDate": "2026-10-10",
                                "total": 500,
                                "currency": "EUR",
                            },
                            {
                                "id": "inv_102",
                                "invoiceNumber": "BORR-2026-102",
                                "clientId": "cli_b",
                                "clientName": "Importadora Atlántico",
                                "status": "draft",
                                "dueDate": "2026-11-15",
                                "total": 1500,
                                "currency": "EUR",
                            },
                        ],
                        "total": 47,
                    },
                }
            if tool == "list_quotes":
                return {
                    "ok": False,
                    "error": "Upstream timeout while reading quotes collection",
                }
            if tool == "list_expenses":
                return {
                    "ok": True,
                    "result": {
                        "data": [
                            {
                                "id": "exp_201",
                                "description": "Sanción aparcamiento",
                                "vendorName": "Ayuntamiento",
                                "category": "other",
                                "date": "2026-10-19",
                                "amount": 90,
                                "currency": "EUR",
                                "taxDeductible": False,
                            }
                        ],
                        "total": 1,
                    },
                }
            if tool == "list_clients":
                return {
                    "ok": True,
                    "result": {
                        "data": [{"id": "cli_a", "name": "Logística Sur SL"}],
                        "total": 1,
                    },
                }
            if tool == "list_client_activities":
                return {"ok": True, "result": {"data": [], "total": 0}}
            return {"ok": False, "error": f"Unknown tool: {tool}"}

    return _Scenario2Client()


def to_json(payload: Any) -> str:
    """Render a dict result as pretty JSON suitable for slash-command output."""
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)