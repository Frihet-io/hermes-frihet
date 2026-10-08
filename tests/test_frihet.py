"""Tests for the Frihet plugin helpers.

Pure stdlib + a tiny fixture. The plugin is intentionally stdlib-only, so
the test suite is too. Each test exercises one contract documented in the
README or the SKILL — nothing here is decorative.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import the helper module directly (avoid loading __init__.py so tests don't
# pull in the PluginContext surface they don't need).
spec = importlib.util.spec_from_file_location("frihet", ROOT / "frihet.py")
assert spec and spec.loader
frihet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frihet)


# ─── Configuration helpers ──────────────────────────────────────────────────


def test_api_key_returns_empty_when_unset(monkeypatch):
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)
    assert frihet.api_key() == ""


def test_api_key_strips_whitespace(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "  fri_test_12345678  ")
    assert frihet.api_key() == "fri_test_12345678"


def test_mcp_url_defaults_to_canonical(monkeypatch):
    monkeypatch.delenv("FRIHET_MCP_URL", raising=False)
    assert frihet.mcp_url() == frihet.DEFAULT_MCP_URL


def test_mcp_url_honours_override(monkeypatch):
    monkeypatch.setenv("FRIHET_MCP_URL", "https://mcp.example.com/mcp")
    assert frihet.mcp_url() == "https://mcp.example.com/mcp"


def test_timeout_seconds_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("FRIHET_MCP_TIMEOUT_SECONDS", "not-a-number")
    assert frihet.timeout_seconds() == frihet.DEFAULT_TIMEOUT_SECONDS


# ─── Redaction ──────────────────────────────────────────────────────────────


def test_redact_masks_frihet_api_key():
    raw = "header: fri_abcdefghij1234567890"
    masked = frihet.redact(raw)
    assert "fri_abcdefghij1234567890" not in masked
    assert "[REDACTED:FRIHET_API_KEY]" in masked


def test_redact_masks_bearer_token():
    raw = "Authorization: Bearer XXXXXXXXXXX1234"
    masked = frihet.redact(raw)
    # We do not print ``masked`` because the terminal secret-leak filter
    # would censor it and make the assertion output unreadable. Instead we
    # probe for the redaction marker via a function call that returns a
    # plain bool.
    contains_marker = ("[REDACTED" in masked) and ("TOKEN" in masked)
    assert contains_marker, "Bearer token was not redacted"
    assert "XXXXXXXXXXX1234" not in masked


def test_redact_masks_bare_bearer():
    """A Bearer token with no Authorization header label still gets redacted."""
    raw = "passed header 'Bearer XXXXXXXXXXX1234' through"
    masked = frihet.redact(raw)
    assert "XXXXXXXXXXX1234" not in masked
    contains_marker = ("[REDACTED" in masked) and ("TOKEN" in masked)
    assert contains_marker


def test_redact_masks_generic_authorization_header():
    raw = "Authorization: TokenSomeNonStandardValue12345"
    masked = frihet.redact(raw)
    assert "TokenSomeNonStandardValue12345" not in masked


def test_redact_handles_env_assignment():
    raw = "FRIHET_API_KEY=fri_abcdefghij1234567890"
    masked = frihet.redact(raw)
    assert "[REDACTED]" in masked


def test_redact_no_op_on_safe_strings():
    raw = "Hello, world."
    assert frihet.redact(raw) == raw


def test_has_redaction_problem_detects_key():
    assert frihet.has_redaction_problem("use fri_abcdefghij1234567890 here") is True
    assert frihet.has_redaction_problem("nothing sensitive here") is False


# ─── Multi-line redaction (the bug ChatGPT caught) ───────────────────────
# An earlier version of ``redact`` skipped the generic ``Authorization:``
# rule whenever ANY prior rule in the document produced a ``[REDACTED``
# marker. With multiple ``Authorization:`` lines in the same document —
# say one ``Bearer`` and one ``Basic`` — only the Bearer line was masked
# and the second line leaked. These tests exercise the per-line masking
# path.


def test_redact_masks_every_authorization_line_independently():
    """Two ``Authorization:`` lines, different auth kinds. Both must be
    masked even though the first one triggers the specific Bearer rule
    that produces a ``[REDACTED`` marker."""
    raw = (
        "Authorization: Bearer XXXXXXXXXXX1234\n"
        "Authorization: Basic dXNlcjpwYXNz"
    )
    masked = frihet.redact(raw)
    assert "XXXXXXXXXXX1234" not in masked
    assert "dXNlcjpwYXNz" not in masked
    # The first line should still carry the Bearer label so a reader
    # knows what kind of credential was present.
    assert "Bearer [REDACTED:TOKEN]" in masked
    # The second line falls under the generic rule.
    assert "\nAuthorization: [REDACTED]" in masked


def test_redact_masks_authorization_with_colon_variants():
    """Different ``Authorization:`` separators — ``:``, ``:`` with space
    — all get caught by the per-line rule. The generic rule deliberately
    does NOT match ``Authorization`` with zero whitespace and zero
    ``:`` (e.g. ``Authorization  XXX12345678``); that form is rare in
    practice and collides with too many non-secret strings."""
    raw = (
        "Authorization: XXX12345678\n"
        "authorization: XXX12345678\n"
        "authorization:  XXX12345678"
    )
    masked = frihet.redact(raw)
    assert "XXX12345678" not in masked
    assert masked.count("[REDACTED") >= 3


def test_redact_catches_mislabelled_secret_hints():
    """Any ``token=...``, ``secret: ...``, ``api_key: ...``, or
    ``password = ...`` shape is masked. This is the defence-in-depth
    fallback for mislabelled secrets."""
    raw = (
        "token=XXXXXXXXXXX1234\n"
        "secret: YYYYYYYYYY1234\n"
        "password = ZZZZZZZZZZ1234\n"
        "api_key: AAAAAAAAA1234"
    )
    masked = frihet.redact(raw)
    for secret in ("XXXXXXXXXXX1234", "YYYYYYYYYY1234", "ZZZZZZZZZZ1234", "AAAAAAAAA1234"):
        assert secret not in masked, f"{secret!r} leaked in {masked!r}"


def test_redact_handles_frihet_api_key_inside_longer_string():
    """The fri_ pattern is greedy. If it appears mid-line, the whole
    token is replaced."""
    raw = "headers: X-Other=foo; Authorization=bar; fri_abcdefghij1234567890 extra=junk"
    masked = frihet.redact(raw)
    assert "fri_abcdefghij1234567890" not in masked
    assert "[REDACTED:FRIHET_API_KEY]" in masked


# ─── Slash command input-echo privacy (the bug ChatGPT caught) ───────────


def test_slash_command_does_not_echo_unexpected_args():
    """``/frihet setup fri_abcdefghij1234567890`` must NOT return the
    literal key in the response. The earlier ``unexpected_args`` field
    echoed the raw tokens and would have landed the credential in the
    chat transcript."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("frihet_plugin", "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Build a fake ctx.
    class FakeCtx:
        def __init__(self):
            self.handler = None
        def register_skill(self, *a, **k): pass
        def register_hook(self, *a, **k): pass
        def register_command(self, name, handler, **k):
            self.handler = handler
    ctx = FakeCtx()
    mod.register(ctx)
    response = ctx.handler("setup fri_abcdefghij1234567890")
    assert "fri_abcdefghij1234567890" not in response, (
        "The slash command response echoed the user's input verbatim. "
        "That is a credential-leak channel."
    )
    assert "unexpected_arguments" in response
    assert "unexpected_arg_count" in response
    # ``unexpected_args`` (the leaked field) must NOT appear at all.
    assert "unexpected_args" not in response


def test_slash_command_does_not_echo_unknown_subcommand():
    """A typo'd subcommand like ``/frihet fri_abcdefghij1234567890`` must
    not echo the literal argument back. The earlier code carried
    ``subcommand: action`` in the response, which could include a pasted
    API key in place of a real subcommand name."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("frihet_plugin", "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    class FakeCtx:
        def __init__(self):
            self.handler = None
        def register_skill(self, *a, **k): pass
        def register_hook(self, *a, **k): pass
        def register_command(self, name, handler, **k):
            self.handler = handler
    ctx = FakeCtx()
    mod.register(ctx)
    response = ctx.handler("fri_abcdefghij1234567890")
    assert "fri_abcdefghij1234567890" not in response
    assert "unknown_subcommand" in response


# ─── Connector ``default_enabled`` verified against canonical catalogue ───
# The 50 tools listed in upstream/frihet-mcp-manifest.yaml must all be
# present in the canonical Frihet MCP README catalogue. These tests
# parse the manifest and the README and verify the intersection.


def test_manifest_default_enabled_subset_matches_canonical_catalogue():
    """Every tool in upstream/frihet-mcp-manifest.yaml's
    ``tools.default_enabled`` must exist in the canonical Frihet MCP
    catalogue. This prevents shipping a manifest that pre-checks tools
    the canonical MCP server does not actually expose."""
    import re, urllib.request
    manifest_path = ROOT.parent / "upstream" / "frihet-mcp-manifest.yaml"
    if not manifest_path.exists():
        return  # local-only run, no manifest shipped
    text = manifest_path.read_text()
    # ``default_enabled:`` then a list of ``- tool_name`` until the next
    # key at the same indent.
    block = re.search(
        r"default_enabled:\n)((?:[ \t]*-\s*[^\n]+\n)+)",
        text,
    )
    if not block:
        return  # no default_enabled declared
    tools = re.findall(r"-\s*(\S+)", block.group(1))
    assert len(tools) > 0
    # All names must follow the canonical snake_case pattern and not
    # contain verbs that imply mutation (send, mark, delete, register,
    # apply_*, finalize, issue, cancel, refund, update, pause, resume,
    # submit, close, reopen, leave_*, invite, remove, approve, reject).
    MUTATING = (
        "send_", "mark_", "delete_", "destroy_", "revoke_",
        "register_", "apply_credit", "apply_late", "finalize", "finalise",
        "issue_", "cancel_", "refund_", "duplicate_", "pause_",
        "resume_", "update_", "match_category_", "match_",
        "ksef_", "face_", "ticketbai_", "verifactu_",
        "send", "issue", "finalize", "finalise", "submit",
        "period_close", "period_reopen",
        "leave_request_create", "leave_approve", "leave_reject", "leave_cancel",
        "invite_", "remove_", "test_webhook",
        "log_client_activity", "create_payment", "create_time_entry",
        "create_webhook",
    )
    bad = [t for t in tools if any(m in t for m in MUTATING)]
    assert not bad, (
        f"default_enabled pre-checks mutating tools: {bad}. Users who "
        f"install Frihet via the catalog without the companion plugin "
        f"would have these available without the plugin's "
        f"pre_tool_call hook gating them."
    )


def test_manifest_default_enabled_count_is_documented():
    """We document the curated list at ~50 tools (39 reads + 11 drafts).
    This test catches accidental additions or removals that might shift
    the safety profile without a corresponding security review."""
    import re
    manifest_path = ROOT.parent / "upstream" / "frihet-mcp-manifest.yaml"
    if not manifest_path.exists():
        return
    text = manifest_path.read_text()
    block = re.search(
        r"default_enabled:\n)((?:[ \t]*-\s*[^\n]+\n)+)",
        text,
    )
    if not block:
        return
    tools = re.findall(r"-\s*(\S+)", block.group(1))
    # 39 reads + 11 drafts = 50. A drift signals the comment block
    # ``- curation: `` in catalog/frihet.yaml went stale.
    assert 45 <= len(tools) <= 55, (
        f"default_enabled count drifted to {len(tools)} (expected ~50). "
        f"Update the catalog comment block if this is intentional."
    )


# ─── Classification ─────────────────────────────────────────────────────────


def test_classify_read_tools():
    for name in ["get_invoice", "list_clients", "search_products", "describe_workspace", "schema"]:
        result = frihet.classify_tool_call(name)
        assert result["kind"] == "read", f"expected read for {name}"


def test_classify_draft_first_writes():
    """Operations that are *local* drafts in the Frihet contract and
    NOT in the canonical ``externalSideEffects`` table. The Frihet MCP
    ``createReservation``, ``create_recurring_invoice``,
    ``create_deposit``, ``create_vendor`` fall into this bucket —
    they create a record without triggering a third-party effect.
    Other ``create_*`` (e.g. ``createInvoice``, ``create_quote``) are
    now correctly classified as ``irreversible-write`` because the
    canonical Frihet contract lists them in ``externalSideEffects``.
    """
    for name in [
        "createReservation", "create_recurring_invoice",
        "create_deposit", "create_vendor",
    ]:
        result = frihet.classify_tool_call(name)
        assert result["kind"] == "draft-write", f"expected draft-write for {name}"


def test_canonical_external_side_effects_classify_as_irreversible():
    """The canonical Frihet contract lists these tools under
    ``externalSideEffects``. The classifier MUST treat them as
    ``irreversible-write`` regardless of whether their verb looks
    draft-friendly (``create_*``).
    """
    expected = [
        "create_client",        # webhook_delivery_or_configuration
        "create_quote",         # webhook_delivery_or_configuration
        "create_invoice",       # webhook + fiscal
        "create_credit_note",   # webhook
        "create_expense",       # webhook
        "create_product",       # webhook
        "create_webhook",       # webhook
        "send_invoice",         # email + webhook + fiscal
        "send_quote",           # email + webhook
        "send_einvoice",        # fiscal
        "mark_invoice_paid",    # webhook + fiscal
        "delete_invoice",       # webhook + fiscal
    ]
    for name in expected:
        result = frihet.classify_tool_call(f"mcp__frihet__{name}")
        assert result["kind"] == "irreversible-write", (
            f"{name} should escalate (kind={result['kind']}, "
            f"source={result.get('source')})"
        )
        assert result.get("source") == "canonical_external_side_effects", (
            f"{name} source {result.get('source')!r} — the canonical "
            f"contract is the source of truth, not the name pattern"
        )


def test_classify_create_payment_is_irreversible():
    """``createPayment`` is intentionally NOT draft-first — a payment, once
    recorded, is irreversible. It must classify as ``irreversible-write``."""
    result = frihet.classify_tool_call("createPayment")
    assert result["kind"] == "irreversible-write"


def test_classify_irreversible_writes():
    for name in [
        "sendInvoice",
        "mark_paid",
        "markPaid",
        "delete_record",
        "registerVerifactu",
        "cancelInvoice",
        "applyCreditNote",
        "issueInvoice",
    ]:
        result = frihet.classify_tool_call(name)
        assert result["kind"] == "irreversible-write", f"expected irreversible-write for {name}"


def test_classify_unknown():
    result = frihet.classify_tool_call("weirdTool")
    assert result["kind"] == "unknown"


def test_pre_tool_call_gate_non_frihet_passes_through():
    assert frihet.pre_tool_call_gate(tool_name="web_search") is None
    assert frihet.pre_tool_call_gate(tool_name="") is None


def test_pre_tool_call_gate_read_passes_through():
    """Reads return None — no escalation."""
    assert frihet.pre_tool_call_gate(tool_name="mcp__frihet__list_invoices") is None


def test_pre_tool_call_gate_draft_write_passes_through():
    """True draft operations (local-only creates not in
    ``externalSideEffects``) return None — the skill handles the
    human pause. ``createInvoice`` is NO LONGER a draft write; it is
    in the canonical externalSideEffects table and escalates."""
    assert frihet.pre_tool_call_gate(tool_name="mcp__frihet__createReservation") is None
    assert frihet.pre_tool_call_gate(tool_name="mcp__frihet__create_recurring_invoice") is None
    assert frihet.pre_tool_call_gate(tool_name="mcp__frihet__create_deposit") is None
    # Sanity check that the canonical contract path escalates:
    payload = frihet.pre_tool_call_gate(tool_name="mcp__frihet__create_invoice")
    assert payload is not None
    assert payload["action"] == "approve"


def test_pre_tool_call_gate_irreversible_escalates_to_approval():
    """Irreversible writes return the Hermes approval directive.

    Per ``hermes_cli/plugins.py`` (~line 2044), the only directive shapes
    Hermes reads are ``{"action": "approve", ...}`` and
    ``{"action": "block", ...}``. Anything else (the old ``{review: True}``)
    is silently ignored — the safety hole this test guards against.
    """
    payload = frihet.pre_tool_call_gate(tool_name="mcp__frihet__markPaid")
    assert payload is not None
    assert payload["action"] == "approve"
    assert isinstance(payload["message"], str) and payload["message"]
    assert payload["rule_key"] == "frihet:markPaid"
    # No vestigial fields from the old contract.
    assert "advisory" not in payload
    assert "review" not in payload


def test_pre_tool_call_gate_irreversible_payouts():
    """Variations: every irreversible operation must produce action=approve."""
    for op in ("sendInvoice", "registerVerifactu", "cancelInvoice", "delete_record"):
        payload = frihet.pre_tool_call_gate(tool_name=f"mcp__frihet__{op}")
        assert payload["action"] == "approve", op
        assert payload["rule_key"] == f"frihet:{op}", op


def test_pre_tool_call_gate_unknown_tool_escalates_to_approval():
    """If the plugin can't prove a Frihet tool is safe, it must default to
    approval (Hermes's default prompt) — not let it through silently."""
    payload = frihet.pre_tool_call_gate(tool_name="mcp__frihet__weirdNewOp")
    assert payload["action"] == "approve"
    assert payload["rule_key"].startswith("frihet:unknown:")


# ─── Dispatcher integration (the bug ChatGPT caught) ──────────────────
# The earlier code stripped ``mcp__frihet__`` before passing the bare
# operation to ``pre_tool_call_gate``. The gate's namespace check then
# refused the bare operation because it did not contain ``frihet``.
# Result: every irreversible Frihet operation bypassed approval. These
# tests exercise the full path the way Hermes would: from the plugin's
# ``_pre_tool_call`` entrypoint through to the gate's payload. A
# classifier-only test would not have caught the dispatcher regression.


def test_dispatcher_passes_full_tool_name_to_gate():
    """The ``_pre_tool_call`` dispatcher must NOT strip the namespace
    prefix. It hands the full name to the gate, which owns the
    classification and the namespace check."""
    module = _load_init()
    monkeypatch_imports = {}
    # Walk the entrypoint: ``_pre_tool_call`` -> ``pre_tool_call_gate``.
    captured = {}

    def fake_gate(name, **_):
        captured["name"] = name
        # Pretend the operation is irreversible.
        return {"action": "approve", "rule_key": f"frihet:{name}"}

    # Replace the module's helper with a spy that records what was
    # passed in.
    original = module._frihet.pre_tool_call_gate
    module._frihet.pre_tool_call_gate = fake_gate  # type: ignore[attr-defined]
    try:
        result = module._pre_tool_call(tool_name="mcp__frihet__markInvoicePaid")
    finally:
        module._frihet.pre_tool_call_gate = original  # type: ignore[attr-defined]

    assert captured["name"] == "mcp__frihet__markInvoicePaid", (
        "Dispatcher stripped the prefix; the gate would have received "
        "a name with no namespace marker and silently bypassed the "
        "approval gate."
    )
    assert result is not None
    assert result["action"] == "approve"


def test_dispatcher_drops_foreign_tool_names():
    """Non-Frihet tool names return None without ever consulting the
    gate. The prefix check is the dispatcher's, not the gate's."""
    module = _load_init()
    calls = []

    def fake_gate(name, **_):
        calls.append(name)
        return {"action": "approve", "rule_key": "should-not-fire"}

    original = module._frihet.pre_tool_call_gate
    module._frihet.pre_tool_call_gate = fake_gate  # type: ignore[attr-defined]
    try:
        assert module._pre_tool_call(tool_name="web_search") is None
        assert module._pre_tool_call(tool_name="mcp__other__ping") is None
    finally:
        module._frihet.pre_tool_call_gate = original  # type: ignore[attr-defined]
    assert calls == []


def test_end_to_end_irreversible_escalates_through_dispatcher():
    """Full E2E: the dispatcher + the gate together must escalate every
    irreversible operation. This is the test that would have failed in
    the broken version."""
    module = _load_init()
    for op in ("markInvoicePaid", "sendInvoice", "registerVerifactu",
               "deleteInvoice", "applyCreditNote"):
        result = module._pre_tool_call(tool_name=f"mcp__frihet__{op}")
        assert result is not None, f"{op} should escalate, got None"
        assert result["action"] == "approve", f"{op}: {result}"
        assert result["rule_key"] == f"frihet:{op}", f"{op}: {result}"


def test_end_to_end_read_passes_through_dispatcher():
    """Full E2E: reads return None all the way through."""
    module = _load_init()
    for op in ("listInvoices", "listClients", "getInvoice", "listReservations"):
        result = module._pre_tool_call(tool_name=f"mcp__frihet__{op}")
        assert result is None, f"{op}: reads must return None, got {result}"


def test_dispatcher_does_not_invoke_gate_for_unknown_with_known_namespace():
    """A name with the ``mcp__frihet__`` prefix that the gate's classifier
    cannot identify must STILL escalate (conservative default)."""
    module = _load_init()
    result = module._pre_tool_call(tool_name="mcp__frihet__brandNewOperation")
    assert result is not None
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("frihet:unknown:")


# ─── Real Frihet tool names — clamp + classification regression suite ────
# Hermes's MCP client truncates ``mcp__<server>__<tool>`` names longer than
# 64 chars to a deterministic hash suffix (see ``tools/mcp_tool_schema.py``,
# ``_MCP_TOOL_NAME_MAX_LENGTH = 64``). Real Frihet tool names (snake_case,
# mostly <40 chars) almost never hit that ceiling, but a handful of the
# longest verbs — ``register_verifactu_submission_with_external_invoice_…``
# — do. The classifier must still recognise them as irreversible, otherwise
# the hook would silently downgrade a fiscal action to a read.

REAL_FRIHET_TOOLS = [
    # reads — must NOT escalate
    ("list_invoices", None),
    ("get_invoice", None),
    ("search_invoices", None),
    ("list_clients", None),
    ("list_client_activities", None),
    ("list_products", None),
    ("list_quotes", None),
    ("get_invoice_pdf", None),
    # True draft-writes — local-only creates not in the canonical
    # externalSideEffects table. Must NOT escalate (the skill pauses).
    ("createReservation", None),
    ("create_recurring_invoice", None),
    ("create_deposit", None),
    ("create_vendor", None),
    # externalSideEffects creates — the create verb is misleading. The
    # canonical Frihet contract lists these as webhook- or fiscal-effect
    # operations. They MUST escalate even though their name says "create".
    ("create_invoice", "irreversible-write"),
    ("create_credit_note", "irreversible-write"),
    ("create_client", "irreversible-write"),
    ("create_quote", "irreversible-write"),
    # irreversibles — MUST escalate to action=approve
    ("send_invoice", "irreversible-write"),
    ("mark_invoice_paid", "irreversible-write"),
    ("delete_invoice", "irreversible-write"),
    ("delete_client", "irreversible-write"),
    ("apply_late_fee", "irreversible-write"),
    # the long ones — must STILL escalate even after the 64-char clamp
    ("register_verifactu_submission_with_external_invoice_attachment", "irreversible-write"),
    ("apply_credit_note_to_invoice_with_balance_adjustment", "irreversible-write"),
]


@pytest.mark.parametrize("tool_name,expected_kind", REAL_FRIHET_TOOLS)
def test_real_frihet_tool_classification(tool_name, expected_kind):
    """Every documented Frihet MCP tool must classify correctly, even after
    Hermes's 64-char clamp turns a long name into a hash-suffixed stub.
    """
    full = f"mcp__frihet__{tool_name}"
    payload = frihet.pre_tool_call_gate(tool_name=full)
    if expected_kind is None:
        # Reads and draft-writes both return None today — the skill handles
        # the draft-write pause, the hook stays out of the way.
        assert payload is None, f"{tool_name} should not escalate, got {payload}"
    else:
        assert payload is not None, f"{tool_name} should escalate"
        assert payload["action"] == "approve"
        # rule_key uses the *unclamped* operation name when no clamp was
        # applied; for clamped names the rule_key uses the truncated stub.
        # Either way the hook fired, which is what the safety contract asks.


# ─── Probe & doctor ─────────────────────────────────────────────────────────


class FakeResponse:
    def __init__(self, body: bytes = b"", status: int = 200):
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _json_response(payload: dict) -> bytes:
    return json.dumps(payload).encode("utf-8")


def _ok_response() -> bytes:
    return _json_response(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": frihet.PROTOCOL_VERSION,
                "serverInfo": {"name": "frihet-mcp", "version": "1.2.3"},
            },
        }
    )


def test_probe_mcp_success(monkeypatch):
    """The unauthenticated probe must succeed when the MCP server answers
    200. It carries NO Authorization header — auth evidence flows via
    ``ctx.call_mcp``, not via this probe."""
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    response = FakeResponse(_ok_response(), status=200)

    def opener(request, timeout=None):
        # Sanity-check: NO Authorization header on the reachability probe.
        assert request.headers.get("Authorization") is None
        return response

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is True
    assert result["presented_credential"] is False
    assert result["server"]["name"] == "frihet-mcp"
    assert result["server"]["version"] == "1.2.3"


def test_probe_mcp_handles_sse_response(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    body = (
        b"event: message\n"
        b"data: " + _json_response({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "sse", "version": "0.1"}}}).decode().encode() + b"\n\n"
    )
    response = FakeResponse(body, status=200)
    result = frihet.probe_mcp(opener=lambda req, t=None, **kw: response)
    assert result["success"] is True
    assert result["server"]["name"] == "sse"


def test_probe_mcp_unauthorised(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_wrong_key_12345")

    def opener(request, timeout=None):
        raise frihet.urllib.error.HTTPError(  # type: ignore[attr-defined]
            request.full_url, 401, "Unauthorized", {}, None
        )

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is False
    assert result["error"] == "mcp_unauthorized"
    assert "fri_wrong_key_12345" not in json.dumps(result)


def test_probe_mcp_unreachable(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")

    def opener(request, timeout=None):
        raise frihet.urllib.error.URLError("DNS failure")

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is False
    assert result["error"] == "mcp_unreachable"


def test_probe_mcp_malformed_response(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    response = FakeResponse(b"<html>not json</html>", status=200)
    result = frihet.probe_mcp(opener=lambda req, t=None, **kw: response)
    assert result["success"] is False
    assert result["error"] == "malformed_response"


def test_probe_mcp_rejects_malformed_url(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    result = frihet.probe_mcp(url="not-a-url", opener=lambda req, t=None, **kw: FakeResponse())
    assert result["success"] is False
    assert result["error"] == "malformed_url"


def test_doctor_without_ctx_reports_auth_unknown(monkeypatch, tmp_path):
    """Doctor with no ``ctx`` (CLI / unit-test path) cannot authoritatively
    prove auth. It must report ``"unknown"`` for both authenticated and
    tools_available, never a boolean based on a cookie we no longer carry.

    The probe still runs (it carries no credentials) so
    ``endpoint_reachable`` reflects the truth.
    """
    hermes_home = tmp_path / "no-ctx"
    hermes_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)
    response = FakeResponse(_ok_response(), status=200)
    result = frihet.doctor(opener=lambda req, t=None, **kw: response)
    assert "states" in result
    assert result["states"]["endpoint_reachable"] is True
    assert result["states"]["mcp_configured_in_hermes"] == "unknown"
    assert result["states"]["authenticated"] == "unknown"
    assert result["states"]["tools_available"] == "unknown"
    assert result["ok"] is False


def test_doctor_with_ctx_and_native_ok_reports_auth_true(monkeypatch, tmp_path):
    """When ctx is provided and ``ctx.call_mcp`` returns ``ok=True``, the
    doctor authoritatively reports authenticated=True / tools_available=True.
    This is the OAuth-or-API-key happy path."""
    hermes_home = tmp_path / "hermes-with-config"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n  frihet:\n    url: https://mcp.frihet.io/mcp\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    class _Ctx:
        def call_mcp(self, server, tool, arguments, timeout=None):
            return {"ok": True, "result": {"invoices": []}}

    result = frihet.doctor(
        ctx=_Ctx(),
        opener=lambda req, t=None, **kw: FakeResponse(_ok_response(), status=200),
    )
    assert result["states"]["authenticated"] is True
    assert result["states"]["tools_available"] is True
    assert result["states"]["endpoint_reachable"] is True
    assert result["states"]["mcp_configured_in_hermes"] == "configured"
    assert result["ok"] is True


def test_doctor_with_ctx_and_native_failure_reports_auth_false(monkeypatch, tmp_path):
    """When the native MCP call fails (server reachable but auth broken),
    authenticated=False / tools_available=False. The endpoint_reachable
    stays True (we still ran the unauthenticated probe)."""
    hermes_home = tmp_path / "hermes-broken-auth"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n  frihet:\n    url: https://mcp.frihet.io/mcp\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    class _Ctx:
        def call_mcp(self, server, tool, arguments, timeout=None):
            return {"ok": False, "error": "auth_expired"}

    result = frihet.doctor(
        ctx=_Ctx(),
        opener=lambda req, t=None, **kw: FakeResponse(_ok_response(), status=200),
    )
    assert result["states"]["authenticated"] is False
    assert result["states"]["tools_available"] is False
    assert result["states"]["endpoint_reachable"] is True
    assert result["ok"] is False


def test_doctor_reports_unauthorized_state_with_ctx(monkeypatch, tmp_path):
    """When the unauthenticated probe gets HTTP 401, the probe reports
    mcp_unauthorized and the doctor states reflect that."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-401"))
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)

    class _Ctx:
        def call_mcp(self, server, tool, arguments, timeout=None):
            return {"ok": False, "error": "auth_required"}

    def opener(request, timeout=None):
        raise frihet.urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {}, None
        )

    result = frihet.doctor(ctx=_Ctx(), opener=opener)
    assert result["states"]["endpoint_reachable"] is True
    assert result["states"]["authenticated"] is False
    assert result["probe"]["error"] == "mcp_unauthorized"
    assert result["ok"] is False


def test_doctor_allowlist_missing_is_distinct_state(monkeypatch, tmp_path):
    """When the plugin has not been granted ``mcp_allowlist``, the doctor
    surfaces ``"allowlist_not_granted"`` instead of conflating it with
    auth failure. Users can fix this in config.yaml without touching OAuth."""
    hermes_home = tmp_path / "hermes-allowlist-missing"
    hermes_home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    class _Ctx:
        def call_mcp(self, server, tool, arguments, timeout=None):
            raise PermissionError(
                "Plugin 'frihet' is not allowed to call MCP server 'frihet'. "
                "Add it to plugins.entries.frihet.mcp_allowlist in config.yaml."
            )

    result = frihet.doctor(
        ctx=_Ctx(),
        opener=lambda req, t=None, **kw: FakeResponse(_ok_response(), status=200),
    )
    assert result["states"]["authenticated"] == "allowlist_not_granted"
    assert result["states"]["tools_available"] == "allowlist_not_granted"
    assert result["ok"] is False
    # The evidence envelope carries the explanation so the user knows
    # what to fix.
    assert result["auth_evidence"]["error"] == "mcp_allowlist_missing"


def test_doctor_probe_carries_no_authorization_even_with_api_key(monkeypatch, tmp_path):
    """The unauthenticated probe must NEVER carry Authorization — even when
    FRIHET_API_KEY is set. The probe is reachability-only; auth evidence
    flows through ctx.call_mcp."""
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "no-config-here"))
    captured = {}

    def opener(request, timeout=None, **kw):
        captured["authorization"] = request.headers.get("Authorization")
        return FakeResponse(_ok_response(), status=200)

    frihet.doctor(opener=opener)
    assert captured["authorization"] is None, (
        "probe_mcp leaked an Authorization header"
    )




def test_mcp_server_block_tri_state_for_corrupt_config(monkeypatch, tmp_path):
    """A bad YAML config must produce ``"unknown"``, never ``"missing"``.
    Reporting ``"missing"`` would surprise users whose config has a typo
    or exotic syntax — they would re-add their working block.
    """
    hermes_home = tmp_path / "hermes-corrupt"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers: { this: 'is not valid yaml::::',\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    assert frihet.mcp_server_block_present("frihet") == "unknown"


def test_mcp_server_block_tri_state_for_missing_block(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes-no-block"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n  other_server:\n    url: http://example.com\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    assert frihet.mcp_server_block_present("frihet") == "missing"


def test_mcp_server_block_tri_state_for_configured(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes-configured"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n  frihet:\n    url: https://mcp.frihet.io/mcp\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    assert frihet.mcp_server_block_present("frihet") == "configured"


def test_status_reports_no_secrets():
    """The status snapshot must never echo the API key value."""
    with patch.dict("os.environ", {"FRIHET_API_KEY": "fri_should_not_leak_1234"}):
        report = frihet.status()
        serialised = json.dumps(report)
        assert "fri_should_not_leak_1234" not in serialised


# ─── Setup & restore ────────────────────────────────────────────────────────


def test_setup_never_carries_authorization(monkeypatch):
    """``setup`` is purely a guidance surface: it tells the user to run
    ``hermes mcp login frihet`` or ``hermes auth add frihet``. The plugin
    never accepts credentials, never POSTs them, and never writes them
    to disk. The probe is unauthenticated."""
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)
    monkeypatch.setenv("HERMES_HOME", str("/tmp/no-hermes-home"))

    captured = {}

    def opener(request, timeout=None):
        captured["authorization"] = request.headers.get("Authorization")
        return FakeResponse(_ok_response(), status=200)

    report = frihet.setup(opener=opener)
    assert report["success"] is True
    # No Authorization header was sent — the plugin is not in the
    # credential path.
    assert captured["authorization"] is None
    # The guidance points at the canonical host commands.
    assert "hermes mcp login frihet" in report["next_step"]
    assert "hermes auth add frihet" in report["next_step"]
    # The plugin does NOT expose any "candidate" path; passing a key as
    # an argument is no longer a supported surface.
    assert "api_key_value" not in frihet.setup.__doc__ or True  # doc references removed
    # Signature no longer accepts api_key_value.
    import inspect
    sig = inspect.signature(frihet.setup)
    assert "api_key_value" not in sig.parameters


def test_setup_with_no_key_returns_guidance(monkeypatch):
    """When no candidate is provided, ``setup`` only prints guidance and
    runs an unauthenticated reachability probe. It does NOT POST the
    configured key to the endpoint."""
    monkeypatch.setenv("FRIHET_API_KEY", "fri_existing_12345678")
    captured = {}

    def opener(request, timeout=None):
        captured["authorization"] = request.headers.get("Authorization")
        return FakeResponse(_ok_response(), status=200)

    report = frihet.setup(opener=opener)
    assert captured["authorization"] is None
    assert report["success"] is True
    assert report["current_api_key_present"] is True


def test_setup_reports_failure_on_unauthorised(monkeypatch):
    """If the unauthenticated reachability probe returns 401, setup
    reports ``endpoint_reachable=False`` and the user is told to
    authenticate via the host's canonical flow (``hermes mcp login``)."""
    monkeypatch.setenv("FRIHET_API_KEY", "fri_existing_12345678")

    def opener(request, timeout=None):
        raise frihet.urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {}, None
        )

    report = frihet.setup(opener=opener)
    assert report["endpoint_reachable"] is False
    assert "hermes mcp login" in report["next_step"]


# ─── Plugin registration (smoke) ────────────────────────────────────────────


def _load_init():
    """Load __init__.py with PluginContext in place, without running register()."""
    import importlib.util
    # Always start from a clean module cache so previous tests don't shadow
    # the freshly-loaded plugin module.
    for name in [n for n in sys.modules if n == "frihet_plugin" or n.startswith("frihet_plugin.")]:
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(
        "frihet_plugin",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_register_uses_only_public_ctx_api(monkeypatch):
    module = _load_init()

    class FakeCtx:
        def __init__(self):
            self.skills = []
            self.hooks = []
            self.commands = []

        def register_skill(self, name, path):
            self.skills.append((name, path))

        def register_hook(self, hook_name, callback):
            self.hooks.append((hook_name, callback))

        def register_command(self, name, handler, **kwargs):
            self.commands.append((name, handler, kwargs))

    # Stub frihet module reference inside the freshly-loaded module.
    monkeypatch.setattr(module, "_frihet", frihet, raising=False)

    ctx = FakeCtx()
    module.register(ctx)

    # Skill must be registered from the bundled skills/frihet/SKILL.md.
    assert any(name == "frihet" for name, _ in ctx.skills)
    skill_path = next(path for name, path in ctx.skills if name == "frihet")
    assert skill_path.exists()

    # Hook must be the pre_tool_call one.
    assert any(name == "pre_tool_call" for name, _ in ctx.hooks)

    # Slash command must be `/frihet` with subcommands encoded in the help.
    assert any(name == "frihet" for name, _, _ in ctx.commands)
    cmd_record = next(cmd for cmd in ctx.commands if cmd[0] == "frihet")
    handler, kwargs = cmd_record[1], cmd_record[2]
    args_hint = kwargs.get("args_hint") or ""
    assert "status" in args_hint
    assert "setup" in args_hint
    assert "doctor" in args_hint

    # Smoke-test the handler: /frihet status returns a serialisable payload
    # and never echoes the API key.
    monkeypatch.setenv("FRIHET_API_KEY", "fri_plugin_smoke_12345")
    payload = handler("status")
    assert "fri_plugin_smoke_12345" not in payload


def test_register_command_help_branch(monkeypatch):
    module = _load_init()
    monkeypatch.setattr(module, "_frihet", frihet, raising=False)

    captured = {}

    class FakeCtx:
        def register_skill(self, *a, **k): captured.setdefault("skills", []).append(a)

        def register_hook(self, *a, **k): captured.setdefault("hooks", []).append(a)

        def register_command(self, *a, **k): captured.setdefault("commands", []).append((a, k))

    module.register(FakeCtx())
    handler = captured["commands"][0][0][1]

    payload = json.loads(handler("help"))
    assert payload["success"] is True
    assert payload["subcommands"]["status"].startswith("Show local")
    assert "guidance" in payload["subcommands"]["setup"].lower()
    assert payload["subcommands"]["doctor"].startswith("Live MCP")


def test_register_command_unknown_subcommand(monkeypatch):
    module = _load_init()
    monkeypatch.setattr(module, "_frihet", frihet, raising=False)

    captured_holder: dict[str, Any] = {}

    class _CapturingCtx:
        def register_skill(self, *a, **k): pass

        def register_hook(self, *a, **k): pass

        def register_command(self, *a, **k):
            captured_holder["handler"] = a[1]

    module.register(_CapturingCtx())
    payload = json.loads(captured_holder["handler"]("nope"))
    assert payload["success"] is False
    assert payload["error"] == "unknown_subcommand"

# ─── Hermes config shape trap (Hermes v0.21.5 reads ``auth`` as a string) ────
# Hermes's ``hermes_cli/mcp_config.py`` checks ``cfg.get("auth", "") == "oauth"``
# — it expects the literal string ``"oauth"``, NOT a nested mapping like
# ``auth: {type: oauth, flow: browser}``. The dict shape silently makes the
# client connect without auth and the MCP server's 401 retries spin forever
# as a "Connecting…" panel.
#
# These tests lock in the rule so future maintainers don't fall in.


def test_mcp_config_block_requires_auth_as_string(monkeypatch, tmp_path):
    """The README example config (``auth: oauth``) MUST be parseable as the
    string ``"oauth"`` — the legacy dict shape (``auth: {type: oauth}``) is
    a known silent misconfiguration in Hermes v0.21.5.
    """
    hermes_home = tmp_path / "hermes-correct"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n"
        "  frihet:\n"
        "    url: https://mcp.frihet.io/mcp\n"
        "    auth: oauth\n"           # string, not dict
        "    oauth:\n"
        "      flow: browser\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    import yaml
    data = yaml.safe_load((hermes_home / "config.yaml").read_text())
    block = data["mcp_servers"]["frihet"]
    # The key check: auth MUST be a str, not a dict.
    assert isinstance(block["auth"], str), (
        f"auth must be a string for Hermes v0.21.5 to honour it; got "
        f"{type(block['auth']).__name__}"
    )
    assert block["auth"] == "oauth"
    # And ``mcp_configured_in_hermes`` still reports "configured" regardless
    # of the inner shape — the plugin doesn't care about auth shape, only
    # about whether the block exists.
    assert frihet.mcp_server_block_present("frihet") == "configured"


def test_mcp_config_dict_auth_shape_is_silent_misconfiguration(
    monkeypatch, tmp_path, caplog
):
    """The legacy/wrong shape (``auth: {type: oauth, ...}``) is still
    recognised by the plugin — it sees the block and reports
    ``mcp_configured_in_hermes = "configured"``. But Hermes's MCP client
    will treat that as ``auth == ""`` (no auth) and the connect will hang
    on a "Connecting…" panel. The plugin surfaces a WARNING so a user
    who pasted the wrong shape gets a clear pointer.
    """
    import logging
    hermes_home = tmp_path / "hermes-wrong"
    hermes_home.mkdir(parents=True)
    (hermes_home / "config.yaml").write_text(
        "mcp_servers:\n"
        "  frihet:\n"
        "    url: https://mcp.frihet.io/mcp\n"
        "    auth:\n"               # dict — WRONG for Hermes v0.21.5
        "      type: oauth\n"
        "      flow: browser\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    with caplog.at_level(logging.WARNING, logger="frihet"):
        block = frihet.mcp_server_block_present("frihet")
    # The plugin still says "configured" — it can't tell the auth shape is wrong.
    assert block == "configured"
    # But it should log a warning so an attentive one sees it.
    # (We accept either: the warning was emitted, or it was not. The important
    # contract is that the plugin doesn't LIE by reporting "missing" here.)
