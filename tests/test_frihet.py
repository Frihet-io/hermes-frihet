"""Tests for the Frihet plugin helpers.

Pure stdlib + a tiny fixture. The plugin is intentionally stdlib-only, so
the test suite is too. Each test exercises one contract documented in the
README or the SKILL — nothing here is decorative.
"""

from __future__ import annotations

import importlib.util
import json
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


# ─── Classification ─────────────────────────────────────────────────────────


def test_classify_read_tools():
    for name in ["get_invoice", "list_clients", "search_products", "describe_workspace", "schema"]:
        result = frihet.classify_tool_call(name)
        assert result["kind"] == "read", f"expected read for {name}"


def test_classify_draft_first_writes():
    for name in ["createInvoice", "create_quote", "create_credit_note"]:
        result = frihet.classify_tool_call(name)
        assert result["kind"] == "draft-write", f"expected draft-write for {name}"


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
    """Draft writes return None — the skill handles the human pause."""
    assert frihet.pre_tool_call_gate(tool_name="mcp__frihet__createInvoice") is None


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
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    response = FakeResponse(_ok_response(), status=200)

    def opener(request, timeout):
        # Sanity-check the request was authorised and used the canonical URL.
        assert request.headers.get("Authorization") == "Bearer fri_test_12345678"
        return response

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is True
    assert result["server"]["name"] == "frihet-mcp"
    assert result["server"]["version"] == "1.2.3"


def test_probe_mcp_handles_sse_response(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    body = (
        b"event: message\n"
        b"data: " + _json_response({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "sse", "version": "0.1"}}}).decode().encode() + b"\n\n"
    )
    response = FakeResponse(body, status=200)
    result = frihet.probe_mcp(opener=lambda req, t: response)
    assert result["success"] is True
    assert result["server"]["name"] == "sse"


def test_probe_mcp_unauthorised(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_wrong_key_12345")

    def opener(request, timeout):
        raise frihet.urllib.error.HTTPError(  # type: ignore[attr-defined]
            request.full_url, 401, "Unauthorized", {}, None
        )

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is False
    assert result["error"] == "mcp_unauthorized"
    assert "fri_wrong_key_12345" not in json.dumps(result)


def test_probe_mcp_unreachable(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")

    def opener(request, timeout):
        raise frihet.urllib.error.URLError("DNS failure")

    result = frihet.probe_mcp(opener=opener)
    assert result["success"] is False
    assert result["error"] == "mcp_unreachable"


def test_probe_mcp_malformed_response(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    response = FakeResponse(b"<html>not json</html>", status=200)
    result = frihet.probe_mcp(opener=lambda req, t: response)
    assert result["success"] is False
    assert result["error"] == "malformed_response"


def test_probe_mcp_rejects_malformed_url(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    result = frihet.probe_mcp(url="not-a-url", opener=lambda req, t: FakeResponse())
    assert result["success"] is False
    assert result["error"] == "malformed_url"


def test_doctor_without_api_key_still_runs_probe(monkeypatch):
    """Doctor is a connectivity probe. Without ``FRIHET_API_KEY``, the probe
    is sent without an Authorization header. The Frihet MCP may accept the
    request (demo / unauthenticated discovery in the future) or reject with
    401 — both are valid outcomes the user needs to see, so we do NOT skip
    the probe silently.
    """
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)
    response = FakeResponse(_ok_response(), status=200)
    result = frihet.doctor(opener=lambda req, t: response)
    assert result["ok"] is True
    assert result["probe"]["success"] is True


def test_doctor_with_api_key_sends_bearer(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_test_12345678")
    response = FakeResponse(_ok_response(), status=200)
    captured = {}

    def opener(request, timeout):
        captured["authorization"] = request.headers.get("Authorization", "")
        return response

    result = frihet.doctor(opener=opener)
    assert result["ok"] is True
    assert captured["authorization"] == "Bearer fri_test_12345678"


def test_status_reports_no_secrets():
    """The status snapshot must never echo the API key value."""
    with patch.dict("os.environ", {"FRIHET_API_KEY": "fri_should_not_leak_1234"}):
        report = frihet.status()
        serialised = json.dumps(report)
        assert "fri_should_not_leak_1234" not in serialised


# ─── Setup & restore ────────────────────────────────────────────────────────


def test_setup_restores_previous_env(monkeypatch):
    monkeypatch.delenv("FRIHET_API_KEY", raising=False)

    def opener(request, timeout):
        # The candidate key was used in the request, and it should NOT leak
        # into the persisted env after setup() returns.
        assert "Bearer fri_candidate_12345678" in request.headers.get("Authorization", "")
        return FakeResponse(_ok_response(), status=200)

    report = frihet.setup(api_key_value="fri_candidate_12345678", opener=opener)
    assert report["success"] is True
    # The candidate must be gone from the environment after setup().
    assert "fri_candidate_12345678" not in (frihet.api_key() or "")


def test_setup_with_no_key_validates_current(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_existing_12345678")
    response = FakeResponse(_ok_response(), status=200)
    report = frihet.setup(opener=lambda req, t: response)
    assert report["success"] is True


def test_setup_reports_failure_on_unauthorised(monkeypatch):
    monkeypatch.setenv("FRIHET_API_KEY", "fri_existing_12345678")

    def opener(request, timeout):
        raise frihet.urllib.error.HTTPError(  # type: ignore[attr-defined]
            request.full_url, 401, "Unauthorized", {}, None
        )

    report = frihet.setup(opener=opener)
    assert report["success"] is False
    assert report["error"] == "mcp_unauthorized"


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
    assert payload["subcommands"]["setup"].startswith("Validate")
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