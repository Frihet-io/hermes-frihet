# hermes-frihet

> **Official Hermes Agent integration for Frihet.**
> Discoverability, setup, diagnostics, and operating guidance for the Frihet MCP.
> **Zero duplicated tools** — the canonical Frihet surface (158 MCP operations)
> stays in [`@frihet/mcp-server`](https://www.npmjs.com/package/@frihet/mcp-server)
> and the remote endpoint [`https://mcp.frihet.io/mcp`](https://mcp.frihet.io/mcp).

[![License: MIT](https://img.shields.io/badge/license-MIT-171717)](LICENSE)
[![Hermes](https://img.shields.io/badge/Hermes-Agent-18181b)](https://hermes-agent.nousresearch.com/)
[![MCP endpoint](https://img.shields.io/badge/MCP-https%3A%2Fmcp.frihet.io%2Fmcp-4A90D9)](https://mcp.frihet.io/mcp)
[![Frihet docs](https://img.shields.io/badge/docs-frihet.io-171717)](https://docs.frihet.io/)

---

## What this plugin is

Hermes Agent is an open-source agent framework by [Nous Research](https://nousresearch.com/).
Frihet is an official business-management platform. This plugin is the
**discoverability + operating layer** between them.

The plugin does **not** re-implement any of the 158 Frihet MCP operations. It
adds three things on top of the canonical MCP:

1. **`/frihet` slash command** with three sub-actions: `status`, `setup`, `doctor`.
2. **`pre_tool_call` hook** that flags Frihet writes whose names imply irreversibility
   (send, markPaid, registerVerifactu, delete, …) so downstream policy or the
   model can pause and require human confirmation.
3. **Bundled skill** (`skills/frihet/SKILL.md`) that teaches Hermes the Frihet
   operating contract: read-before-write, draft-first, Idempotency-Key,
   redaction, Frihet-server authority for workspace/scopes/roles/resources.

The actual data operations flow through the canonical Frihet MCP, which
Hermes already speaks natively (`hermes mcp add` / `mcp_servers.frihet` block).

## Install

### From the Hermes plugin catalog (recommended)

```bash
hermes plugins search frihet
hermes plugins install frihet
```

The installer clones this repo at the exact SHA pinned in the catalog entry
and drops it under `~/.hermes/plugins/frihet/`.

### Manual install

```bash
git clone https://github.com/Frihet-io/hermes-frihet.git \
  ~/.hermes/plugins/frihet
```

Restart Hermes or start a new chat (`/reset`) so the loader picks it up.

## Configure

Add a Frihet API key (generate one at <https://app.frihet.io/settings/api>)
and the MCP server block. The plugin's `.env.example` ships the canonical
values:

```bash
cp ~/.hermes/plugins/frihet/.env.example ~/.hermes/plugins/frihet/.env
# Edit the new .env and paste your key.
```

Or add the MCP server block to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  frihet:
    url: https://mcp.frihet.io/mcp
    auth: oauth                # native MCP OAuth 2.1 + PKCE (browser flow)
    trust: untrusted           # Frihet is a third-party MCP; default to untrusted
    # Alternatively, for unattended callers:
    # auth: api_key
    # env:
    #   FRIHET_API_KEY: ${FRIHET_API_KEY}
```

> The plugin itself never stores your API key. Any string matching
> `fri_<24+ chars>` or `Bearer …` is auto-redacted by the bundled
> `pre_tool_call` hook.

## Use

In any Hermes chat session:

```text
/frihet status    # local snapshot — no network
/frihet setup     # validate FRIHET_API_KEY and print the MCP server block
/frihet doctor    # live MCP handshake — checks endpoint and auth
```

Then ask Hermes:

```
show me my overdue invoices from the last 30 days
```

Hermes will:

1. Resolve `mcp__frihet__list_invoices` (provided by the canonical MCP).
2. Filter by status and due date on the Hermes side, or pass the filter
   through to the MCP tool.
3. Render the result.

The bundled skill guides every read/write to honour the Frihet operating
contract. Irreversible writes surface an advisory the model can act on; the
plugin never blocks a call.

## Safety contract (summary)

The full version lives in [`skills/frihet/SKILL.md`](skills/frihet/SKILL.md).
The non-negotiables:

- **Read before write.** Confirm the target exists before mutating it.
- **Draft first.** `createInvoice`, `createQuote`, `createCreditNote`,
  `createPayment` default to `status: "draft"`. Show totals, hand back.
- **Honour `Idempotency-Key`.** Reuse on retry-with-same-intent;
  generate a new one for a different business reason. Never retry blindly.
- **Reconcile before retry on ambiguity.** If a write returned
  `idempotency_pending`, `unknown_status`, a 5xx, or a timeout,
  **read the record by the key you used** before retrying.
- **No secrets in the model context.** The `pre_tool_call` hook redacts
  `fri_…`, `Bearer …`, and `Authorization:` lines.
- **Frihet is the authority.** Workspace, scopes, roles, and resources
  belong to Frihet. Don't invent rows that contradict it.

## Disclosure

Before installing, please note:

- The plugin makes outbound HTTPS calls to `https://mcp.frihet.io/mcp`
  when you run `/frihet doctor` or any Frihet MCP tool. No other
  third-party endpoints are contacted.
- `/frihet setup` validates a candidate key against the canonical
  endpoint, but does **not** persist the value — that's your job, in
  the Hermes secret directory.
- The plugin does not run background processes, does not write to any
  file outside the plugin directory, and does not auto-update itself.

## Development

The plugin is stdlib-only by design — zero runtime dependencies keeps the
catalog admission floor uncontested and the install footprint minimal.

```bash
# Run the test suite.
python -m pytest -q

# Smoke-load the plugin via the official Hermes loader
# (skipped if hermes_cli is not importable in this env).
python -m pytest -q tests/test_plugin_discovery.py

# Build the wheel.
python -m build

# Validate the manifest against the current Hermes admission rules.
hermes plugins validate ~/.hermes/plugins/frihet --install-deps
```

## Compatibility

- **Hermes Agent:** `>=0.21.5` (declared in `plugin.yaml` as `requires_hermes`).
- **Python:** `>=3.11` (matches Hermes Agent's floor).
- **Frihet MCP protocol:** `2025-06-18` (forward-compatible with later minor).

## Upstream MCP catalog candidate

In addition to this plugin, the repo carries a ready-to-submit candidate for
Hermes's native `optional-mcps/` directory:

- `upstream/frihet-mcp-manifest.yaml` — modelled on
  `optional-mcps/linear/manifest.yaml`, declares native MCP OAuth 2.1 + PKCE,
  no third-party provider, post-install guidance.

When we're ready to publish (after dogfooding the plugin), the upstream PR
lands this manifest at `NousResearch/hermes-agent/optional-mcps/frihet/`,
so Frihet shows up under **Capabilities → Connectors** in addition to
**Capabilities → Plugins**.

## License

[MIT](LICENSE) © 2026 Frihet-io.