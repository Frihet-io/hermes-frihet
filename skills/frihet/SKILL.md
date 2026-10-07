---
name: frihet
description: "Use when operating Frihet through Hermes Agent — invoices, expenses, clients, quotes, products, webhooks, tax intelligence, or any other Frihet record. Always prefer reading before writing, drafts before sends, and reconciliation before retry."
version: 0.1.0
author: Frihet-io
license: MIT
metadata:
  hermes:
    tags: [frihet, erp, invoices, expenses, mcp, official]
    homepage: https://github.com/Frihet-io/hermes-frihet
    related_skills: []
---

# Frihet with Hermes Agent

## Overview

Frihet is the official business-management platform behind this integration.
Hermes talks to Frihet through its canonical MCP surface (`@frihet/mcp-server`
on npm, `https://mcp.frihet.io/mcp` remotely, 158 operations). This plugin
**does not** add or duplicate Frihet tools — the MCP provides them. What
this plugin adds is:

- The `/frihet` slash command for status, setup, and doctor.
- The `pre_tool_call` hook that flags writes whose names imply irreversibility.
- This skill, so Hermes knows how to operate Frihet safely.

## When to Use

- The user asks Hermes to read, draft, send, or analyze Frihet data:
  invoices, expenses, clients, products, quotes, webhooks, taxes.
- The user asks about the state of the Frihet connection
  (`/frihet status`, `/frihet doctor`).
- The user is onboarding and wants a guided key validation
  (`/frihet setup`).

Do not use this skill for any non-Frihet ERP. Do not use it to bypass the
Frihet MCP — there is no other way to talk to Frihet from Hermes.

## The Contract

The Frihet MCP is the only surface you should call. Hermes exposes those
tools as `mcp__frihet__<operation>` (the prefix is the MCP server name in
`mcp_servers.frihet`). Treat them as if they were a single, shared business
account with audit trails:

1. **Read before write.** Before creating, updating, sending, marking paid,
   deleting, or filing anything, call the matching `*get` or `*list` tool to
   confirm the target exists and the parameters match.
2. **Draft first (only when the operation supports drafts).** `createInvoice`,
   `createQuote`, `createCreditNote`, and similar default to
   `status: "draft"` on the Frihet side. Build the draft, show the totals,
   and hand the decision back. Do **not** auto-send from inside an
   autonomous loop. **Note:** `createPayment` does NOT have a draft
   status — it is classified as **irreversible** by the plugin and
   always escalates to human approval via the `pre_tool_call` hook.
3. **Honour `Idempotency-Key`.** Frihet's write operations accept an
   `Idempotency-Key`. If you are retrying after a network blip, reuse the
   same key. If you are re-running for a different business reason,
   generate a new one. Never retry a write blindly without a key.
5. **Reconcile before retry on ambiguity.** If a write returned
   `idempotency_pending`, `unknown_status`, a 5xx, a timeout, or anything
   that is not a clean 200 with a body, **read the record by the key you
   used** before retrying. Two retries with the same key are safe; one
   retry without checking is how double charges happen.
6. **No secrets in the model context.** API keys, OAuth bearer tokens,
   `Authorization` headers, and any string matching `fri_<24+ chars>` are
   redacted by this plugin's helper functions (`status()`, `setup()`,
   `doctor()`, and the `redact()` utility) before they ever appear in
   the model's working context or in slash-command output. The
   `pre_tool_call` hook does NOT redact — it only classifies and
   escalates. If you find yourself about to send a credential in
   conversation, stop — write to the Hermes secret directory instead
   (`hermes auth add frihet`) and use OAuth/PKCE (`hermes mcp login
   frihet`) when possible.
7. **Frihet is the authority for workspace, scopes, roles, and resources.**
   Do not invent rows in your own memory that contradict what the MCP
   says. If a record is not returned by `*get`/`*list`, it does not exist
   for you.

## Irreversibility Classification

The plugin classifies every Frihet MCP tool call into one of:

| Kind | Examples | Hook behaviour |
|------|----------|----------------|
| `read` | `get`, `list`, `search`, `describe`, `schema`, `fetch…` | `None` — call flows through. |
| `draft-write` | `createInvoice`, `createQuote`, `createCreditNote` | `None` — the skill tells the model to pause and show totals. |
| `irreversible-write` | `send`, `markPaid`, `issue`, `delete`, `destroy`, `revoke`, `cancelInvoice`, `registerVerifactu`, `applyCreditNote`, … | `{"action": "approve", "rule_key": "frihet:<op>", …}` — escalates to Hermes's human approval gate. |
| `unknown` (any other Frihet MCP tool) | — | `{"action": "approve", …}` — fail-closed; Hermes prompts the user. |

The hook follows Hermes's `pre_tool_call` directive contract exactly
(`hermes_cli/plugins.py`, the `_PreToolCallDirective` shape). Returning
anything else (e.g. `{review: True}`) is silently ignored — and a silent
ignore on a fiscal action is the worst possible safety hole.

## Connection Diagnostics

```
/frihet status   # local snapshot, no network
/frihet doctor   # live MCP handshake
/frihet setup    # validate FRIHET_API_KEY (or a candidate you paste once)
```

`status` is always safe. `doctor` makes one `initialize` round-trip — it
is read-only on the Frihet side. `setup` only validates; it never writes
the key to disk and never echoes the candidate.

## What This Plugin Will Never Do

- Re-implement any of the 158 Frihet MCP operations.
- Stand up a second MCP server alongside `@frihet/mcp-server`.
- Reach into the host's internal config files, memory, or session state.
- Auto-update its own files. Updates reach users only through the
  catalog re-pin flow.
- Auto-approve dangerous tool calls or disable the user's approvals.
- Persist API keys in plugin state, config.yaml, or transcript files.