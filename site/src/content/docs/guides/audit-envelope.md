---
title: "The Cullis Audit Envelope"
description: "How tools attach a three-string sidecar (action, subject, outcome) that turns raw RPC payloads into CISO-readable audit rows on the Mastio dashboard."
category: "Guides"
order: 10
updated: "2026-05-23"
---

# The Cullis Audit Envelope

**Scope of this page**: a Cullis-specific pattern that tool authors opt into so that the Mastio audit dashboard renders a *business-readable* row instead of a raw RPC dump. Three free-form strings, attached by the tool to its result, read by Mastio when writing the audit chain row and rendering the dashboard card.

This is the pattern that takes you from:

> Tool invoked: `risk_check` → `http://mcp-portfolio:9900/`

to:

> Pre-trade risk check: BUY €5,000,000 FR0000571085 → approved: within mandate (1d VaR €58,150)

The first form is what a developer reads when debugging. The second is what a CISO, auditor, or compliance officer reads when reviewing the log six months later for a MiFID II or DORA evidence request.

## 1. The envelope

A tool attaches a `_cullis_audit` sidecar field anywhere inside its JSON-RPC result:

```json
{
  "content": [...],
  "_cullis_audit": {
    "action":  "Pre-trade risk check",
    "subject": "BUY €5,000,000 FR0000571085",
    "outcome": "approved: within mandate (1d VaR €58,150)"
  }
}
```

Three required string fields:

| Field | Answers | Style | Length budget |
|---|---|---|---|
| `action` | What did the tool do? | Verb-phrase, capitalised | ≤ 40 characters |
| `subject` | What did it act upon? | Domain object, identifier first | ≤ 80 characters |
| `outcome` | What happened, in business terms? | Result + reason, no jargon | ≤ 120 characters |

**The length budget is for display.** The audit chain stores the values verbatim, no truncation. Only the rendered card header is clipped to keep it on one line. If you write a 200-character outcome, the audit row keeps all 200 characters and the dashboard truncates the rendered preview only.

**Placement is flexible.** Mastio walks the parsed tool result up to depth 8 looking for the first dict with key `_cullis_audit` and all three required fields. Top-level placement (alongside `content` and `isError`) is recommended; nested inside a `content[i]` block also works.

## 2. Emitting the envelope from a tool

The SDK ships a helper that attaches the envelope in one call:

```python
from cullis_sdk.audit import envelope

@mcp.tool()
async def place_order(isin: str, qty: int, price: float) -> dict:
    result = await broker.execute(isin, qty, price)
    return envelope(
        result,
        action="Order placement",
        subject=f"BUY {qty:,} × {isin} @ €{price:,.2f}",
        outcome=f"filled: order #{result['order_id']}",
    )
```

`envelope()` mutates the result dict in place and returns the same reference, so `return envelope(...)` is a one-line idiom.

For tools where the result is built up across multiple branches (try/except, early returns), `make_envelope()` builds the dict separately so you can attach it once at the end:

```python
from cullis_sdk.audit import envelope, make_envelope

@mcp.tool()
async def risk_check(isin: str, side: str, notional: float) -> dict:
    try:
        decision = await pricing.evaluate(isin, side, notional)
        env = make_envelope(
            action="Pre-trade risk check",
            subject=f"{side} €{notional:,.0f} {isin}",
            outcome=(
                f"approved: within mandate (1d VaR €{decision.var_1d:,.0f})"
                if decision.approved
                else f"rejected: {decision.reason}"
            ),
        )
        return envelope({"content": [...], "isError": False}, **env)
    except OffUniverseError as e:
        env = make_envelope(
            action="Pre-trade risk check",
            subject=f"{side} €{notional:,.0f} {isin}",
            outcome=f"rejected: not in approved universe ({e.universe_id})",
        )
        return envelope({"content": [...], "isError": True}, **env)
```

The third helper, `extract(payload)`, mirrors Mastio's reader: it walks an arbitrary JSON-ish payload and returns the first valid envelope it finds, or `None`. Useful for tests, and for orchestrator tools that forward an upstream envelope through their own response wrapper.

## 3. What Mastio does with it

**On the audit chain.** The envelope rides along inside the tool result that already feeds the executor's `detail` JSON. No new column, no schema migration. The chain hash covers the full detail including the envelope, so tampering with the strings invalidates the chain just like any other audit field.

**On the dashboard.** When `/proxy/audit` renders a tool call, it groups the three fan-out rows (PDP decision → executor `tool_execute` → egress `resource_call`) into a single card. The grouper walks the result detail and, if it finds a valid envelope, replaces the card header:

- Without envelope: title `Tool invoked: risk_check`, subtitle `http://mcp-portfolio:9900/`.
- With envelope: title `Pre-trade risk check`, body `BUY €5,000,000 FR0000571085 → approved: within mandate (1d VaR €58,150)`.

**On the SSE stream.** During a `chat_completion_stream`, when the model emits a tool call and the result returns, Mastio also emits a sidecar SSE frame to the client:

```
event: cullis_audit
data: {"action": "Pre-trade risk check", "subject": "BUY ...", "outcome": "approved: ..."}
```

This matches the row that gets written to `local_audit`. Useful when building a UI that wants to surface "what the agent just did" to a human supervisor in near-real-time, without polling the audit endpoint.

## 4. Writing the three strings well

The strings should read as if written by the compliance officer, not the engineer. Use the domain vocabulary the regulator and the business stakeholder share. Avoid raw RPC names, schema names, internal acronyms, HTTP paths.

| Domain | Good `action` examples |
|---|---|
| Trading | `Pre-trade risk check`, `Order placement`, `Market data lookup` |
| KYC | `KYC screening`, `AML check`, `PEP lookup`, `Beneficial owner check` |
| DORA | `Incident logged`, `Incident closed`, `ICT third-party review` |
| KYB | `Business KYC`, `UBO verification`, `Sanctions screen` |

For `subject`, lead with the identifier the auditor would search for: an ISIN, a customer id, an incident id, an order id, a counterparty LEI. Append qualifiers (currency, quantity, side) after.

For `outcome`, put the verdict first, then the reason. Compare:

| | |
|---|---|
| Weak | `rejected because exposure exceeds limit by 23%` |
| Strong | `rejected: exposure exceeds limit by 23%` |

The colon convention lets the eye land on the verdict in the leftmost characters of the dashboard column.

## 5. Graceful degradation

Tools that don't emit the envelope keep working. The dashboard falls back to:

- Card title: `Tool invoked: <tool_name>`
- Card subtitle: `<endpoint_url>` (or `via Mastio gateway` if not available)

No warning, no error. The fallback is intentionally drab so operators can see at a glance which tools have adopted the envelope and which haven't. This matters for third-party MCP servers you don't control: they integrate cleanly, they just don't get the upgraded display.

When a tool does emit the envelope but with the wrong shape (missing field, non-string value), Mastio's reader rejects the envelope silently and falls back. The original payload is unchanged in the chain.

## 6. Composite tools and orchestrators

When tool A internally calls tool B and returns B's result wrapped in its own response, the envelope question is "whose action did the agent perform, A's or B's?"

The current behaviour: the **leaf** envelope wins. Mastio's depth-first walk hits B's nested envelope first because it stops at the first valid match. Practically: orchestrators should generally NOT emit their own envelope when their job is purely to delegate. When the orchestrator does meaningful synthesis on top of the leaf (e.g. "looked up two prices and chose the cheaper venue"), it should emit its own envelope, and either omit the leaves' envelopes or accept that one specific leaf will surface.

If you need both, the cleanest approach is to lift the leaves' envelopes into a top-level `_cullis_audit_chain` list and let your team's dashboard query post-process — this is not standardised and won't render specially today.

## 7. Verifying the envelope reaches the chain

After adopting the helper in a tool, run the tool once through Mastio and verify the row:

```bash
# From the operator workstation
curl -s -H "X-Admin-Secret: $MASTIO_ADMIN_SECRET" \
  "https://mastio.example.com/proxy/audit?event_type=resource_call&limit=5" \
  | jq '.[0].details.result_summary'
```

You should see your three strings under `_cullis_audit` inside the result. From there, the dashboard at `/proxy/audit` renders the card with the new header.

For offline verification (auditor handed an NDJSON export), the standalone verifier preserves the envelope verbatim: `python scripts/cullis-audit-verify.py --chain <export.ndjson>` walks the chain and the per-row JSON keeps `_cullis_audit` for your tooling to consume.

## What's next

- [Chat completion via Mastio](../quickstart/chat-completion) — the `event: cullis_audit` SSE sidecar shows up in the streaming path
- [MCP tools via Mastio](../quickstart/mcp-tools) — every `call_mcp_tool` audits a `resource_call` row that the envelope decorates
- [Audit export](../operate/audit-export) — pull the chain (envelope included) to NDJSON for offline analysis
