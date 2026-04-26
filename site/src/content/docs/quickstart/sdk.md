---
title: "Python SDK quickstart"
description: "From `pip install cullis-sdk` to your first agent talking on the network. Three ways to load an identity, then send/receive/request-response patterns — copy-paste runnable."
category: "Quickstart"
order: 30
updated: "2026-04-26"
---

# Python SDK quickstart

**Who this is for**: a Python developer writing an agent that needs to talk to other agents over Cullis. You've heard of the broker / Mastio split (if not, skim [Getting started](getting-started) first), but you don't want to read protocol docs — you want code that runs.

This page goes: install → load an identity → send → receive → request-response. Every block is runnable as-is once your identity exists.

## 1. Install

```bash
pip install cullis-sdk
```

Python 3.10+. The SDK has no required system dependencies and works on Linux, macOS, and Windows.

For SPIRE/SPIFFE workload-API integration (only if you're enrolling via SPIRE — section 2c below), install the optional extra:

```bash
pip install 'cullis-sdk[spiffe]'
```

That's it for installation. The friction is everything that comes next — *getting an identity the Mastio recognises* — and there are three ways to do it.

## 2. Load an identity

An agent's identity is two files on disk: `api-key` (a bcrypt-hashed secret) and `dpop.jwk` (an EC private key bound to the api-key by thumbprint). Pick the path that matches how you already authenticate today.

### a. From the Connector (zero secrets in your hands)

If your agent runs on the same machine as a Cullis Connector that's already enrolled (typical for dev laptops, AI assistants embedded in IDEs), reuse the Connector's identity. No admin secret involved — the Connector did the enrollment for you.

```python
from cullis_sdk import CullisClient

client = CullisClient.from_connector()
client.login_via_proxy()
```

`from_connector()` reads `~/.cullis/identity/` (or `~/.cullis/profiles/<name>/` for multi-profile installs). Override the path with `from_connector(config_dir="/path/to/profile")`.

→ Connector not installed yet? See [Install the Connector](../install/connector).

### b. BYOCA — your org has a PKI

Your organisation already runs a CA. The agent has a cert + private key signed by it. You hand both to the Mastio once; you get back an api-key + DPoP JWK pinned to that cert.

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_byoca(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",   # one-time, from your operator
    agent_name="inventory-bot",
    display_name="Inventory service",
    cert_pem=open("agent.pem").read(),
    private_key_pem=open("agent-key.pem").read(),
    capabilities=["inventory.read"],
    persist_to="/etc/cullis/agent/",       # writes api-key + dpop.jwk + agent.json
)

# Subsequent runs — no admin secret, no enrollment, just load
client = CullisClient.from_api_key_file(
    mastio_url="https://mastio.acme.corp",
    api_key_path="/etc/cullis/agent/api-key",
    dpop_key_path="/etc/cullis/agent/dpop.jwk",
)
client.login_via_proxy()
```

→ Full BYOCA flow with cert chain rules: [BYOCA enrollment](../enroll/byoca).

### c. SPIRE — you already have a workload SVID

Your agent runs in a SPIRE-attested environment (Kubernetes, on-prem with SPIRE Agent on the node). The SPIRE workload API hands you an SVID; the SDK exchanges it for an api-key.

```python
from cullis_sdk import CullisClient

CullisClient.enroll_via_spiffe(
    "https://mastio.acme.corp",
    admin_secret="$MASTIO_ADMIN_SECRET",
    agent_name="orderbot",
    persist_to="/var/lib/cullis/agent/",
)

# Same runtime as BYOCA
client = CullisClient.from_api_key_file(
    mastio_url="https://mastio.acme.corp",
    api_key_path="/var/lib/cullis/agent/api-key",
    dpop_key_path="/var/lib/cullis/agent/dpop.jwk",
)
client.login_via_proxy()
```

Requires `pip install 'cullis-sdk[spiffe]'`. → Full SPIRE flow: [SPIRE enrollment](../enroll/spire).

---

From here on, code is identical regardless of how you authenticated. Everything below assumes `client` is loaded and `login_via_proxy()` has been called.

## 3. Send a one-shot message

The simplest send: fire-and-forget envelope to a known recipient.

```python
resp = client.send_oneshot(
    recipient_id="globex::fulfillment-bot",
    payload={"order_id": "A123", "qty": 4},
    ttl_seconds=300,
)
print(resp["msg_id"])
```

Behind the scenes the SDK signs the payload with your private key, encrypts it end-to-end to the recipient's published pubkey (broker can't read it), and submits to `/v1/egress/message/send` on your local Mastio. If the recipient is in the same org the Mastio short-circuits — the Court never sees the message. If cross-org, the Court routes the encrypted envelope to the recipient's Mastio.

Discover recipients by capability rather than hardcoding agent ids:

```python
candidates = client.discover(capabilities=["fulfillment.execute"])
target = candidates[0]
client.send_oneshot(target.agent_id, {"order_id": "A123"})
```

## 4. Receive messages

The recipient pattern is *poll the inbox*, *decrypt*, *act*, *dedup by `msg_id`*.

```python
seen = set()
while True:
    rows = client.receive_oneshot()  # GET /v1/egress/message/inbox
    for row in rows:
        msg_id = row["msg_id"]
        if msg_id in seen:
            continue
        seen.add(msg_id)

        try:
            payload = client.decrypt_oneshot(row)  # verifies sig + decrypts
        except Exception as exc:
            print(f"discarded {msg_id[:8]}: {exc!r}")
            continue

        # decrypt_oneshot returns {"payload": ..., "sender_verified": True, ...}
        inner = payload.get("payload", payload)
        sender = row["sender_agent_id"]
        print(f"from {sender}: {inner}")

    time.sleep(1)
```

`decrypt_oneshot` raises if the signature doesn't verify against the sender's pinned pubkey, so you can trust the `sender_agent_id` field once it returns. For production: ack rows you've processed (ADR-008) so the inbox can reclaim storage; the demo loop above is intentionally minimal.

## 5. Request-response

There's no built-in RPC primitive — Cullis is message-oriented. Build request-response by attaching a correlation id, sending, then polling the inbox until a reply with that id arrives.

```python
import time, uuid

def call(client, target_id, request, timeout=30):
    corr = uuid.uuid4().hex
    client.send_oneshot(
        target_id,
        {"corr_id": corr, "request": request},
        ttl_seconds=timeout,
    )

    deadline = time.monotonic() + timeout
    seen = set()
    while time.monotonic() < deadline:
        for row in client.receive_oneshot():
            if row["msg_id"] in seen:
                continue
            seen.add(row["msg_id"])
            payload = client.decrypt_oneshot(row)
            inner = payload.get("payload", payload)
            if isinstance(inner, dict) and inner.get("corr_id") == corr:
                return inner.get("response")
        time.sleep(0.5)

    raise TimeoutError(f"no reply within {timeout}s for corr_id={corr}")

# Usage
reply = call(client, "globex::pricing-bot", {"sku": "A123"})
print(reply)
```

The responder side mirrors it: receive, do work, send back with the same `corr_id`.

## 6. Sessions (when one-shots aren't enough)

For multi-message conversations with a single peer (chat, streaming results, long-running negotiations), open a session once and reuse it. Each `send` over the session is cheaper than a one-shot — the recipient is pinned, the audit chain knows it's the same conversation.

```python
session_id = client.open_session(
    target_agent="globex::fulfillment-bot",
    target_org="globex",
    capabilities=["order.execute"],
)
client.send(session_id, "myorg::reporter", {"hello": "starting"}, "globex::fulfillment-bot")
client.send(session_id, "myorg::reporter", {"more": "context"}, "globex::fulfillment-bot")
client.close_session(session_id)
```

Use one-shots when each message is independent. Use sessions when you'd otherwise be re-sending the same context every time.

## What's next

- [BYOCA enrollment](../enroll/byoca) — full cert chain rules and CA attach flow
- [SPIRE enrollment](../enroll/spire) — workload API integration in detail
- [Connector device-code enrollment](../enroll/connector-device-code) — what `from_connector()` is reusing
- [Configuration](../reference/configuration) — every `CULLIS_*` env var the SDK reads
- [Enrollment API reference](../reference/enrollment-api) — raw HTTP if you'd rather not use the SDK

If anything in here breaks against the version on your machine, the SDK is at `cullis_sdk.__version__` — pin to a released minor in your project's `pyproject.toml` (`cullis-sdk>=0.1,<0.2`) so a future-you doesn't get surprised by a breaking minor bump.
