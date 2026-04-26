# `cullis-sdk`

**Python SDK for the Cullis federated agent-trust network.**

The Cullis SDK is the library you import from your Python agent code to
talk to a Cullis broker. It handles enrollment, mutual TLS / DPoP-bound
authentication, agent discovery, session management, and end-to-end
encrypted messaging — so your agent code stays focused on what it does,
not on the wire format.

The SDK is one of three Python distributions in the Cullis monorepo:

| Distribution      | Purpose                                                          |
|-------------------|------------------------------------------------------------------|
| `cullis-sdk`      | Library you `import cullis_sdk` from your agent code (this one). |
| `cullis-connector`| End-user MCP server bridging Claude Code / Cursor / etc.         |
| `mcp-proxy`       | Org-level gateway (deployed as a container, not pip-installed).  |

---

## Install

```bash
pip install cullis-sdk
```

Python 3.10+ required.

For [SPIFFE](https://spiffe.io/) workload-API integration (enroll an
agent using its SPIRE-issued SVID), install the optional extra:

```bash
pip install 'cullis-sdk[spiffe]'
```

---

## Quick start

```python
from cullis_sdk import CullisClient

with CullisClient("https://broker.example.com") as client:
    client.login(
        agent_id="myorg::reporter",
        org_id="myorg",
        cert_path="reporter.crt",
        key_path="reporter.key",
    )

    agents = client.discover(capabilities=["order.write"])
    target = agents[0]

    session = client.open_session(
        target.agent_id, target.org_id, ["order.write"],
    )
    client.send(
        session_id=session,
        from_agent="myorg::reporter",
        payload={"text": "Place order #42"},
        to_agent=target.agent_id,
    )
```

The SDK does the heavy lifting: x509 mutual TLS to the broker,
DPoP-bound bearer tokens for replay protection, ECDH key agreement
for end-to-end encryption to the recipient agent, and (on receive)
hash-chain verification of the per-org audit log.

---

## Architecture

```
       ┌──────────┐  mTLS + DPoP   ┌──────────┐  mTLS + DPoP  ┌──────────┐
       │ Agent A  │───────────────▶│  Broker  │◀──────────────│ Agent B  │
       │ (cullis- │                │ (Cullis  │               │ (cullis- │
       │   sdk)   │                │  Site)   │               │   sdk)   │
       └──────────┘                └──────────┘               └──────────┘
            │                                                       ▲
            └─── E2E-encrypted payload (ECDH, broker can't read) ───┘
```

The broker authenticates both endpoints, routes messages, and
appends a tamper-evident hash-chain entry per send. It never sees
the cleartext payload.

---

## Documentation

- Repository: https://github.com/cullis-security/cullis
- Site: https://cullis.io
- Issues: https://github.com/cullis-security/cullis/issues
- Quickstart: https://cullis.io/docs/quickstart/getting-started/

---

## License

Functional Source License 1.1 with Apache-2.0 future grant
([`LICENSE`](https://github.com/cullis-security/cullis/blob/main/LICENSE)).
You can use, modify, and self-host the SDK for any non-competing
purpose; competing-use restriction lifts after two years to Apache 2.0.
