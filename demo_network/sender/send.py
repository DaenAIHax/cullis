"""
Smoke-test sender: opens a session with demo-org-b::checker and sends a
single message containing the nonce injected at smoke startup. Exits 0 on
success, non-zero on any failure.
"""
import json
import os
import sys
import time
import ssl

from cullis_sdk import CullisClient

BROKER_URL  = os.environ["BROKER_URL"]
AGENT_ID    = os.environ["AGENT_ID"]              # demo-org-a::sender
ORG_ID      = os.environ["ORG_ID"]                # demo-org-a
PEER_AGENT  = os.environ["PEER_AGENT_ID"]         # demo-org-b::checker
PEER_ORG    = os.environ["PEER_ORG_ID"]           # demo-org-b
CERT_PATH   = os.environ["AGENT_CERT_PATH"]
KEY_PATH    = os.environ["AGENT_KEY_PATH"]
NONCE       = os.environ["SMOKE_NONCE"]
CA_BUNDLE   = os.environ.get("CA_BUNDLE", "/certs/ca.crt")


def main() -> int:
    # Let httpx inside the SDK use our test CA bundle.
    os.environ["SSL_CERT_FILE"] = CA_BUNDLE

    # Build an SSL context that trusts only the test CA — passed through the
    # SDK's verify_tls hook is not available, so we rely on SSL_CERT_FILE
    # being picked up by certifi via the python ssl module.
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    try:
        print(f"sender: logging in as {AGENT_ID}")
        client.login(AGENT_ID, ORG_ID, CERT_PATH, KEY_PATH)

        print(f"sender: opening session with {PEER_AGENT}")
        session_id = client.open_session(
            target_agent_id=PEER_AGENT,
            target_org_id=PEER_ORG,
            capabilities=["message.receive"],
        )

        # The session is pending until the checker accepts it. Wait up to 30s.
        for attempt in range(30):
            sessions = client.list_sessions()
            s = next((x for x in sessions if x.session_id == session_id), None)
            if s and getattr(s, "status", "") == "active":
                break
            time.sleep(1)
        else:
            raise SystemExit(f"sender: session {session_id} not accepted within 30s")

        payload = {
            "nonce":     NONCE,
            "sent_at":   int(time.time()),
            "from":      AGENT_ID,
        }
        print(f"sender: sending payload {payload!r}")
        client.send(
            session_id=session_id,
            sender_agent_id=AGENT_ID,
            payload=payload,
            recipient_agent_id=PEER_AGENT,
        )

        print(f"sender: OK — message delivered to {PEER_AGENT} (session {session_id})")
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
