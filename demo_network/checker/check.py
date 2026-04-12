"""
Smoke-test checker: logs in as demo-org-b::checker, polls for sessions+
messages in a background thread, and serves the last-received payload on
http://<self>:9000/last-message.

`smoke.sh check` curls that endpoint and asserts the expected nonce.
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cullis_sdk import CullisClient

BROKER_URL = os.environ["BROKER_URL"]
AGENT_ID   = os.environ["AGENT_ID"]        # demo-org-b::checker
ORG_ID     = os.environ["ORG_ID"]          # demo-org-b
CERT_PATH  = os.environ["AGENT_CERT_PATH"]
KEY_PATH   = os.environ["AGENT_KEY_PATH"]
CA_BUNDLE  = os.environ.get("CA_BUNDLE", "/certs/ca.crt")
PORT       = int(os.environ.get("PORT", "9000"))

os.environ["SSL_CERT_FILE"] = CA_BUNDLE

_last_message: dict | None = None
_last_message_lock = threading.Lock()
_login_ok = threading.Event()


def _poll_loop() -> None:
    """Long-running: login, poll each session for new messages."""
    global _last_message
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    # Retry login in case broker is still warming up.
    for attempt in range(30):
        try:
            client.login(AGENT_ID, ORG_ID, CERT_PATH, KEY_PATH)
            break
        except Exception as exc:
            print(f"checker: login attempt {attempt+1} failed: {exc}")
            time.sleep(2)
    else:
        print("checker: giving up on login after 30 attempts")
        return
    _login_ok.set()
    print(f"checker: logged in as {AGENT_ID}")

    seen: set[tuple[str, int]] = set()
    session_cursors: dict[str, int] = {}
    accepted_sessions: set[str] = set()

    while True:
        try:
            sessions = client.list_sessions()
        except Exception as exc:
            print(f"checker: list_sessions failed: {exc}")
            time.sleep(2)
            continue

        for s in sessions:
            sid = s.session_id
            # Auto-accept any pending session — for smoke we trust every
            # counterparty. Production should apply a policy here.
            if getattr(s, "status", "") == "pending" and sid not in accepted_sessions:
                try:
                    client.accept_session(sid)
                    accepted_sessions.add(sid)
                    print(f"checker: accepted session {sid}")
                except Exception as exc:
                    print(f"checker: accept({sid}) failed: {exc}")
                    continue
            cursor = session_cursors.get(sid, -1)
            try:
                msgs = client.poll(sid, after=cursor, poll_interval=0)
            except Exception as exc:
                print(f"checker: poll({sid}) failed: {exc}")
                continue
            for m in msgs:
                key = (sid, m.seq)
                if key in seen:
                    continue
                seen.add(key)
                session_cursors[sid] = max(cursor, m.seq)
                payload = m.payload
                print(f"checker: RECEIVED session={sid} payload={payload!r}")
                with _last_message_lock:
                    _last_message = {
                        "session_id": sid,
                        "payload":    payload,
                        "received_at": int(time.time()),
                    }
        time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "ok": True,
                "login_ok": _login_ok.is_set(),
            }).encode())
            return
        if self.path.startswith("/last-message"):
            with _last_message_lock:
                body = _last_message or {"payload": None}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())
            return
        self.send_response(404)
        self.end_headers()

    # Silence default noisy request logging.
    def log_message(self, *args, **kwargs) -> None:
        return


def main() -> None:
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"checker: HTTP listening on :{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
