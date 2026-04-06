"""
PDP Webhook Template — Policy Decision Point for Cullis.

This is a starting point for your organization's authorization webhook.
The Cullis broker calls this endpoint for every session request involving your org.

Customize the rules in `evaluate()` to match your business logic:
  - Check agent authorization against your IAM/LDAP/HR system
  - Restrict which external orgs can contact your agents
  - Limit capabilities per agent or per time window
  - Apply compliance rules (e.g. no cross-border data transfer)

Usage:
  python pdp_server.py --port 9000
  python pdp_server.py --port 9000 --config rules.json
  python pdp_server.py --port 9000 --opa-url http://opa:8181

Endpoint:
  POST /policy
  Body: {
    "initiator_agent_id": str,
    "initiator_org_id":   str,
    "target_agent_id":    str,
    "target_org_id":      str,
    "capabilities":       list[str],
    "session_context":    "initiator" | "target"
  }
  Response: {"decision": "allow"} | {"decision": "deny", "reason": str}
"""
import argparse
import json
import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
_log = logging.getLogger("pdp")


# ─── Default rules ──────────────────────────────────────────────────────────
# Override by passing --config rules.json

DEFAULT_RULES = {
    # Organizations allowed to initiate sessions with us
    "allowed_initiator_orgs": [],  # empty = allow all

    # Organizations we are allowed to initiate sessions with
    "allowed_target_orgs": [],  # empty = allow all

    # Capabilities we allow in sessions (empty = allow all)
    "allowed_capabilities": [],

    # Agents explicitly blocked (e.g. during incident response)
    "blocked_agents": [],

    # Maximum concurrent sessions per initiator org (0 = unlimited)
    "max_sessions_per_org": 0,
}


def load_rules(config_path: str | None) -> dict:
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            rules = json.load(f)
        _log.info("Loaded rules from %s", config_path)
        return {**DEFAULT_RULES, **rules}
    return DEFAULT_RULES.copy()


def evaluate(body: dict, rules: dict) -> tuple[str, str]:
    """
    Evaluate a session request against the rules.
    Returns ("allow", "") or ("deny", "reason").
    """
    initiator_agent = body.get("initiator_agent_id", "")
    initiator_org   = body.get("initiator_org_id", "")
    target_agent    = body.get("target_agent_id", "")
    target_org      = body.get("target_org_id", "")
    capabilities    = body.get("capabilities", [])
    context         = body.get("session_context", "")

    # Rule 1: blocked agents
    if initiator_agent in rules["blocked_agents"]:
        return "deny", f"Agent {initiator_agent} is blocked"
    if target_agent in rules["blocked_agents"]:
        return "deny", f"Agent {target_agent} is blocked"

    # Rule 2: allowed initiator orgs (when we are the target)
    if context == "target" and rules["allowed_initiator_orgs"]:
        if initiator_org not in rules["allowed_initiator_orgs"]:
            return "deny", f"Org {initiator_org} is not in the allowed initiators list"

    # Rule 3: allowed target orgs (when we are the initiator)
    if context == "initiator" and rules["allowed_target_orgs"]:
        if target_org not in rules["allowed_target_orgs"]:
            return "deny", f"Org {target_org} is not in the allowed targets list"

    # Rule 4: capabilities
    if rules["allowed_capabilities"]:
        blocked = [c for c in capabilities if c not in rules["allowed_capabilities"]]
        if blocked:
            return "deny", f"Capabilities not allowed: {blocked}"

    # All checks passed
    return "allow", ""


async def _forward_to_opa(opa_url: str, body: dict) -> tuple[str, str]:
    """Forward the decision to OPA and translate the response."""
    import httpx
    url = f"{opa_url.rstrip('/')}/v1/data/atn/session/allow"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json={"input": body})
        if resp.status_code != 200:
            return "deny", f"OPA returned HTTP {resp.status_code}"
        result = resp.json().get("result", {})
        if isinstance(result, bool):
            return ("allow" if result else "deny"), ""
        if isinstance(result, dict):
            allowed = result.get("allow", False)
            reason = result.get("reason", "")
            return ("allow" if allowed else "deny"), reason
        return "deny", "OPA returned unexpected result"
    except Exception as exc:
        return "deny", f"OPA error: {exc}"


def build_app(rules: dict, opa_url: str | None = None) -> FastAPI:
    app = FastAPI(title="PDP Webhook")

    @app.get("/health")
    async def health():
        return {"status": "ok", "opa": opa_url or "disabled"}

    @app.post("/policy")
    async def policy_decision(request: Request):
        body = await request.json()

        # Forward to OPA if configured, otherwise use local rules
        if opa_url:
            decision, reason = await _forward_to_opa(opa_url, body)
        else:
            decision, reason = evaluate(body, rules)

        initiator = body.get("initiator_agent_id", "?")
        target    = body.get("target_agent_id", "?")
        context   = body.get("session_context", "?")
        backend   = "OPA" if opa_url else "local"
        _log.info("[%s/%s] %s  %s -> %s  ctx=%s  %s",
                  decision.upper(), backend, initiator, body.get("initiator_org_id", "?"),
                  target, context, reason or "")

        resp: dict = {"decision": decision}
        if reason:
            resp["reason"] = reason
        return JSONResponse(resp)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="PDP Webhook Server")
    parser.add_argument("--port",   type=int, default=9000)
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--config", default=None, help="Path to rules.json")
    parser.add_argument("--opa-url", default=None, help="OPA URL (e.g. http://opa:8181) — forward decisions to OPA")
    args = parser.parse_args()

    rules = load_rules(args.config)
    _log.info("PDP starting on http://%s:%d/policy", args.host, args.port)
    if args.opa_url:
        _log.info("OPA forwarding enabled: %s", args.opa_url)
    else:
        _log.info("Rules: %s", json.dumps(rules, indent=2))

    app = build_app(rules, opa_url=args.opa_url)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
