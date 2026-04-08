"""
Full-stack E2E test (Item 12 in plan.md).

What this test reproduces, automatically, in ~3 minutes:

  Manual sequence we did on 2026-04-07/08            →  Automated equivalent
  ---------------------------------------------------------------------
  1. ./deploy_broker.sh --dev                          docker compose up
  2. Open dashboard, generate invite token A          POST /v1/admin/invites
  3. Open dashboard, generate invite token B          POST /v1/admin/invites
  4. ./deploy_proxy.sh (proxy alpha)                   compose service proxy-alpha
  5. Browser → proxy-alpha /proxy/login + register     setup_proxy_org.py exec
  6. Browser → proxy-alpha /proxy/agents/create        setup_proxy_org.py exec
  7. Repeat 4-6 for proxy beta                         (idem)
  8. Approve both orgs from broker dashboard           POST /v1/admin/orgs/X/approve
  9. Manual: alpha-buyer opens session to beta-seller  POST /v1/egress/sessions
 10. Manual: beta-seller accepts                       POST /v1/egress/sessions/{id}/accept
 11. Manual: alpha-buyer sends message                 POST /v1/egress/send
 12. Manual: beta-seller polls + verifies content      GET  /v1/egress/messages/{id}
 13. docker compose down -v                            (fixture teardown)

The test asserts:
  - Org registration via invite token works
  - Admin approval flips status to active
  - Cross-org capability discovery returns the remote agent
  - Session opens and accepts (PDP webhook between proxies returns ALLOW)
  - E2E message sent by alpha-buyer arrives intact at beta-seller

Skipped by default. Run with:

    pytest -m e2e tests/e2e/test_full_flow.py
    tests/e2e/run.sh
"""
import pytest

from tests.e2e.helpers.broker_admin import (
    BrokerAdminError,
    approve_org,
    generate_invite_token,
)
from tests.e2e.helpers.proxy_setup import register_org, create_agent
from tests.e2e.helpers.e2e_messaging import (
    discover_agents,
    open_session,
    accept_session,
    send_message,
    wait_for_message_with_payload,
)

pytestmark = [pytest.mark.e2e, pytest.mark.asyncio]


# The proxy containers reach the broker via Docker DNS, not localhost.
# This URL is used inside the docker compose network only.
BROKER_INTERNAL_URL = "http://broker:8000"


@pytest.mark.timeout(600)
async def test_full_two_org_message_exchange(e2e_stack):
    """
    Full happy-path: two orgs, two agents, one message exchange across the
    federation. Boots the entire stack via docker compose. Asserts that
    every step the user did manually still works.
    """
    broker_host_url   = e2e_stack["broker_url"]         # http://localhost:18000
    proxy_alpha_url   = e2e_stack["proxy_alpha_url"]    # http://localhost:19100
    proxy_beta_url    = e2e_stack["proxy_beta_url"]     # http://localhost:19101
    admin_secret      = e2e_stack["admin_secret"]

    # ── Step 1: generate two invite tokens (one per org) ────────────────────
    invite_alpha = await generate_invite_token(
        broker_host_url, admin_secret, label="e2e-alpha", ttl_hours=1,
    )
    invite_beta = await generate_invite_token(
        broker_host_url, admin_secret, label="e2e-beta",  ttl_hours=1,
    )
    assert invite_alpha and invite_alpha != invite_beta

    capabilities = ["procurement.read", "procurement.write"]

    # ── Step 2: register both orgs (status=pending) ────────────────────────
    register_org(
        proxy_service_name="proxy-alpha",
        broker_url=BROKER_INTERNAL_URL,
        invite_token=invite_alpha,
        org_id="alpha",
        display_name="Alpha Org",
    )
    register_org(
        proxy_service_name="proxy-beta",
        broker_url=BROKER_INTERNAL_URL,
        invite_token=invite_beta,
        org_id="beta",
        display_name="Beta Org",
    )

    # ── Step 3: network admin approves both orgs ────────────────────────────
    # The broker rejects any agent registration calls while the org is in
    # `pending` state, so this MUST happen before create_agent().
    await approve_org(broker_host_url, admin_secret, "alpha")
    await approve_org(broker_host_url, admin_secret, "beta")

    # ── Step 4: create one agent in each org ───────────────────────────────
    alpha = create_agent(
        proxy_service_name="proxy-alpha",
        org_id="alpha",
        agent_name="buyer",
        capabilities=capabilities,
    )
    assert alpha.org_id == "alpha"
    assert alpha.api_key.startswith("sk_")
    assert "::" in alpha.agent_id  # convention: org::name

    beta = create_agent(
        proxy_service_name="proxy-beta",
        org_id="beta",
        agent_name="seller",
        capabilities=capabilities,
    )
    assert beta.org_id == "beta"

    # ── Step 5: alpha-buyer discovers beta-seller (cross-org capability) ───
    discovered = await discover_agents(
        proxy_alpha_url,
        alpha.api_key,
        capabilities=["procurement.read"],
    )
    discovered_ids = {a.get("agent_id") for a in discovered}
    assert beta.agent_id in discovered_ids, (
        f"beta-seller not visible in discovery from alpha. "
        f"Got: {discovered_ids}"
    )

    # ── Step 6: alpha-buyer opens a session to beta-seller ─────────────────
    session_id = await open_session(
        proxy_alpha_url,
        alpha.api_key,
        target_agent_id=beta.agent_id,
        target_org_id=beta.org_id,
        capabilities=["procurement.read"],
    )
    assert session_id

    # ── Step 7: beta-seller accepts the pending session ────────────────────
    await accept_session(proxy_beta_url, beta.api_key, session_id)

    # ── Step 8: alpha-buyer sends an E2E message ───────────────────────────
    test_payload = {
        "kind": "purchase_order_request",
        "marker": "e2e-mvp-001",
        "items": [{"sku": "WIDGET-42", "qty": 100}],
    }
    await send_message(
        proxy_alpha_url,
        alpha.api_key,
        session_id=session_id,
        payload=test_payload,
        recipient_agent_id=beta.agent_id,
    )

    # ── Step 9: beta-seller receives the decrypted message ────────────────
    received = await wait_for_message_with_payload(
        proxy_beta_url,
        beta.api_key,
        session_id=session_id,
        expected_marker_key="marker",
        expected_marker_value="e2e-mvp-001",
        timeout_seconds=20.0,
    )
    received_payload = received["payload"]
    assert received_payload["kind"] == "purchase_order_request"
    assert received_payload["items"][0]["sku"] == "WIDGET-42"
    assert received_payload["items"][0]["qty"] == 100

    # End of MVP flow. Reply path / RFQ / transaction tokens are out of scope
    # for the MVP and will be added in a future iteration if needed.


@pytest.mark.timeout(60)
async def test_invite_token_invalid_is_rejected(e2e_stack):
    """A garbage invite token must be rejected by /v1/onboarding/join."""
    # The proxy script exits 2 if /onboarding/join returns non-2xx.
    with pytest.raises(RuntimeError, match="setup_proxy_org.py failed"):
        register_org(
            proxy_service_name="proxy-alpha",
            broker_url=BROKER_INTERNAL_URL,
            invite_token="not-a-real-token-xxxxxxxxxxxxxxxx",
            org_id="rogue",
            display_name="Rogue Org",
        )


@pytest.mark.timeout(30)
async def test_admin_invite_requires_admin_secret(e2e_stack):
    """The admin invite endpoint must reject calls without the admin secret."""
    broker_host_url = e2e_stack["broker_url"]
    with pytest.raises(BrokerAdminError):
        await generate_invite_token(
            broker_host_url, admin_secret="wrong-secret", label="should-fail",
        )
