"""External-system integrations that bridge Cullis Mastio's policy +
audit surface into adjacent agent-infrastructure components.

The first inhabitant is :mod:`cullis_enterprise = False` —
``mcp_proxy.integrations.agentgateway`` — which exposes:

  * an OPA Data API-compatible endpoint at ``/v1/data/cullis/policy/...``
    so agentgateway (the Rust agent gateway from agentgateway.dev) can
    consult Cullis as its external policy decision point without
    learning Cullis-specific URLs, and

  * a CloudEvents HTTP-binding sink at ``/v1/integrations/cloudevents``
    that consumes the events agentgateway emits via OpenTelemetry and
    records each one as an immutable row on Cullis' hash-chained
    audit_log. The customer that runs both gets one cryptographically
    verifiable audit trail covering the data-plane (agentgateway) and
    the control-plane (Cullis) without writing glue code.

Why a separate package rather than overloading ``/pdp/policy``:

  * The PDP webhook accepts a Cullis-shaped body (initiator_agent_id,
    target_agent_id, session_context) and returns a Cullis-shaped
    response (decision + reason). The OPA Data API contract is generic
    (``{input: ...}`` → ``{result: ...}``) — agentgateway expects this
    exact shape. Lining up the two would force one side to leak the
    other's vocabulary.

  * Rotation: the operator can rotate
    ``MCP_PROXY_INTEGRATIONS_HMAC_SECRET`` independently from
    ``MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET``. The broker PDP plane is a
    different trust boundary from a customer-controlled adjacent
    gateway.
"""
