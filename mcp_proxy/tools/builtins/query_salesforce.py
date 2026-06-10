"""
Builtin tool: query_salesforce — execute a SOQL query against Salesforce.

This tool makes external HTTP calls and requires a domain whitelist.
In production it would use ``ctx.secrets["SF_CLIENT_ID"]`` and
``ctx.secrets["SF_CLIENT_SECRET"]`` for OAuth, then call the SOQL endpoint
via ``ctx.http_client`` (which enforces the domain whitelist).
The demo implementation returns mock data.
"""
from __future__ import annotations

from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import tool_registry


@tool_registry.register(
    name="query_salesforce",
    capability="crm.read",
    allowed_domains=["login.salesforce.com", "*.salesforce.com"],
    description="Query Salesforce SOQL endpoint",
    parameters_schema={
        "type": "object",
        "properties": {
            "soql": {
                "type": "string",
                "description": "SOQL query string",
            },
        },
        "required": ["soql"],
    },
)
async def query_salesforce(ctx: ToolContext) -> dict:
    """Execute a SOQL query and return results.

    In production, this would:
      1. Authenticate via OAuth using ctx.secrets
      2. POST the SOQL query via ctx.http_client (whitelisted transport)
      3. Return the result set

    The demo returns static mock data.
    """
    # TODO: Replace with real Salesforce OAuth + SOQL query executing
    # ctx.parameters["soql"]; the demo returns static mock data.
    return {
        "totalSize": 1,
        "done": True,
        "records": [
            {
                "attributes": {"type": "Account", "url": "/services/data/v58.0/sobjects/Account/001..."},
                "Name": "Acme Corp",
                "Id": "001...",
            },
        ],
    }
