"""Audit API router — per-session JSON audit trail reads for Connector tools.

The dashboard already renders audit rows as HTML at ``/proxy/audit``.
This module exposes a narrower, machine-readable surface scoped to a
single session_id so an agent can pull its own audit trail at runtime
(e.g. from the ``get_audit_trail`` MCP tool in the Cullis Connector).
"""
