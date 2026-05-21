"""Synthetic mock data for the 3 reference demo agents.

ALL fictional. No real persons, no real KYC, no real sanctions, no real
beneficial owners, no real M&A targets, no real vendors. Names and IDs are
deterministic so tests are reproducible. Mirrors the shape that production
data sources would return (Onfido/Veriff, OFAC consolidated, OpenCorporates,
Bloomberg/Reuters feeds, internal comps DBs).
"""

from __future__ import annotations

from typing import Any

# -----------------------------------------------------------------------------
# Agent 1 -- KYC Screener
# -----------------------------------------------------------------------------

KYC_DOCUMENTS: dict[str, dict[str, Any]] = {
    "doc_low_risk_retail": {
        "doc_id": "doc_low_risk_retail",
        "type": "passport",
        "country": "IT",
        "given_name": "Mario",
        "family_name": "Rossi",
        "dob": "1985-04-12",
        "expiry": "2034-03-01",
        "image_quality": 0.94,
    },
    "doc_sanctions_hit": {
        "doc_id": "doc_sanctions_hit",
        "type": "passport",
        "country": "RU",
        "given_name": "Synthetic-Sanctions-Test",
        "family_name": "Petrov",
        "dob": "1970-01-01",
        "expiry": "2030-01-01",
        "image_quality": 0.91,
    },
    "doc_high_risk_pep": {
        "doc_id": "doc_high_risk_pep",
        "type": "national_id",
        "country": "IT",
        "given_name": "Synthetic-PEP-Test",
        "family_name": "Bianchi",
        "dob": "1962-07-21",
        "expiry": "2031-12-31",
        "image_quality": 0.88,
    },
}

# Synthetic sanctions list. Matching is by exact (family_name, dob).
SANCTIONS_LIST: list[dict[str, Any]] = [
    {
        "list_name": "OFAC-SDN-DEMO",
        "family_name": "Petrov",
        "given_name": "Synthetic-Sanctions-Test",
        "dob": "1970-01-01",
        "reason": "synthetic_demo_entry",
    },
]

# Synthetic PEP list.
PEP_LIST: list[dict[str, Any]] = [
    {
        "family_name": "Bianchi",
        "given_name": "Synthetic-PEP-Test",
        "dob": "1962-07-21",
        "role": "synthetic_demo_minister",
    },
]


# -----------------------------------------------------------------------------
# Agent 2 -- Pitchbook Builder
# -----------------------------------------------------------------------------

COMPS_DB: dict[str, list[dict[str, Any]]] = {
    "saas": [
        {"name": "DemoCorpA", "ev_revenue": 8.4, "ev_ebitda": 32.0, "growth": 0.41},
        {"name": "DemoCorpB", "ev_revenue": 6.1, "ev_ebitda": 28.5, "growth": 0.34},
        {"name": "DemoCorpC", "ev_revenue": 4.7, "ev_ebitda": 22.0, "growth": 0.28},
    ],
    "industrials": [
        {"name": "IndustrialDemoA", "ev_revenue": 1.8, "ev_ebitda": 12.0, "growth": 0.08},
        {"name": "IndustrialDemoB", "ev_revenue": 2.1, "ev_ebitda": 14.5, "growth": 0.11},
    ],
}

# Each memo is tagged with a `desk`. Chinese Wall: agent inheriting user's
# desk MUST NOT read a memo tagged with a different desk.
INTERNAL_RESEARCH: dict[str, dict[str, Any]] = {
    "memo_tech_001": {
        "memo_id": "memo_tech_001",
        "desk": "tech",
        "title": "DemoCorpA Q3 outlook",
        "mnpi": True,
        "body": "[SYNTHETIC] tech-desk MNPI body content",
    },
    "memo_industrials_001": {
        "memo_id": "memo_industrials_001",
        "desk": "industrials",
        "title": "IndustrialDemoA capex cycle",
        "mnpi": False,
        "body": "[SYNTHETIC] industrials-desk public-side content",
    },
    "memo_industrials_002": {
        "memo_id": "memo_industrials_002",
        "desk": "industrials",
        "title": "IndustrialDemoB carve-out rumor",
        "mnpi": True,
        "body": "[SYNTHETIC] industrials-desk MNPI body content",
    },
}

NEWS_FEED: dict[str, list[dict[str, Any]]] = {
    "DemoCorpA": [
        {"timestamp": "2026-05-10T09:14:00Z", "headline": "DemoCorpA expands EU footprint"},
        {"timestamp": "2026-05-18T11:00:00Z", "headline": "DemoCorpA hires new CFO"},
    ],
    "IndustrialDemoA": [
        {
            "timestamp": "2026-05-12T08:30:00Z",
            "headline": "IndustrialDemoA capex up 12% YoY",
        }
    ],
}


# -----------------------------------------------------------------------------
# Agent 3 -- DORA Vendor / TPA Compliance Reporter
# -----------------------------------------------------------------------------

VENDOR_REGISTRY: list[dict[str, Any]] = [
    {
        "vendor_id": "vendor_cloud_demo",
        "name": "DemoCloud SaaS",
        "category": "cloud_infrastructure",
        "criticality": "CRITICAL",
        "country": "IE",
    },
    {
        "vendor_id": "vendor_kyc_demo",
        "name": "DemoKYC Provider",
        "category": "kyc_screening",
        "criticality": "IMPORTANT",
        "country": "DE",
    },
    {
        "vendor_id": "vendor_email_demo",
        "name": "DemoMail Provider",
        "category": "communication",
        "criticality": "NON_IMPORTANT",
        "country": "IT",
    },
]

VENDOR_ASSESSMENTS: dict[str, dict[str, Any]] = {
    "vendor_cloud_demo": {
        "vendor_id": "vendor_cloud_demo",
        "last_assessment": "2026-04-01",
        "soc2_type2": True,
        "iso27001": True,
        "data_residency_eu": True,
        "subcontractors_disclosed": ["DemoCloud-EU-North", "DemoCloud-EU-South"],
        "exit_strategy_documented": True,
        "rto_minutes": 60,
    },
    "vendor_kyc_demo": {
        "vendor_id": "vendor_kyc_demo",
        "last_assessment": "2026-03-15",
        "soc2_type2": True,
        "iso27001": False,
        "data_residency_eu": True,
        "subcontractors_disclosed": [],
        "exit_strategy_documented": True,
        "rto_minutes": 240,
    },
    "vendor_email_demo": {
        "vendor_id": "vendor_email_demo",
        "last_assessment": "2026-02-01",
        "soc2_type2": False,
        "iso27001": False,
        "data_residency_eu": False,
        "subcontractors_disclosed": [],
        "exit_strategy_documented": False,
        "rto_minutes": 1440,
    },
}

FEDERATED_AUDITOR_ORGS: dict[str, dict[str, Any]] = {
    # Synthetic auditor org enrolled in the Cullis Court federation.
    "auditor_org_demo": {
        "org_id": "auditor_org_demo",
        "name": "DemoAudit EU",
        "country": "LU",
        "court_anchor": "https://court-demo.cullis.invalid/anchor",
        "enrolled": True,
    },
    # Synthetic auditor org NOT enrolled. Used to test the federation gate.
    "auditor_org_not_enrolled": {
        "org_id": "auditor_org_not_enrolled",
        "name": "DemoAudit Off-Federation",
        "country": "CH",
        "court_anchor": None,
        "enrolled": False,
    },
}
