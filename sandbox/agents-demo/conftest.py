"""pytest conftest for the reference demo agents.

This `conftest.py` sits at the top of `sandbox/agents-demo/`. The dash in the
directory name makes the path itself unusable as a Python package, so we
add this directory to `sys.path` instead. From inside any `agent_*/` or
`shared/` module, imports are flat:

    from shared.audit_hooks import AuditChain
    from shared.capability_gate import CapabilityGate, Principal

The same path manipulation is repeated in each agent's `main.py` so it
also works when invoked directly (e.g. `python -m agent_kyc_screener.main`).
"""

from __future__ import annotations

import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
