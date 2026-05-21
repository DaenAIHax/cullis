#!/usr/bin/env bash
# Copy the BYOCA cert + key + DPoP JWK for each agents-demo principal out of
# the stack's bootstrap-state docker volume and into a local directory the
# host-side `sandbox/agents-demo/agent_*/main_stack.py` CLI can read from.
#
# The stack mints + parks identity material under
# `/state/orga/agents/<agent_name>/{agent.pem, agent-key.pem, dpop.jwk}` on
# the `bootstrap-state` volume. This helper copies it to
# `./.data/agents-demo/<agent_name>/` on the host (gitignored by default
# via .data/ in the repo .gitignore).
#
# Usage:
#   ./stack/extract-agents-demo-certs.sh
#
# Prereq: `./stack/demo.sh up` completed successfully (bootstrap-mastio
# container exited 0 with bindings approved).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cullis-stack}"

DEST_ROOT="${CULLIS_AGENTS_DEMO_IDENTITY_ROOT:-${REPO_ROOT}/.data/agents-demo}"
AGENTS=(kyc-screener pitchbook-builder dora-reporter)

# Spawn a one-shot busybox container that mounts the bootstrap-state volume
# read-only and copies the three identity files for each demo agent into a
# tar stream we capture on the host. Mirrors how `./demo_network/extract-*.sh`
# scripts behave: cross-platform, no `docker cp` race against running
# containers, no chown gymnastics.

mkdir -p "$DEST_ROOT"

for name in "${AGENTS[@]}"; do
  AGENT_DIR="${DEST_ROOT}/${name}"
  mkdir -p "$AGENT_DIR"
  echo "→ extracting orga::${name} identity to ${AGENT_DIR}"

  # Use the existing bootstrap-state volume name pinned by the stack.
  VOLUME="${COMPOSE_PROJECT_NAME}_bootstrap-state"

  docker run --rm \
    -v "${VOLUME}:/state:ro" \
    -v "${AGENT_DIR}:/out" \
    busybox:stable \
    sh -c "cp /state/orga/agents/${name}/agent.pem /out/ && \
           cp /state/orga/agents/${name}/agent-key.pem /out/ && \
           cp /state/orga/agents/${name}/dpop.jwk /out/ && \
           chmod 644 /out/*.pem /out/*.jwk"
done

# Also extract the Org A CA chain for verify_tls.
CA_DIR="${DEST_ROOT}/_ca"
mkdir -p "$CA_DIR"
docker run --rm \
  -v "${COMPOSE_PROJECT_NAME}_bootstrap-state:/state:ro" \
  -v "${CA_DIR}:/out" \
  busybox:stable \
  sh -c "cp /state/orga/ca.pem /out/ && chmod 644 /out/*.pem"

echo ""
echo "✓ Identity material extracted to: ${DEST_ROOT}"
echo ""
echo "Run a demo agent against the stack:"
echo ""
echo "  cd ${REPO_ROOT}"
echo "  python -m sandbox.agents-demo.agent_kyc_screener.main_stack \\"
echo "      --case-id case_demo_001 \\"
echo "      --document-id doc_low_risk_retail \\"
echo "      --mastio-url https://localhost:9443 \\"
echo "      --identity-dir ${DEST_ROOT}/kyc-screener \\"
echo "      --ca-chain ${DEST_ROOT}/_ca/ca.pem"
echo ""
