# Reference deployment LLM-driven Cullis agent.
#
# Same SDK install as the sandbox image, but the entrypoint is the
# LLM-driven loop in `reference/agent/llm_agent.py`. It calls Ollama
# on the host (via `host.docker.internal`, set in compose) for each
# decision and executes the resulting tool call against Cullis.
#
# Role-specific system prompts ship in /app/prompts/ (one file per role:
# buyer.txt, inventory.txt, broker.txt, supplier.txt). The container's
# AGENT_ROLE env var picks which one is loaded.
#
# Build context must be the repo root (so pyproject.toml + cullis_sdk/ are visible).
FROM python:3.11-slim

# Install deps first for caching. cullis-sdk pulls httpx transitively, so
# the LLM agent can talk to Ollama without an extra pip install.
COPY pyproject.toml /build/pyproject.toml
COPY cullis_sdk/ /build/cullis_sdk/
COPY cullis_connector/ /build/cullis_connector/

RUN pip install --no-cache-dir "/build[spiffe]"

COPY reference/agent/llm_agent.py /app/llm_agent.py
COPY reference/agent/prompts/ /app/prompts/

# Match spire-server registration entry `unix:uid:1000` (same as sandbox image,
# so SPIRE workload attestation works for the alice-spiffe / bob-spiffe agents).
RUN groupadd -g 1000 agent && useradd -u 1000 -g 1000 -m -s /bin/sh agent
USER 1000:1000

WORKDIR /app
ENTRYPOINT ["python", "/app/llm_agent.py"]
