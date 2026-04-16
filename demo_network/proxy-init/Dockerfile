FROM python:3.11-slim

# Ship alembic + the mcp_proxy package so the init container can apply
# the proxy's real migration chain before the proxy itself starts. This
# makes ADR-007 seed rows (inserted below) survive because the target
# tables already exist by the time proxy-a boots.
#
# Build context expands to the repo root (see compose.yml); mirrors the
# broker + sender + proxy services.
COPY demo_network/proxy-init/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app
COPY mcp_proxy/ /app/mcp_proxy/

ENV PYTHONPATH=/app

COPY demo_network/proxy-init/seed.py /usr/local/bin/seed.py

ENTRYPOINT ["python", "/usr/local/bin/seed.py"]
