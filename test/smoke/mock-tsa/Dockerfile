# =============================================================================
# Cullis smoke — mock TSA + OpenAI-compatible chat stub
# =============================================================================
#
# Single container, two HTTP servers:
#   :2560  — RFC 3161 TSA (signs TimeStampReq with a self-issued CA
#            baked into the image, returns a TimeStampResp the
#            real audit_anchor_watcher accepts).
#   :2561  — OpenAI-compatible /v1/chat/completions stub. Returns a
#            fixed completion so 40_chat_completion can assert a
#            deterministic shape end-to-end.
#
# No external network, no real CA, no public TSA. The whole point is
# that smoke runs in an air-gapped container build.
# =============================================================================
FROM python:3.11-slim

WORKDIR /app

# rfc3161-client builds the request the Mastio sends; asn1crypto + the
# in-tree crypto library are used to sign the TimeStampToken we return.
# cryptography is already used by the rest of the project.
RUN pip install --no-cache-dir \
    cryptography==45.0.7 \
    rfc3161-client==1.0.3 \
    asn1crypto==1.5.1

COPY server.py /app/server.py

EXPOSE 2560 2561

# Two ports on one process — uses asyncio.start_server twice.
CMD ["python", "/app/server.py"]
