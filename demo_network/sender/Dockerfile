FROM python:3.11-slim

RUN pip install --no-cache-dir \
    httpx==0.27.2 \
    cryptography==43.0.1 \
    PyJWT==2.9.0 \
    websockets==13.1

WORKDIR /app
# The SDK is copied from the repo root at build time.
COPY cullis_sdk/ /app/cullis_sdk/
COPY demo_network/sender/send.py /app/send.py

ENV PYTHONPATH=/app

CMD ["python", "/app/send.py"]
