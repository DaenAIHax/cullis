FROM python:3.11-slim

RUN pip install --no-cache-dir \
    httpx==0.27.2 \
    cryptography==43.0.1 \
    PyJWT==2.9.0 \
    websockets==13.1

WORKDIR /app
COPY cullis_sdk/ /app/cullis_sdk/
COPY demo_network/checker/check.py /app/check.py

ENV PYTHONPATH=/app

EXPOSE 9000

HEALTHCHECK --interval=3s --timeout=2s --start-period=5s --retries=20 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/health').read()" || exit 1

CMD ["python", "/app/check.py"]
