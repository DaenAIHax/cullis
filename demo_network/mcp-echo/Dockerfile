FROM python:3.11-slim

RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 9200

HEALTHCHECK --interval=3s --timeout=2s --start-period=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9200/healthz')" || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9200", "--log-level", "warning"]
