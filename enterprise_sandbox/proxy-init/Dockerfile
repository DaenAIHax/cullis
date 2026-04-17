FROM python:3.11-slim

COPY enterprise_sandbox/proxy-init/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app
COPY mcp_proxy/ /app/mcp_proxy/

ENV PYTHONPATH=/app

COPY enterprise_sandbox/proxy-init/seed.py /usr/local/bin/seed.py

ENTRYPOINT ["python", "/usr/local/bin/seed.py"]
