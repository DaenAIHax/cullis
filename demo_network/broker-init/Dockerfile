FROM python:3.11-slim

RUN pip install --no-cache-dir cryptography==43.0.1

COPY gen_broker_ca.py /usr/local/bin/gen_broker_ca.py

ENTRYPOINT ["python", "/usr/local/bin/gen_broker_ca.py"]
