FROM python:3.11-slim

RUN pip install --no-cache-dir httpx==0.27.2 cryptography==43.0.1

WORKDIR /app
COPY bootstrap.py /app/bootstrap.py
COPY pin_mastio.py /app/pin_mastio.py

ENTRYPOINT ["python", "/app/bootstrap.py"]
