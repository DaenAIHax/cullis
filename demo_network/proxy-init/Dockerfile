FROM python:3.11-slim

RUN pip install --no-cache-dir aiosqlite==0.20.0

COPY seed.py /usr/local/bin/seed.py

ENTRYPOINT ["python", "/usr/local/bin/seed.py"]
