# Capitolo 22 — Docker e Docker Compose

> *"Metti tutto in una scatola: il programma, le librerie, la configurazione. Se funziona sulla tua scrivania, funziona ovunque."*

---

## Container vs VM — spiegazione da bar

### La macchina virtuale (VM)

Immagina di voler aprire un chiosco di panini al mare. Con le VM, costruisci un intero ristorante per ogni panino diverso: fondamenta, muri, cucina, bagno, impianto elettrico. Vuoi 3 tipi di panino? 3 ristoranti completi.

### Il container (Docker)

Con Docker, costruisci un solo ristorante (il sistema operativo) e ci metti dentro dei **food truck** indipendenti. Ogni truck ha i suoi ingredienti e attrezzi, ma condividono la strada e l'elettricita. Leggeri, veloci da spostare, isolati tra loro.

```
VM:                                 Container:

+------------------+                +------------------+
| App A            |                | App A | App B    |
| Guest OS (Linux) |                |-------|----------|
| Hypervisor       |                | Docker Engine    |
| Host OS          |                | Host OS          |
| Hardware         |                | Hardware         |
+------------------+                +------------------+

~GB per VM, minuti per avvio         ~MB per container, secondi per avvio
```

---

## Immagini e Layer — come si costruisce un container

Un'**immagine Docker** e come una ricetta: descrive cosa c'e dentro il container. E composta da **layer** (strati), come una torta:

```
Layer 4:  CMD ["uvicorn", ...]           ← comando di avvio
Layer 3:  COPY app/ ./app/               ← codice applicativo
Layer 2:  RUN pip install -r req.txt     ← dipendenze Python
Layer 1:  FROM python:3.11-slim         ← base: Python su Debian
```

Ogni layer e **immutabile** e **cacheable**. Se cambi solo il codice (Layer 3), Docker riusa i layer 1 e 2 dalla cache — il build e molto piu veloce.

---

## Dockerfile del Broker

Il `Dockerfile` del broker Cullis:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Layer cache: dipendenze cambiano raramente
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Codice + migrazioni
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .

ENV PYTHONPATH=/app

# Sicurezza: non girare come root
RUN useradd --no-create-home --system appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000",
     "--workers", "1", "--proxy-headers",
     "--forwarded-allow-ips", "172.16.0.0/12"]
```

Punti chiave:
- **`COPY requirements.txt` prima del codice**: se cambi solo il codice Python, pip install non viene rieseguito (cache layer)
- **`USER appuser`**: il processo gira come utente non-root — se un attaccante buca l'app, non ha accesso root
- **`--proxy-headers`**: Uvicorn legge `X-Forwarded-For` da Nginx per l'IP reale del client
- **`--forwarded-allow-ips`**: accetta proxy headers solo dalla rete Docker interna (172.16.0.0/12)

## Dockerfile del Proxy

Il proxy (`mcp_proxy/Dockerfile`) e simile ma piu leggero:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY mcp_proxy/requirements-proxy.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp_proxy/ ./mcp_proxy/
COPY cullis_sdk/ ./cullis_sdk/

RUN mkdir -p /data && \
    useradd --no-create-home --system proxyuser && \
    chown proxyuser:proxyuser /data

ENV PYTHONPATH=/app
EXPOSE 9100
USER proxyuser

CMD ["uvicorn", "mcp_proxy.main:app", "--host", "0.0.0.0", "--port", "9100"]
```

Nota: il proxy copia anche `cullis_sdk/` perche lo usa per comunicare con il broker.

---

## Docker Compose — l'orchestra

Docker Compose permette di definire e avviare **piu container insieme** con un solo comando. Ogni servizio e descritto in un file YAML.

### docker-compose.yml — il broker stack

```yaml
services:
  nginx:          # reverse proxy TLS
    image: nginx:alpine
    ports: ["8443:443", "80:80"]
    depends_on:
      broker: { condition: service_healthy }

  vault:          # secrets management
    image: hashicorp/vault:1.17
    ports: ["8200:8200"]

  postgres:       # database
    image: postgres:16-alpine
    volumes: [postgres_data:/var/lib/postgresql/data]

  redis:          # cache, pub/sub
    image: redis:7-alpine

  jaeger:         # distributed tracing
    image: jaegertracing/all-in-one:1.58
    ports: ["16686:16686", "4317:4317"]

  broker:         # l'applicazione Cullis
    build: .
    ports: ["8000:8000"]
    depends_on:
      postgres: { condition: service_healthy }
      vault:    { condition: service_healthy }
      redis:    { condition: service_healthy }
```

```
Un solo "docker compose up" avvia 6 container:

  +----------+     +----------+     +---------+
  |  Nginx   |---->|  Broker  |---->| Postgres|
  | :8443    |     |  :8000   |     | :5432   |
  +----------+     +----------+     +---------+
                        |
                   +----+----+
                   |         |
              +--------+ +--------+
              | Redis  | | Vault  |
              | :6379  | | :8200  |
              +--------+ +--------+
                   |
              +--------+
              | Jaeger |
              | :16686 |
              +--------+
```

### docker-compose.proxy.yml — il proxy per org

```yaml
services:
  mcp-proxy:
    build:
      context: .
      dockerfile: mcp_proxy/Dockerfile
    ports: ["9100:9100"]
    volumes: [mcp_proxy_data:/data]
    networks: [broker_net]

networks:
  broker_net:
    external: true
    name: agent-trust_default     # si connette alla rete del broker!
```

Il proxy **si connette alla rete Docker del broker** (`agent-trust_default`). Questo permette:
- Il proxy raggiunge il broker come `http://broker:8000` (DNS interno Docker)
- Il broker raggiunge il PDP del proxy come `http://mcp-proxy:9100/pdp/policy`

---

## Networking — come si parlano i container

```
Rete Docker "agent-trust_default":

  broker      → DNS: "broker"       → 172.18.0.5
  postgres    → DNS: "postgres"     → 172.18.0.2
  redis       → DNS: "redis"        → 172.18.0.3
  vault       → DNS: "vault"        → 172.18.0.4
  mcp-proxy   → DNS: "mcp-proxy"    → 172.18.0.6  (dalla rete esterna)
```

Docker crea automaticamente un DNS interno: ogni servizio e raggiungibile per **nome**. Nel `docker-compose.yml` del broker:

```yaml
DATABASE_URL: postgresql+asyncpg://atn:${POSTGRES_PASSWORD}@postgres:5432/agent_trust
REDIS_URL: redis://redis:6379
VAULT_ADDR: http://vault:8200
```

`postgres`, `redis`, `vault` sono nomi DNS risolti automaticamente da Docker.

---

## Volumes — i dati persistenti

I container sono **effimeri**: se li cancelli, perdi tutto. I volumes salvano i dati fuori dal container:

```yaml
postgres:
  volumes:
    - postgres_data:/var/lib/postgresql/data    # dati PostgreSQL

mcp-proxy:
  volumes:
    - mcp_proxy_data:/data                      # SQLite del proxy

broker:
  volumes:
    - ./certs:/app/certs:ro                     # certificati (read-only)
```

- `postgres_data` e un **named volume**: Docker lo gestisce, sopravvive ai restart
- `./certs:/app/certs:ro` e un **bind mount**: mappa una cartella dell'host nel container (`:ro` = read-only)

---

## Health Checks — il controllo periodico

Docker puo controllare se un servizio e "sano":

```yaml
broker:
  healthcheck:
    test: ["CMD", "python", "-c",
           "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
    interval: 10s       # controlla ogni 10 secondi
    timeout: 5s         # massimo 5 secondi per rispondere
    retries: 12         # dopo 12 fallimenti → unhealthy
    start_period: 15s   # aspetta 15s prima di iniziare i controlli

postgres:
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U atn -d agent_trust"]
    interval: 5s
    retries: 10

redis:
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
```

Con `depends_on: { condition: service_healthy }`, il broker non parte finche Postgres, Redis e Vault non sono pronti.

---

## deploy.sh — un comando per tutto

Lo script `deploy.sh` orchestra il deployment completo:

```
./deploy.sh
    |
    +-- "Cosa vuoi deployare?"
    |     1) Broker    → deploy_broker.sh
    |     2) Proxy     → deploy_proxy.sh
    |     3) Entrambi  → broker poi proxy
```

`deploy_broker.sh` esegue in sequenza:
1. Verifica prerequisiti (docker, openssl)
2. Scelta modalita (dev/prod)
3. Genera `.env` con segreti casuali
4. Genera broker CA (RSA-4096)
5. Genera certificato TLS (self-signed o Let's Encrypt)
6. `docker compose up --build -d`
7. Carica la chiave CA in Vault
8. Attende health check
9. Esegue Alembic migrations
10. Stampa URL e prossimi passi

---

## Comandi utili

```bash
docker compose up --build -d     # avvia tutto, ricostruisci immagini
docker compose logs -f broker    # segui i log del broker
docker compose ps                # stato dei container
docker compose down              # ferma tutto
docker compose down -v           # ferma e cancella volumi (DATI PERSI!)

# Proxy (file separato)
docker compose -f docker-compose.proxy.yml up -d
```

---

## Riepilogo — cosa portarti a casa

- I **container** sono come food truck: leggeri, isolati, portabili — a differenza delle VM che sono ristoranti completi
- Le **immagini** sono composte da **layer** cacheable — metti le dipendenze prima del codice per build veloci
- Il **Dockerfile** del broker usa `python:3.11-slim`, utente non-root, e proxy headers
- **Docker Compose** orchestra 6 servizi (broker, postgres, redis, vault, nginx, jaeger) con un comando
- Il **networking** Docker crea DNS interni: i container si parlano per nome (`postgres`, `redis`, `vault`)
- Il proxy si connette alla **rete del broker** (`agent-trust_default`) per comunicazione bidirezionale
- I **volumes** preservano dati tra restart (postgres_data, mcp_proxy_data)
- I **health checks** garantiscono che i servizi partano nell'ordine giusto
- `deploy.sh` e `deploy_broker.sh` automatizzano l'intero setup: PKI, TLS, env, Vault, migrazioni

---

**Prossimo capitolo:** [23 — HashiCorp Vault](23-vault.md)
