# Capitolo 26 — PostgreSQL

> *"Se Redis e il post-it sulla scrivania, PostgreSQL e l'archivio notarile: tutto registrato, tutto verificabile, niente va perso."*

---

## Perche PostgreSQL — spiegazione da bar

Immagina di dover scegliere dove tenere i documenti importanti della tua azienda: contratti, fatture, atti notarili.

- **SQLite** e come un quaderno: pratico per appunti personali, lo porti ovunque, ma se due persone scrivono contemporaneamente si pestano i piedi
- **MySQL** e come un archivio condiviso: funziona, ma ogni tanto qualcosa si perde nei passaggi
- **PostgreSQL** e come un archivio notarile: ogni documento e verificato, timbrato, numerato, e nessuno puo modificarlo senza lasciare traccia

PostgreSQL e il database del broker Cullis in produzione. Vediamo perche.

---

## Le caratteristiche che contano per Cullis

### ACID — le quattro garanzie

```
A — Atomicity   (Atomicita)
    Una transazione o riesce tutta o fallisce tutta.
    "O trasferisci 100 euro DA Alice A Bob, o non fai niente."
    Non puo succedere che togli 100 a Alice e poi il sistema crashi
    prima di darli a Bob.

C — Consistency  (Consistenza)
    Il database passa sempre da uno stato valido a un altro stato valido.
    "Non puoi avere un agente registrato senza organizzazione."

I — Isolation    (Isolamento)
    Due transazioni concorrenti non si vedono a meta.
    "Se due agenti chiedono una sessione contemporaneamente,
     ognuno vede il database come se fosse l'unico."

D — Durability   (Durabilita)
    Dopo un commit, i dati sopravvivono a crash, riavvii, blackout.
    "Se il broker conferma la registrazione, e registrata. Punto."
```

Per un trust broker, ACID non e un lusso — e un requisito. Se un agente viene registrato ma il commit si perde, il sistema e in uno stato inconsistente.

### JSON nativo

PostgreSQL ha il tipo `jsonb` — JSON binario con indici e query:

```sql
-- Cerca agenti con capability "supply"
SELECT * FROM agents
WHERE capabilities @> '["supply"]';
```

Cullis archivia capabilities e metadata come JSON, sfruttando la flessibilita senza perdere la struttura relazionale.

### Full-Text Search

```sql
-- Cerca agenti il cui nome contiene "payment"
SELECT * FROM agents
WHERE to_tsvector('english', display_name) @@ to_tsquery('payment');
```

Utile per la discovery degli agenti nel registro.

### Concorrenza

PostgreSQL gestisce migliaia di connessioni concorrenti con MVCC (Multi-Version Concurrency Control): ogni transazione vede un "snapshot" consistente del database, senza bloccare le altre.

SQLite, al contrario, ha un singolo writer alla volta — perfetto per sviluppo, insufficiente per produzione.

---

## PostgreSQL nel Docker Compose di Cullis

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_USER: atn
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-atn}
    POSTGRES_DB: agent_trust
  volumes:
    - postgres_data:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U atn -d agent_trust"]
    interval: 5s
    timeout: 5s
    retries: 10
```

- **`postgres:16-alpine`**: PostgreSQL 16 su Alpine Linux (immagine leggera)
- **Volume `postgres_data`**: i dati sopravvivono al riavvio del container
- **Health check**: `pg_isready` verifica che il database accetti connessioni
- Il broker non parte finche Postgres non e healthy (`depends_on: { condition: service_healthy }`)

---

## Connection Pooling — asyncpg + SQLAlchemy

### Il problema

Aprire una connessione al database e costoso: handshake TCP, autenticazione, allocazione memoria. Se ogni richiesta HTTP apre e chiude una connessione, il database soffre.

### La soluzione: pool di connessioni

```
Senza pool:                          Con pool:

Richiesta 1 → apri connessione      Pool: [conn1, conn2, conn3, conn4, conn5]
Richiesta 2 → apri connessione                    |
Richiesta 3 → apri connessione      Richiesta 1 → prendi conn1 → usa → restituisci
...100 richieste = 100 connessioni   Richiesta 2 → prendi conn2 → usa → restituisci
                                     Richiesta 3 → prendi conn1 → usa → restituisci
Database: "basta! troppe connessioni!"  (riusa le stesse 5 connessioni)
```

### asyncpg — il driver asincrono

La connection string in produzione:

```
postgresql+asyncpg://atn:password@postgres:5432/agent_trust
    |         |       |     |        |       |        |
  dialetto  driver   user  pass     host    porta   database
```

- **`postgresql`**: dialetto SQLAlchemy
- **`asyncpg`**: driver asincrono nativo per PostgreSQL (scritto in Cython, molto veloce)
- In sviluppo si usa `sqlite+aiosqlite` — il codice Python resta identico

In `app/db/database.py`:

```python
engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
```

SQLAlchemy crea automaticamente un pool di connessioni. Il default e 5 connessioni + 10 overflow, configurabile.

---

## SQLite vs PostgreSQL — quando usare cosa

```
                       SQLite                    PostgreSQL
                    ─────────────              ──────────────
Tipo:              File locale                 Server standalone
Concorrenza:       1 writer                    Migliaia di client
Dimensioni:        fino a ~1 TB               Petabyte
Dove in Cullis:    Dev broker + Proxy prod     Broker produzione
Driver Python:     aiosqlite                   asyncpg
Migrazioni:        metadata.create_all         Alembic upgrade head
Backup:            copia il file               pg_dump
```

### Perche il proxy usa SQLite anche in produzione?

Il MCP Proxy e un **sidecar** per organizzazione. Gestisce poche decine di agenti interni e il suo audit log. Non ha bisogno di:
- Concorrenza massiva (un proxy per org)
- Replica o clustering
- Connessioni remote

SQLite con WAL mode e piu che sufficiente, e non richiede un server separato.

### Perche il broker usa PostgreSQL?

Il broker e il **punto centrale** della rete. Gestisce:
- Centinaia di organizzazioni
- Migliaia di agenti
- Sessioni concorrenti
- Audit log append-only con hash chain
- Query complesse per discovery

Qui SQLite non regge: il single-writer diventa un collo di bottiglia.

---

## Migrazioni con Alembic

Le migrazioni Alembic (vedi capitolo 21) funzionano sia con SQLite che con PostgreSQL. In produzione, `deploy_broker.sh` le applica dopo l'avvio:

```bash
# deploy_broker.sh
docker exec "$BROKER_CONTAINER" alembic upgrade head
```

Ma il broker le applica anche allo startup in `app/db/database.py`:

```python
async def init_db() -> None:
    await asyncio.to_thread(_run_alembic)   # alembic upgrade head
```

Doppio livello di sicurezza: se il deploy script fallisce, il broker le applica da solo.

### Compatibilita cross-database

Alembic e SQLAlchemy generano SQL diverso per PostgreSQL e SQLite. Esempio dal codice (`app/auth/jti_blacklist.py`):

```python
# Gestisce entrambi i dialetti per INSERT ... ON CONFLICT
dialect_name = db.bind.dialect.name

if dialect_name == "postgresql":
    stmt = pg_insert(JtiBlacklist).values(jti=jti, expires_at=expires_at)
    stmt = stmt.on_conflict_do_nothing(index_elements=["jti"])
else:
    # SQLite
    stmt = sqlite_insert(JtiBlacklist).values(jti=jti, expires_at=expires_at)
    stmt = stmt.on_conflict_do_nothing(index_elements=["jti"])
```

---

## Sicurezza PostgreSQL in Cullis

### Credenziali

```yaml
# docker-compose.yml
environment:
  POSTGRES_USER: atn
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-atn}   # da .env in produzione
  POSTGRES_DB: agent_trust
```

`deploy_broker.sh` genera password casuali in `.env` per la produzione. Il default `atn` e solo per sviluppo.

### Rete isolata

PostgreSQL non espone porte all'esterno. E raggiungibile solo dalla rete Docker interna:

```yaml
postgres:
  # Nessun "ports:" → non accessibile dall'esterno
  # Solo i container sulla stessa rete Docker possono raggiungerlo
```

Il broker lo raggiunge come `postgres:5432` (DNS Docker). Dall'esterno, nessuno puo connettersi.

### Volume persistente

```yaml
volumes:
  postgres_data:    # named volume — sopravvive a docker compose down
```

Attenzione: `docker compose down -v` cancella i volumi e **tutti i dati**. Usare solo in sviluppo.

---

## Readiness Probe — il broker verifica PostgreSQL

L'endpoint `/readyz` del broker controlla che PostgreSQL sia raggiungibile:

```python
@app.get("/readyz", tags=["infra"])
async def readyz():
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        return JSONResponse({"status": "not_ready"}, status_code=503)
```

Se PostgreSQL e giu, il broker risponde 503 — Kubernetes/Docker sa che non deve mandargli traffico.

---

## Riepilogo — cosa portarti a casa

- **PostgreSQL** e il database di produzione del broker Cullis: ACID, concorrenza, JSON nativo, full-text search
- **ACID** garantisce che le transazioni siano atomiche, consistenti, isolate e durevoli — fondamentale per un trust broker
- **asyncpg** e il driver asincrono ad alte prestazioni, usato via SQLAlchemy
- Il **connection pool** riusa connessioni aperte invece di crearne di nuove ogni volta
- **SQLite** per sviluppo (broker) e produzione (proxy) — PostgreSQL solo dove serve la concorrenza
- Le **migrazioni Alembic** funzionano su entrambi i database grazie all'astrazione SQLAlchemy
- PostgreSQL gira in Docker (`postgres:16-alpine`) con volume persistente e **nessuna porta esposta**
- Il **readiness probe** `/readyz` verifica la connettivita al database prima di accettare traffico

---

**Prossimo capitolo:** [27 — Audit Ledger Crittografico](27-audit-ledger.md)
