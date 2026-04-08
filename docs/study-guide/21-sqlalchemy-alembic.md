# Capitolo 21 — SQLAlchemy Async + Alembic

> *"Un buon magazziniere sa dove sta ogni cosa, la trova al volo, e quando il magazzino cambia disposizione, sposta tutto senza perdere niente."*

---

## Cos'e un ORM — spiegazione da bar

Immagina di parlare con un magazziniere che parla solo cinese (SQL). Tu parli italiano (Python). Un ORM (Object-Relational Mapper) e il tuo interprete: tu dici "dammi tutti gli agenti attivi" in Python, e lui traduce in SQL per il magazziniere.

```
Senza ORM (SQL diretto):
  cursor.execute("SELECT * FROM agents WHERE is_active = 1 AND org_id = 'acme'")
  rows = cursor.fetchall()
  # rows e una lista di tuple... quale colonna e quale?

Con ORM (SQLAlchemy):
  agents = await session.execute(
      select(AgentRecord).where(AgentRecord.is_active == True, AgentRecord.org_id == "acme")
  )
  # ogni risultato e un oggetto Python con attributi: agent.name, agent.org_id, ...
```

Il vantaggio: scrivi Python, l'ORM genera SQL. Se cambi database (SQLite in dev, PostgreSQL in prod), il codice Python resta uguale.

---

## SQLAlchemy 2.0 — la versione moderna

SQLAlchemy 2.0 ha introdotto:
- **Async engine**: connessioni non bloccanti (perfetto per FastAPI/ASGI)
- **Mapped classes**: modelli dichiarati come classi Python normali
- **Type hints**: autocompletamento e controllo tipo

### Engine e Session in Cullis

In `app/db/database.py`:

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
```

```
                     database_url
                         |
                         v
SQLite dev:    "sqlite+aiosqlite:///./agent_trust.db"
Postgres prod: "postgresql+asyncpg://atn:password@postgres:5432/agent_trust"
                   |         |        |     |         |           |
                 dialetto  driver    user  pass      host       database
```

- **Engine** = la connessione al database (come aprire il cancello del magazzino)
- **Session** = una "visita" al magazzino (apri, leggi/scrivi, chiudi)
- **`expire_on_commit=False`** = dopo un commit, gli oggetti restano leggibili senza ricaricarli

### Il pattern `async with`

```python
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
```

`async with` garantisce che la sessione venga chiusa sempre, anche se qualcosa va storto. E come un blocco `try/finally` automatico.

```
async with AsyncSessionLocal() as session:
    # sessione aperta
    await session.execute(...)
    await session.commit()
# sessione chiusa automaticamente qui, anche se c'e stata un'eccezione
```

---

## Mapped Classes — i modelli

In SQLAlchemy 2.0, una tabella del database diventa una classe Python. Dalla codebase Cullis:

```python
# app/db/database.py
class Base(DeclarativeBase):
    pass

# app/auth/jti_blacklist.py
class JtiBlacklist(Base):
    __tablename__ = "jti_blacklist"

    jti        = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
```

```
Classe Python           Tabella SQL
─────────────           ───────────
JtiBlacklist       →    jti_blacklist
  .jti             →      jti VARCHAR(128) PRIMARY KEY
  .expires_at      →      expires_at TIMESTAMP WITH TIMEZONE NOT NULL
```

Ogni modello importato in `alembic/env.py` viene registrato automaticamente in `Base.metadata` — la mappa completa dello schema.

### Modelli del broker

In `alembic/env.py` troviamo tutti i modelli importati:

```python
from app.auth.jti_blacklist import JtiBlacklist
from app.auth.revocation import RevokedCert
from app.broker.db_models import SessionRecord, SessionMessageRecord, RfqRecord, RfqResponseRecord
from app.broker.notifications import Notification
from app.auth.transaction_db import TransactionTokenRecord
from app.db.audit import AuditLog
from app.policy.store import PolicyRecord
from app.registry.binding_store import BindingRecord
from app.registry.org_store import OrganizationRecord
from app.registry.store import AgentRecord
```

Sono 11 tabelle principali che coprono: identita agenti, organizzazioni, sessioni, messaggi, policy, audit, revoca.

---

## Alembic — le migrazioni

### Il problema

Il database e gia in produzione con dati reali. Vuoi aggiungere una colonna. Non puoi cancellare tutto e ricreare — perderesti i dati.

```
Prima:    agents (id, name, org_id)
Dopo:     agents (id, name, org_id, created_at)    ← nuova colonna!
```

### La soluzione: migrazioni

Alembic crea file di migrazione — script Python che descrivono le modifiche da applicare (e da annullare):

```python
# alembic/versions/473ecda4a4ca_initial_schema.py

def upgrade():
    op.create_table('agents',
        sa.Column('id', sa.String(128), primary_key=True),
        sa.Column('name', sa.String(256)),
        sa.Column('org_id', sa.String(128)),
    )

def downgrade():
    op.drop_table('agents')
```

### Versioning — la catena di migrazioni

```
473ecda4a4ca  ← initial_schema
     |
7043c1ddb652  ← add_oidc_columns_to_organizations
     |
7f54c1eb5e89  ← add_audit_log_hash_chain
     |
a1b2c3d4e5f6  ← add_rfq_and_transaction_token_tables
     |
3ee228696375  ← add_client_seq_to_session_messages
     |
   [HEAD]     ← stato attuale
```

Ogni migrazione ha un ID univoco e conosce la precedente. Alembic sa sempre "a che punto sei" e applica solo le mancanti.

### Auto-generate

```bash
alembic revision --autogenerate -m "aggiungi colonna X"
```

Alembic confronta i modelli Python con lo schema attuale del database e genera automaticamente la migrazione. Tu la revisioni e la applichi:

```bash
alembic upgrade head    # applica tutte le migrazioni fino alla piu recente
```

### Come Cullis esegue le migrazioni

In `app/db/database.py`, la funzione `init_db()` fa tutto automaticamente allo startup:

```python
async def init_db() -> None:
    if os.environ.get("SKIP_ALEMBIC"):
        # Test mode: crea tabelle direttamente (DB in-memory)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    # Produzione: Alembic in un thread separato
    await asyncio.to_thread(_run_alembic)
```

Perche un thread separato? Alembic internamente chiama `asyncio.run()`, che non puo girare dentro un loop asyncio gia attivo. `asyncio.to_thread()` risolve il conflitto.

### Configurazione Alembic

`alembic.ini` configura il percorso degli script. `alembic/env.py` gestisce la connessione:

```python
# Override dell'URL da variabile d'ambiente
database_url = os.environ.get("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)
```

In produzione (Docker), `DATABASE_URL` viene passato via `docker-compose.yml`:
```yaml
DATABASE_URL: postgresql+asyncpg://atn:${POSTGRES_PASSWORD}@postgres:5432/agent_trust
```

---

## SQLite vs PostgreSQL — dev vs prod

```
                  Sviluppo                     Produzione
                 ──────────                   ────────────
Database:     SQLite (file locale)        PostgreSQL 16 (Docker)
Driver:       aiosqlite                   asyncpg
URL:          sqlite+aiosqlite:///./      postgresql+asyncpg://...
Migrazioni:   SKIP_ALEMBIC=1             alembic upgrade head
Concorrenza:  un processo                 multi-worker
```

### Il proxy usa SQLite anche in produzione

Il MCP Proxy (`mcp_proxy/db.py`) usa **aiosqlite direttamente**, senza SQLAlchemy:

```python
async def init_db(db_path: str) -> None:
    async with aiosqlite.connect(_db_path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(_SCHEMA_SQL)
        await db.commit()
```

Perche? Il proxy e un sidecar leggero per organizzazione. Non ha bisogno di PostgreSQL — SQLite con WAL mode (Write-Ahead Logging) basta per le dimensioni attese.

Il proxy ha 3 tabelle: `internal_agents`, `audit_log`, `proxy_config` — tutte definite come SQL diretto in `_SCHEMA_SQL`.

### StaticPool per test

Nei test, SQLite in-memory puo dare problemi con connessioni multiple. La soluzione e `StaticPool`:

```python
engine = create_async_engine(
    "sqlite+aiosqlite://",
    poolclass=StaticPool,     # una sola connessione condivisa
    connect_args={"check_same_thread": False},
)
```

`SKIP_ALEMBIC=1` dice a `init_db()` di usare `Base.metadata.create_all` invece di Alembic.

---

## Flusso completo — dalla richiesta al database

```
    Richiesta HTTP
         |
         v
    FastAPI router
         |
    Depends(get_db)  → apre AsyncSession
    Depends(get_current_agent) → verifica JWT
         |
         v
    Logica business
         |
    session.execute(select(AgentRecord).where(...))
         |
         v
    SQLAlchemy traduce in SQL
         |
    asyncpg / aiosqlite esegue
         |
         v
    Risultato → oggetto Python
         |
    session.commit() se scrittura
         |
    async with chiude la sessione
         |
         v
    Risposta HTTP
```

---

## Riepilogo — cosa portarti a casa

- **ORM** traduce oggetti Python in tabelle SQL e viceversa, rendendo il codice indipendente dal database
- **SQLAlchemy 2.0 async** usa `create_async_engine` + `async_sessionmaker` per connessioni non bloccanti
- **`async with`** garantisce che le sessioni vengano sempre chiuse, anche in caso di errore
- **Alembic** gestisce le migrazioni: script versionati che modificano lo schema senza perdere dati
- **Auto-generate** confronta i modelli Python con il DB e crea la migrazione automaticamente
- Cullis broker usa **PostgreSQL in produzione** (`asyncpg`) e **SQLite in sviluppo** (`aiosqlite`)
- Il MCP Proxy usa **aiosqlite direttamente** (senza SQLAlchemy) per semplicita
- I **test** usano `StaticPool` + `SKIP_ALEMBIC=1` per database in-memory effimeri
- Le migrazioni vengono applicate automaticamente allo startup del broker (`init_db()`)

---

**Prossimo capitolo:** [22 — Docker e Docker Compose](22-docker.md)
