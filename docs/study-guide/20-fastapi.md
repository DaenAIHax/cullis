# Capitolo 20 — FastAPI — Framework Web

> *"Un buon cameriere non ti fa aspettare, non sbaglia l'ordine, e ti dice subito se qualcosa non c'e nel menu."*

---

## Cos'e FastAPI — spiegazione da bar

Immagina un ristorante. Il cameriere (FastAPI) prende le ordinazioni (richieste HTTP), le porta in cucina (la tua logica), e riporta i piatti (risposte). Ma questo cameriere e speciale:

- **Controlla l'ordine prima** di mandarlo in cucina: se chiedi "pizza con 47 ingredienti" ti dice subito "no, massimo 10" (validazione Pydantic)
- **Gestisce piu tavoli contemporaneamente** senza bloccarsi: mentre aspetta che la cucina prepari un piatto, serve un altro tavolo (async/await)
- **Ha un menu sempre aggiornato** che si genera da solo (OpenAPI/Swagger)
- **Filtra chi entra**: controlla il dress code, controlla il documento, e aggiunge il coperto automaticamente (middleware)

FastAPI e il framework web Python su cui gira tutto Cullis — sia il broker che il proxy.

---

## ASGI vs WSGI — il modello di servizio

```
WSGI (vecchio):        un cameriere per tavolo
                       Cliente A → cameriere A → cucina → attende → risponde
                       Cliente B → cameriere B → cucina → attende → risponde
                       (se hai 100 clienti, servono 100 camerieri)

ASGI (FastAPI):        un cameriere gestisce tutti
                       Cliente A → ordine → cucina...
                       (mentre cucina prepara)
                       Cliente B → ordine → cucina...
                       Cliente A → piatto pronto → consegnato
                       (un solo cameriere, nessuno aspetta fermo)
```

**WSGI** (Web Server Gateway Interface) e sincrono: ogni richiesta blocca un thread fino al completamento. Flask e Django tradizionale usano WSGI.

**ASGI** (Asynchronous Server Gateway Interface) e asincrono: una richiesta puo "aspettare" (I/O, database, rete) senza bloccare il processo. FastAPI usa ASGI tramite **Uvicorn**.

In Cullis il broker viene lanciato cosi nel `Dockerfile`:

```
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000",
     "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "172.16.0.0/12"]
```

Uvicorn e il server ASGI. `app.main:app` indica il modulo e l'oggetto FastAPI.

---

## Dependency Injection — il sistema dei "preparativi"

FastAPI ha un meccanismo potente: la **dependency injection**. Funziona cosi: prima di eseguire la tua funzione, FastAPI esegue delle funzioni "preparatorie" e ti passa i risultati.

```
Senza dependency injection:           Con dependency injection:

@router.post("/sessioni")             @router.post("/sessioni")
async def crea():                     async def crea(
    db = apri_database()                  db = Depends(get_db),
    utente = verifica_token()             utente = Depends(get_current_agent),
    ...                                   ...
                                      ):
```

In Cullis, `app/db/database.py` definisce `get_db()` — una funzione che apre una sessione database e la chiude automaticamente dopo la richiesta:

```python
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session       # <- "yield" = la sessione vive per tutta la richiesta
                            #    poi viene chiusa automaticamente
```

Nel broker router (`app/broker/router.py`) ogni endpoint riceve le dipendenze:

```python
@router.post("/sessions", status_code=201)
async def request_session(
    body: SessionRequest,                              # corpo validato da Pydantic
    current_agent: TokenPayload = Depends(get_current_agent),  # auth JWT
    store: SessionStore = Depends(get_session_store),          # session store
    db: AsyncSession = Depends(get_db),                        # database
):
```

Ogni `Depends(...)` viene risolto **prima** che la funzione esegua. Se `get_current_agent` fallisce (token invalido), la richiesta ritorna 401 senza mai arrivare alla logica.

---

## Validazione Pydantic — il controllore dell'ordine

Pydantic valida automaticamente i dati in ingresso. Se un campo manca o ha il tipo sbagliato, FastAPI ritorna 422 con un messaggio chiaro.

In Cullis, `app/config.py` usa `pydantic_settings` per configurazione:

```python
class Settings(BaseSettings):
    jwt_algorithm: str = "RS256"
    jwt_access_token_expire_minutes: int = 30
    database_url: str = "sqlite+aiosqlite:///./agent_trust.db"
    redis_url: str = ""
    kms_backend: str = "vault"
    # ... ogni campo ha tipo + default
    class Config:
        env_file = ".env"     # legge da .env automaticamente
```

Pydantic converte `"30"` (stringa dall'env var) a `30` (intero) automaticamente. Se scrivi `"abc"` dove serve un intero, crash immediato con errore chiaro.

---

## OpenAPI e Swagger — il menu automatico

FastAPI genera automaticamente la documentazione API:

- **`/docs`** — Swagger UI interattiva (puoi provare le chiamate dal browser)
- **`/redoc`** — documentazione leggibile

In `app/main.py` l'app viene creata con metadati descrittivi:

```python
app = FastAPI(
    title="Cullis — Federated Trust Broker",
    description="Zero-trust identity for AI agents...",
    version=settings.app_version,
    lifespan=lifespan,
)
```

Ogni router aggiunge le sue sezioni con `tags=["broker"]`, `tags=["infra"]`, ecc.

---

## Middleware — il filtro all'ingresso

I middleware sono funzioni che processano **ogni richiesta** prima che arrivi al router, e **ogni risposta** prima che esca. Pensa a un metal detector all'aeroporto: tutti passano.

### CORS Middleware

```
Browser (origin: app.example.com)  →  Broker (origin: broker.cullis.io)
                                       "Posso ricevere richieste da questo dominio?"
```

In Cullis, `app/main.py` configura CORS leggendo `ALLOWED_ORIGINS`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "DPoP"],
)
```

Se `ALLOWED_ORIGINS="*"`, le credenziali vengono disabilitate (avviso nei log).

### Security Headers Middleware

Cullis aggiunge header di sicurezza su **ogni risposta**:

```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # DPoP-Nonce sulle API (non su dashboard/health)
    response.headers["DPoP-Nonce"] = get_current_dpop_nonce()
    return response
```

L'endpoint JWKS (`/.well-known/jwks.json`) riceve `Cache-Control: public, max-age=3600` (cacheable), tutto il resto riceve `no-store`.

---

## WebSocket — la linea telefonica aperta

```
REST (polling):                      WebSocket:

  Client: "Ci sono messaggi?"           Client ←→ Server
  Server: "No."                         (connessione aperta, bidirezionale)
  (5 sec dopo)                          Server: "Nuovo messaggio!"
  Client: "Ci sono messaggi?"           Server: "Sessione accettata!"
  Server: "No."                         (zero spreco)
  Client: "Ci sono messaggi?"
  Server: "Si, eccolo."
```

In Cullis, il broker gestisce WebSocket per notifiche push agli agenti. La configurazione Nginx fa l'upgrade del protocollo:

```
location /v1/broker/ws {
    proxy_pass http://broker:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Il `ConnectionManager` in `app/broker/ws_manager.py` gestisce le connessioni attive con limite per-org (max 100) e usa Redis Pub/Sub per multi-worker.

---

## Lifespan Events — accendere e spegnere

FastAPI 0.93+ usa `lifespan` al posto dei vecchi `on_startup`/`on_shutdown`. In `app/main.py`:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── STARTUP ──
    validate_config(settings)       # validazione configurazione
    init_telemetry()                # OpenTelemetry
    await init_db()                 # Alembic migrations
    await ensure_bootstrapped()     # admin secret
    await init_redis(settings.redis_url)  # pool Redis
    await ws_manager.init_redis()   # pub/sub per WebSocket
    # ripristina sessioni dal DB
    async with AsyncSessionLocal() as db:
        restored = await restore_sessions(db, session_store)

    yield   # ← l'app gira qui

    # ── SHUTDOWN ──
    await ws_manager.shutdown()     # chiude WebSocket
    await close_redis()             # chiude pool Redis
    shutdown_telemetry()            # flush tracce
```

Tutto cio che va prima di `yield` e startup. Tutto dopo e shutdown. Il pattern `@asynccontextmanager` garantisce che lo shutdown avvenga anche in caso di errore.

---

## Struttura Router in Cullis

```
app/main.py
    |
    +-- v1 = APIRouter(prefix="/v1")
    |     +-- auth_router        (/v1/auth/...)        app/auth/router.py
    |     +-- registry_router    (/v1/registry/...)     app/registry/router.py
    |     +-- org_router         (/v1/orgs/...)         app/registry/org_router.py
    |     +-- binding_router     (/v1/bindings/...)     app/registry/binding_router.py
    |     +-- broker_router      (/v1/broker/...)       app/broker/router.py
    |     +-- policy_router      (/v1/policy/...)       app/policy/router.py
    |     +-- onboarding_router  (/v1/onboarding/...)   app/onboarding/router.py
    |     +-- admin_router       (/v1/admin/...)        app/onboarding/router.py
    |
    +-- dashboard_router    (/dashboard/...)    app/dashboard/router.py
    +-- agent_console_router                    app/dashboard/agent_console.py
    +-- /health, /healthz, /readyz             (inline in main.py)
    +-- /.well-known/jwks.json                 (inline in main.py)
```

API versionate sotto `/v1`, dashboard senza prefisso versione. Health check esposti per Docker/Kubernetes:
- `/healthz` — liveness (il processo e vivo?)
- `/readyz` — readiness (database, Redis, KMS raggiungibili?)

Il proxy (`mcp_proxy/main.py`) segue la stessa architettura: lifespan, CORS, security headers, router modulari (ingress, egress, dashboard), health check.

---

## Riepilogo — cosa portarti a casa

- **FastAPI** e un framework web Python asincrono (ASGI) che genera documentazione automatica
- **ASGI vs WSGI**: ASGI gestisce molte richieste concorrenti senza bloccare, WSGI ne gestisce una per thread
- **Dependency injection** (`Depends()`) prepara database, autenticazione e servizi prima di ogni richiesta
- **Pydantic** valida automaticamente i dati in ingresso e la configurazione da variabili d'ambiente
- **Middleware** CORS e security headers processano ogni richiesta/risposta (vedi `app/main.py`)
- **WebSocket** per push real-time con upgrade via Nginx e `ConnectionManager`
- **Lifespan** gestisce startup (DB, Redis, telemetria) e shutdown in modo sicuro
- Cullis organizza i router sotto un prefisso `/v1` per versionamento API

---

**Prossimo capitolo:** [21 — SQLAlchemy Async + Alembic](21-sqlalchemy-alembic.md)
