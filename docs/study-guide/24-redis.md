# Capitolo 24 — Redis

> *"La memoria a breve termine e velocissima: sai dove hai messo le chiavi della macchina, ma non ti ricordi cosa hai mangiato martedi scorso."*

---

## Cos'e Redis — spiegazione da bar

Immagina un post-it sulla scrivania. Ci scrivi cose che ti servono subito: "il numero del tassista", "l'ordine del caffe per i colleghi", "la lista della spesa". E velocissimo da consultare (basta guardare giu), ma non ci archivi i documenti importanti — quelli vanno nell'archivio (il database).

Redis e quel post-it per i server: un database **in memoria** (RAM), velocissimo, ma pensato per dati **temporanei** o **effimeri**.

```
PostgreSQL (archivio):        Redis (post-it):
  - Dati permanenti           - Dati temporanei
  - Su disco (SSD)            - In memoria (RAM)
  - Query complesse           - Operazioni semplici
  - Millisecondi              - Microsecondi
  - Sopravvive al riavvio     - Puo perdersi al riavvio (ok per il nostro uso)
```

---

## Strutture dati Redis

Redis non e solo "chiave → valore". Ha strutture dati native:

```
Strings:     SET nome "Alice"       GET nome → "Alice"
             (la piu semplice: un valore per chiave)

Sets:        SADD frutti "mela" "pera"    SMEMBERS frutti → {"mela", "pera"}
             (collezione senza duplicati)

Sorted Sets: ZADD classifica 100 "Alice" 85 "Bob"
             ZRANGEBYSCORE classifica 90 100 → ["Alice"]
             (collezione ordinata per punteggio — usata per rate limiting!)

Pub/Sub:     PUBLISH canale "messaggio"
             SUBSCRIBE canale → ricevi messaggi in tempo reale
             (come una radio: chi trasmette non sa chi ascolta)
```

Cullis usa **tutte e tre** le strutture avanzate: Strings per JTI, Sorted Sets per rate limiting, Pub/Sub per WebSocket.

---

## Redis in Cullis — i tre usi

### 1. JTI Blacklist — protezione replay (DPoP)

Quando un agente invia un DPoP proof, il JWT contiene un `jti` (JWT ID) unico. Redis lo registra con un TTL di 300 secondi:

```
SET dpop:jti:abc123 "1" NX EX 300
     |          |     |  |  |   |
     prefisso   JTI   1  |  |   TTL: 5 minuti
                         |  |
                         NX: solo se NON esiste gia
                         EX: scade dopo N secondi
```

Il risultato:
- **Prima volta** (JTI nuovo): SET riesce → richiesta accettata
- **Seconda volta** (replay): SET fallisce (NX) → richiesta rifiutata

Da `app/auth/dpop_jti_store.py`:

```python
class RedisDpopJtiStore:
    _PREFIX = "dpop:jti:"

    async def consume_jti(self, jti: str, ttl_seconds: int = 300) -> bool:
        result = await self._redis.set(
            f"{self._PREFIX}{jti}", "1", nx=True, ex=ttl_seconds,
        )
        return result is not None   # True = nuovo, False = replay
```

`SET NX EX` e **atomico**: non c'e rischio che due richieste concorrenti con lo stesso JTI passino entrambe (nessuna TOCTOU race condition).

### 2. Rate Limiting — finestra scorrevole

Il rate limiter usa **Sorted Sets** per implementare una finestra temporale scorrevole. Ogni richiesta viene registrata con il timestamp come score:

```
ratelimit:agent-123:auth.token
  +-- score: 1712577600.1  member: "a1b2c3"
  +-- score: 1712577601.5  member: "d4e5f6"
  +-- score: 1712577602.8  member: "g7h8i9"
```

Lo script Lua in `app/rate_limit/limiter.py` esegue tutto in modo atomico:

```lua
-- 1. Rimuovi le richieste scadute (fuori dalla finestra)
redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
-- 2. Conta le richieste nella finestra
local count = redis.call('ZCARD', key)
-- 3. Se troppe, nega
if count >= max_requests then return 0 end
-- 4. Altrimenti, registra questa richiesta
redis.call('ZADD', key, now, request_id)
redis.call('EXPIRE', key, ttl)
return 1
```

```
Finestra scorrevole (60 secondi, max 10 richieste):

tempo  →  ─────[====finestra 60s====]──────→
                ^                     ^
             cutoff                  now

Richieste nella finestra: * * * * * * *  (7 su 10: ok, passa)
                          * * * * * * * * * * * (11 su 10: 429 Too Many Requests!)
```

I bucket configurati nel broker:

```python
rate_limiter.register("auth.token",       window_seconds=60,  max_requests=10)
rate_limiter.register("broker.session",   window_seconds=60,  max_requests=20)
rate_limiter.register("broker.message",   window_seconds=60,  max_requests=60)
rate_limiter.register("dashboard.login",  window_seconds=300, max_requests=5)
rate_limiter.register("onboarding.join",  window_seconds=300, max_requests=5)
```

### 3. WebSocket Pub/Sub — notifiche cross-worker

Quando il broker gira su piu worker (processi), un messaggio potrebbe arrivare al worker A mentre l'agente destinatario e connesso via WebSocket al worker B.

```
Senza Redis:                     Con Redis Pub/Sub:

Worker A: riceve messaggio       Worker A: riceve messaggio
Worker A: agente non connesso!        |
  → messaggio perso              PUBLISH ws:agent:bob "nuovo msg"
                                      |
                                 Worker B: SUBSCRIBE ws:agent:bob
                                 Worker B: agente connesso!
                                   → messaggio consegnato via WS
```

Da `app/broker/ws_manager.py`:

```python
class ConnectionManager:
    async def init_redis(self) -> None:
        redis = get_redis()
        if redis is None:
            logger.info("WebSocket manager: no Redis — single-worker mode")
            return
        self._redis = redis
        self._pubsub = redis.pubsub()
        logger.info("WebSocket manager: Redis Pub/Sub enabled")
```

Il channel prefix e `ws:agent:{agent_id}`. Quando un messaggio arriva, il manager:
1. Prova la consegna locale (agent connesso a questo worker?)
2. Se Redis e disponibile, pubblica sul canale dell'agente
3. Il worker che ha la connessione WebSocket riceve e consegna

---

## Fallback in-memory — dev senza Redis

Ogni componente ha un fallback quando Redis non e disponibile. Da `app/config.py`:

```python
redis_url: str = ""   # vuoto = Redis disabilitato
```

Se `REDIS_URL` e vuoto:

```python
# app/redis/pool.py
async def init_redis(redis_url: str) -> bool:
    if not redis_url:
        _log.info("Redis disabled — REDIS_URL is empty")
        return False
```

| Componente | Con Redis | Senza Redis |
|---|---|---|
| DPoP JTI | `RedisDpopJtiStore` (SET NX EX) | `InMemoryDpopJtiStore` (dict + lock) |
| Rate Limit | Sorted Set + Lua | `deque` con `asyncio.Lock` |
| WebSocket | Pub/Sub cross-worker | Solo connessioni locali |

Il fallback in-memory funziona perfettamente per sviluppo e test con un singolo worker, ma **non e sicuro per produzione multi-worker**: due worker non condividono memoria.

---

## TTL — la scadenza automatica

TTL (Time To Live) e la caratteristica killer di Redis per Cullis. Ogni chiave puo avere una scadenza:

```
SET dpop:jti:abc123 "1" EX 300
                            |
                       scade dopo 5 minuti
                       Redis la cancella automaticamente
                       nessun job di pulizia necessario!
```

```
Senza TTL (database):             Con TTL (Redis):
  - Inserisci record              - SET con EX
  - Devi fare cleanup periodico   - Redis cancella da solo
  - Cron job o lazy delete        - Zero manutenzione
  - La tabella cresce             - Memoria costante
```

Questo e perfetto per:
- **JTI replay protection**: un JTI scade dopo 300s, poi non serve piu
- **Rate limit windows**: le richieste vecchie escono dalla finestra e vengono rimosse

---

## Connessione e pool

`app/redis/pool.py` gestisce il client condiviso:

```python
import redis.asyncio as aioredis

async def init_redis(redis_url: str) -> bool:
    client = aioredis.from_url(
        redis_url,
        decode_responses=True,          # risposte come stringhe, non bytes
        socket_connect_timeout=5,       # timeout connessione
        socket_timeout=5,               # timeout operazione
    )
    await client.ping()                 # verifica connettivita
    _client = client

def get_redis() -> aioredis.Redis | None:
    return _client                      # None se Redis e disabilitato
```

Il client e un singleton: creato una volta allo startup, usato ovunque, chiuso allo shutdown.

---

## Riepilogo — cosa portarti a casa

- **Redis** e un database in memoria: velocissimo per dati temporanei, non un sostituto del database principale
- Cullis usa Redis per tre scopi: **JTI blacklist** (replay protection), **rate limiting** (sliding window), **WebSocket pub/sub** (cross-worker)
- **SET NX EX** e l'operazione atomica che impedisce i replay: "salva solo se non esiste, scade dopo N secondi"
- I **Sorted Sets** con script **Lua** implementano il rate limiting senza race condition
- Il **Pub/Sub** permette ai worker di notificare agenti connessi ad altri worker
- Tutto ha un **fallback in-memory** per sviluppo senza Redis (dict + asyncio.Lock)
- Il **TTL** elimina automaticamente i dati scaduti — zero manutenzione
- Il pool Redis e un **singleton** inizializzato nel lifespan di FastAPI (`app/redis/pool.py`)
- In produzione, Redis gira come container Docker (`redis:7-alpine`) sulla rete interna

---

**Prossimo capitolo:** [25 — Nginx e TLS](25-nginx-tls.md)
