# Capitolo 36 — Rate Limiting

> *"Se non metti un limite, qualcuno prendera tutto."*

---

## Cos'e il rate limiting — spiegazione da bar

Immagina un bar con un solo barista. Un cliente arriva e ordina 100 caffe in un minuto. Il barista e bloccato, e tutti gli altri clienti aspettano.

Il **rate limiting** e il cartello che dice: "Massimo 5 ordini per persona ogni 10 minuti." Non importa se sei un cliente abituale o uno nuovo — c'e un limite per tutti. Chi lo supera, riceve un "torna dopo".

Nei sistemi software, il rate limiting protegge da:
- **Brute-force**: un attaccante che prova migliaia di password al secondo
- **DoS (Denial of Service)**: un attaccante che inonda il server di richieste per renderlo inaccessibile
- **Abuso API**: un agente buggy che manda richieste in loop infinito

---

## Sliding Window — la finestra che scorre

### Fixed window vs sliding window

Ci sono due modi per contare le richieste:

**Fixed window** (finestra fissa): "Massimo 10 richieste tra le 14:00 e le 14:01."
Problema: un attaccante manda 10 richieste alle 14:00:59 e altre 10 alle 14:01:00. In due secondi ha fatto 20 richieste, il doppio del limite.

**Sliding window** (finestra scorrevole): "Massimo 10 richieste negli ultimi 60 secondi, da adesso."
La finestra si muove con il tempo. Non c'e un "reset" al confine del minuto.

```
Fixed window (vulnerabile al boundary attack):
  14:00                14:01                14:02
    ├───── window 1 ─────┤───── window 2 ─────┤
    │          10 req ──▶│◀── 10 req          │
    │              ▲ boundary: 20 req in 2s!  │

Sliding window (nessun boundary attack):
  Ogni richiesta guarda gli ultimi 60 secondi:
    14:00:30     richiesta #1
    14:00:45     richiesta #5
    14:01:00     richiesta #10
    14:01:01     richiesta #11 → BLOCCATA (10 nelle ultime 60s)
    14:01:31     richiesta #11 → OK (#1 e uscita dalla finestra)
```

Cullis usa **sliding window**.

---

## Dual Backend — in-memory e Redis

### Il problema

Un singolo processo puo contare le richieste in memoria. Ma in produzione, il broker ha piu worker (processi). Se il conteggio e solo in memoria, ogni worker vede solo le proprie richieste, e un attaccante puo distribuire le richieste su tutti i worker per superare il limite.

### La soluzione: backend automatico

```
Avvio del broker
       │
       ▼
┌──────────────┐     Redis disponibile?
│  Prima       │─────────────────────────┐
│  richiesta   │                         │
└──────┬───────┘                         │
       │                                 │
       ▼                                 ▼
┌──────────────┐                  ┌──────────────┐
│  In-memory   │                  │    Redis     │
│  (deque)     │                  │  (sorted set)│
│              │                  │              │
│ Singolo      │                  │ Multi-worker │
│ worker       │                  │ atomico      │
│ reset al     │                  │ persistente  │
│ restart      │                  │              │
└──────────────┘                  └──────────────┘
```

Il backend viene scelto **lazily** alla prima richiesta: se Redis e configurato e raggiungibile, si usa Redis. Altrimenti, si usa l'in-memory. Nessuna configurazione manuale necessaria.

> **In Cullis:** guarda `app/rate_limit/limiter.py`, metodo `_select_backend()`.

---

## Backend in-memory — come funziona

Per ogni combinazione `(soggetto, bucket)`, Cullis mantiene una **deque** (coda a doppia estremita) con i timestamp delle richieste:

```python
# Struttura interna (semplificata)
_windows = {
    ("acme::buyer", "broker.session"): deque([14:00:30, 14:00:45, 14:00:52]),
    ("acme::buyer", "auth.token"):     deque([14:00:10]),
    ("widgets::supplier", "broker.message"): deque([...]),
}
```

Ad ogni richiesta:
1. Rimuovi i timestamp piu vecchi della finestra (`cutoff = now - window_seconds`)
2. Conta quanti rimangono
3. Se `count >= max_requests` → HTTP 429 Too Many Requests
4. Altrimenti, aggiungi il timestamp corrente

L'accesso e protetto da `asyncio.Lock()` per evitare race condition. Per prevenire memory leak, c'e un limite di 50.000 soggetti unici — se si supera, il piu vecchio viene eliminato (LRU eviction).

---

## Backend Redis — atomico con Lua script

Con piu worker, il conteggio deve essere **atomico**. Un ZCARD seguito da ZADD non e atomico — tra i due comandi, un altro worker potrebbe inserire una richiesta. Cullis risolve con un **Lua script** eseguito atomicamente nel server Redis:

```lua
-- Eseguito atomicamente dal server Redis
local key = KEYS[1]
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local request_id = ARGV[4]
local ttl = tonumber(ARGV[5])

-- 1. Rimuovi richieste fuori dalla finestra
redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)

-- 2. Conta le richieste nella finestra
local count = redis.call('ZCARD', key)

-- 3. Se il limite e raggiunto, rifiuta
if count >= max_requests then
    return 0
end

-- 4. Aggiungi la nuova richiesta
redis.call('ZADD', key, now, request_id)
redis.call('EXPIRE', key, ttl)
return 1
```

Ogni richiesta e un membro del sorted set con il timestamp come score. Il `ZREMRANGEBYSCORE` pulisce le richieste vecchie, `ZCARD` conta, `ZADD` aggiunge — tutto in un'unica operazione atomica.

Lo script viene caricato una volta con `SCRIPT LOAD` e poi invocato con `EVALSHA` per efficienza.

> **In Cullis:** guarda `app/rate_limit/limiter.py`, la variabile `_LUA_SCRIPT` e il metodo `_check_redis()`.

---

## Configurazione per endpoint — i bucket

Cullis registra limiti diversi per tipo di endpoint. Ogni bucket ha la sua finestra e il suo limite:

```
┌───────────────────────┬───────────┬──────────────┐
│  Bucket               │  Finestra │  Max request │
├───────────────────────┼───────────┼──────────────┤
│  auth.token           │    60s    │      10      │
│  broker.session       │    60s    │      20      │
│  broker.message       │    60s    │      60      │
│  dashboard.login      │   300s   │       5      │
│  onboarding.join      │   300s   │       5      │
│  broker.rfq           │    60s    │       5      │
│  broker.rfq_respond   │    60s    │      20      │
└───────────────────────┴───────────┴──────────────┘
```

**Perche limiti diversi?**

- `auth.token` (10/min): l'autenticazione e un'operazione pesante (verifica certificato, catena, DPoP). 10 al minuto e piu che sufficiente per un agente legittimo. Un brute-force viene bloccato dopo 10 tentativi.
- `dashboard.login` (5/5min): il login della dashboard e il bersaglio principale per brute-force di password. 5 tentativi in 5 minuti e generoso per un umano, ma blocca un attacco automatico.
- `broker.message` (60/min): i messaggi sono leggeri e frequenti in una sessione attiva. 60 al minuto permette comunicazione fluida.
- `broker.rfq` (5/min): le Request for Quote sono operazioni pesanti che scatenano broadcast a piu agenti. 5 al minuto previene lo spam.

Il soggetto del rate limit e l'`agent_id` — ogni agente ha il suo contatore indipendente.

> **In Cullis:** guarda `app/rate_limit/limiter.py`, le chiamate `rate_limiter.register(...)` in fondo al file.

---

## La risposta HTTP 429

Quando il limite e superato, il server risponde con:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
    "detail": "Rate limit exceeded for 'auth.token': max 10 req/60s"
}
```

L'header `Retry-After` dice al client quanto aspettare prima di riprovare. Un client ben fatto rispetta questo header e aspetta. Un attaccante che lo ignora continua a ricevere 429 senza mai passare.

---

## Osservabilita — metriche

Ogni rifiuto incrementa un contatore OpenTelemetry:

```
RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
```

Questo permette di:
- Monitorare in tempo reale quanti rate limit vengono colpiti
- Distinguere per bucket: se `auth.token` ha molti rifiuti, potrebbe essere un brute-force in corso
- Configurare alert automatici: "se `dashboard.login` supera 50 rifiuti in 10 minuti, notifica il team"

> **In Cullis:** guarda `app/telemetry_metrics.py` per la definizione del contatore.

---

## WebSocket rate limiting — dentro la connessione

Oltre al rate limiting HTTP, anche le connessioni WebSocket hanno un limite interno:

```
_WS_MSG_LIMIT = 30      # max messaggi per finestra
_WS_MSG_WINDOW = 60     # finestra in secondi

Messaggio ricevuto via WebSocket:
  1. Pulisci i timestamp piu vecchi di 60 secondi
  2. Se ci sono gia 30 messaggi nella finestra → close(1008)
  3. Altrimenti, registra il timestamp e processa
```

Questo e separato dal rate limiting HTTP perche le connessioni WebSocket non passano per il middleware HTTP. Il rate limiting e inline nel loop del WebSocket.

> **In Cullis:** guarda `app/broker/router.py`, variabili `_WS_MSG_LIMIT` e `_WS_MSG_WINDOW` nel websocket_endpoint.

---

## Schema completo

```
Richiesta HTTP in arrivo
       │
       ▼
┌──────────────────┐
│   Estrai         │
│   agent_id       │  (dal token JWT)
│   + bucket       │  (dall'endpoint)
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  rate_limiter    │
│  .check()        │
└──────┬───────────┘
       │
       ├── Redis disponibile?
       │     SI → _check_redis() (Lua atomico)
       │     NO → _check_memory() (deque + lock)
       │
       ├── Limite superato?
       │     SI → HTTP 429 + Retry-After
       │          + RATE_LIMIT_REJECT_COUNTER++
       │     NO → prosegui con l'handler
       │
       ▼
┌──────────────────┐
│   Endpoint       │
│   handler        │
└──────────────────┘
```

---

## Riepilogo — cosa portarti a casa

- Il **rate limiting** protegge da brute-force, DoS e abuso API
- Cullis usa **sliding window** — nessun boundary attack possibile
- Il backend e **duale**: in-memory per sviluppo, Redis per produzione — scelto automaticamente
- Il backend Redis usa un **Lua script atomico** per evitare race condition tra worker
- Ogni endpoint ha il suo **bucket** con limiti calibrati: 5/5min per il login, 60/min per i messaggi
- L'header **Retry-After** nella risposta 429 dice al client quanto aspettare
- Le **metriche OpenTelemetry** permettono di monitorare e alertare sui rate limit
- Anche i **WebSocket** hanno rate limiting interno (30 msg/60s)

---

*Prossimo capitolo: [37 — Mappa degli Standard](37-standard-rfc.md) — tutti gli standard e RFC usati da Cullis in un unico riferimento*
