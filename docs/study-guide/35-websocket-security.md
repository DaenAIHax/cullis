# Capitolo 35 — WebSocket Security

> *"Una porta aperta e comoda. Ma se non la sorvegli, entra chiunque."*

---

## Cos'e un WebSocket — spiegazione da bar

Immagina di fare una telefonata. Con HTTP normale, e come mandare un SMS: scrivi, mandi, aspetti la risposta, e la connessione si chiude. Se vuoi un aggiornamento, devi mandare un altro SMS.

Con **WebSocket**, e come una telefonata vera: alzi la cornetta una volta, e poi parli e ascolti in tempo reale finche qualcuno non riattacca. Il canale resta aperto.

In Cullis, il WebSocket serve per **notifiche in tempo reale**: quando un agente riceve un messaggio o una richiesta di sessione, il broker glielo "pusha" immediatamente via WebSocket, senza che l'agente debba chiedere continuamente "ci sono novita?" (polling).

Il problema? Un canale che resta aperto e piu difficile da proteggere. Non hai il lusso di riautenticare a ogni richiesta come con HTTP. Servono difese specifiche.

---

## 1. Origin Validation

### Il problema

Il middleware CORS di FastAPI protegge le richieste HTTP, ma **non copre i WebSocket**. Un sito malevolo potrebbe aprire un WebSocket verso il broker usando i cookie dell'utente.

**Analogia:** Il buttafuori controlla chi entra dalla porta principale (HTTP), ma c'e una porta laterale (WebSocket) senza nessuno a sorvegliare.

### La difesa

Cullis verifica manualmente l'header `Origin` all'inizio della connessione WebSocket:

```
Client si connette a wss://broker.cullis.tech/v1/broker/ws
  Header: Origin: https://evil-site.com

Server controlla:
  allowed_origins = ["https://dashboard.cullis.tech"]
  "https://evil-site.com" in allowed_origins?  → NO

Risultato: connessione chiusa con codice 1008
  (il client non riceve nemmeno l'handshake)
```

Se `ALLOWED_ORIGINS` contiene `*`, l'origin check viene saltato (utile in sviluppo, da non usare in produzione).

> **In Cullis:** guarda `app/broker/router.py`, funzione `websocket_endpoint()` — il blocco "Origin validation (#25)".

---

## 2. Auth Timeout — chiudi se non ti autentichi

### Il problema

Un attaccante potrebbe aprire centinaia di connessioni WebSocket senza mai autenticarsi, consumando risorse del server (connection exhaustion).

**Analogia:** Immagina cento persone che entrano in un bar, si siedono ai tavoli, ma non ordinano mai nulla. Occupano tutti i posti senza consumare. Alla fine, i clienti veri non trovano posto.

### La difesa

Cullis impone un timeout di **10 secondi** per l'autenticazione. Se il client non manda il messaggio `{"type": "auth", "token": "..."}` entro 10 secondi, la connessione viene chiusa:

```
┌─────────┐                          ┌─────────┐
│ Client  │                          │ Broker  │
└────┬────┘                          └────┬────┘
     │──── WebSocket connect ────────────▶│
     │◀─── accept ───────────────────────│
     │                                    │
     │     (10 secondi di silenzio...)    │
     │                                    │
     │◀─── close(1008, "Auth timeout")──│
     │                                    │
     ✕                                    │
```

Il valore `_WS_AUTH_TIMEOUT = 10` e definito nel router. Abbastanza tempo per un client legittimo, ma troppo poco per un attaccante che vuole tenere connessioni zombie.

> **In Cullis:** guarda `app/broker/router.py`, costante `_WS_AUTH_TIMEOUT` e il blocco `asyncio.wait_for(... timeout=_WS_AUTH_TIMEOUT)`.

---

## 3. Autenticazione completa — non basta il token

### Il problema

Verificare solo il JWT non e sufficiente. Un token rubato potrebbe essere usato per impersonare un agente via WebSocket.

### La difesa: 5 verifiche in sequenza

La fase di autenticazione WebSocket esegue **cinque check** prima di confermare la connessione:

```
Step 1: Decode JWT
  └─ Token valido? Firma RS256 corretta? Non scaduto?
  
Step 2: Verifica DPoP proof
  └─ Il client deve mandare un dpop_proof nel messaggio auth
  └─ htm = "GET" (WebSocket upgrade e un HTTP GET)
  └─ htu = URL canonico del WebSocket endpoint
  └─ La chiave del proof deve corrispondere al cnf.jkt del token

Step 3: Revocation check
  └─ Il token e stato invalidato dall'admin?
  └─ Confronto: token iat vs agent.token_invalidated_at

Step 4: Binding check
  └─ L'agente ha un binding approvato nella sua org?
  └─ Se il binding e stato revocato, la connessione WS viene rifiutata

Step 5: Connection registration
  └─ Registra la connessione nel ConnectionManager
  └─ Se il limite per-org e raggiunto → rifiuta
  └─ Se l'agente aveva gia una connessione → chiudi la vecchia
```

Solo dopo tutti e cinque i check il server risponde `{"type": "auth_ok"}`.

> **In Cullis:** guarda `app/broker/router.py`, step 2a-2d nell'endpoint `websocket_endpoint()`.

---

## 4. Connection Limits — per-agent e per-org

### Il problema

Un'organizzazione compromessa potrebbe aprire migliaia di connessioni WebSocket per esaurire le risorse del broker.

**Analogia:** Un'azienda prenota tutte le sale riunioni dell'edificio per tutto il giorno. Nessun altro puo lavorare.

### La difesa: limite per-org nel ConnectionManager

Il `ConnectionManager` traccia quante connessioni ha ogni organizzazione:

```
_MAX_CONNECTIONS_PER_ORG = 100

org "acmebuyer":   23 connessioni  ← OK
org "widgetcorp":  99 connessioni  ← OK (quasi al limite)
org "widgetcorp": +1 connessione  ← 100 → RIFIUTATA
                                     ConnectionRefusedError
```

Il conteggio e protetto da un `asyncio.Lock()` per evitare race condition TOCTOU (Time-Of-Check-Time-Of-Use): il check del limite e la registrazione avvengono atomicamente sotto lock.

Inoltre, se un agente si riconnette, la connessione precedente viene chiusa automaticamente — un agente puo avere al massimo **una** connessione attiva.

> **In Cullis:** guarda `app/broker/ws_manager.py`, costante `_MAX_CONNECTIONS_PER_ORG` e il metodo `connect()`.

---

## 5. Binding alla sessione autenticata

### Il problema

Una volta autenticato via WebSocket, l'agente potrebbe provare a ricevere messaggi destinati ad altri agenti.

### La difesa: WS legato all'identita

Il WebSocket e registrato con l'`agent_id` estratto dal token JWT verificato. Il `ConnectionManager` mappa `agent_id → WebSocket`:

```
Agente "acme::buyer" autenticato
  → ws_manager._connections["acme::buyer"] = <WebSocket>

Messaggio arriva per "acme::buyer"
  → ws_manager.send_to_agent("acme::buyer", data)
  → consegna diretta sulla connessione registrata

Messaggio arriva per "widgets::supplier"
  → ws_manager.send_to_agent("widgets::supplier", data)
  → consegna su una connessione DIVERSA
  → "acme::buyer" non vede nulla
```

Non c'e modo per un agente di "iscriversi" ai messaggi di un altro agente. La mappatura e rigida e basata sull'identita verificata al momento dell'autenticazione.

---

## 6. Heartbeat, Keepalive e Idle Timeout

### Il problema

Connessioni WebSocket dormenti consumano risorse. Un agente che si disconnette senza chiudere la connessione (crash, rete persa) lascia una connessione "zombie" nel server.

**Analogia:** Un cliente si addormenta al bar. Occupa un posto, ma non ordina nulla. Il barista aspetta un po', poi lo sveglia e gli chiede di andare.

### La difesa: ping/pong + idle timeout + token expiry

```
┌─────────┐                          ┌─────────┐
│ Client  │                          │ Broker  │
└────┬────┘                          └────┬────┘
     │                                    │
     │ (ogni tanto)                       │
     │──── {"type": "ping"} ────────────▶│
     │◀─── {"type": "pong"} ────────────│
     │                                    │
     │ (5 minuti di silenzio)             │
     │◀─── close(1000, "Idle timeout") ─│
     │                                    │
     ✕                                    │
```

Tre meccanismi di protezione:

1. **Idle timeout** (`_WS_IDLE_TIMEOUT = 300`): se il client non manda nessun messaggio per 5 minuti, la connessione viene chiusa
2. **Token expiry check**: ad ogni iterazione del loop, il server verifica che il JWT non sia scaduto. Se `time.time() > agent.exp`, la connessione viene chiusa con un messaggio esplicativo
3. **Rate limit**: massimo 30 messaggi per finestra di 60 secondi (`_WS_MSG_LIMIT = 30`, `_WS_MSG_WINDOW = 60`). Se superato, la connessione viene chiusa con codice 1008

> **In Cullis:** guarda `app/broker/router.py`, il loop `while True` nel websocket_endpoint con i tre controlli.

---

## 7. Cross-worker delivery via Redis Pub/Sub

### Il problema

In produzione, il broker puo avere piu worker (processi). Un agente connesso al worker 1 manda un messaggio a un agente connesso al worker 2. Come lo consegni?

### La soluzione

Il `ConnectionManager` supporta due modalita:

```
Singolo worker (dev):
  Agente A ──▶ ws_manager ──▶ Agente B
              (in-memory)

Multi worker (prod):
  Worker 1                    Worker 2
  Agente A ──▶ ws_manager     ws_manager ──▶ Agente B
                    │              ▲
                    ▼              │
               Redis Pub/Sub channel
               "ws:agent:widgets::supplier"
```

Ogni agente ha un canale Redis dedicato. Quando un messaggio non puo essere consegnato localmente, viene pubblicato sul canale Redis. Il listener dell'altro worker lo riceve e lo consegna.

> **In Cullis:** guarda `app/broker/ws_manager.py`, metodo `send_to_agent()` e `_redis_listener()`.

---

## Schema completo della sicurezza WebSocket

```
Connessione in arrivo
       │
       ▼
┌──────────────┐
│   Origin     │── non in whitelist ──▶ close(1008)
│   check      │
└──────┬───────┘
       │ ok
       ▼
┌──────────────┐
│   Accept     │
│   handshake  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Auth msg   │── timeout 10s ──▶ close(1008)
│   atteso     │── malformato  ──▶ close + errore
└──────┬───────┘
       │ ricevuto
       ▼
┌──────────────┐
│  JWT decode  │── invalido ──▶ auth_error + close
│  DPoP verify │── key mismatch ──▶ auth_error + close
│  Revocation  │── revocato ──▶ auth_error + close
│  Binding     │── non approvato ──▶ auth_error + close
│  Org limit   │── 100 raggiunto ──▶ auth_error + close
└──────┬───────┘
       │ tutto ok
       ▼
┌──────────────┐
│   auth_ok    │
│   loop       │── idle 5min ──▶ close(1000)
│   attivo     │── token exp ──▶ close(1000)
│              │── rate limit ──▶ close(1008)
└──────────────┘
```

---

## Riepilogo — cosa portarti a casa

- Il **WebSocket** e un canale persistente — serve piu sicurezza rispetto a HTTP stateless
- L'**origin validation** e fatta manualmente perche il CORS middleware non copre i WebSocket
- L'**auth timeout** di 10 secondi previene connection exhaustion da connessioni zombie
- L'autenticazione richiede **5 check**: JWT, DPoP proof, revocation, binding, org limit
- Il **limite di 100 connessioni per org** con lock atomico previene il resource exhaustion
- Il **binding WS-identita** impedisce a un agente di ricevere messaggi altrui
- **Idle timeout** (5 min), **token expiry check**, e **rate limit** (30 msg/min) chiudono le connessioni problematiche
- In produzione, **Redis Pub/Sub** permette la delivery cross-worker

---

*Prossimo capitolo: [36 — Rate Limiting](36-rate-limiting.md) — come proteggere il sistema da brute-force e DoS*
