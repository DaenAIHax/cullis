# Capitolo 29 — Dashboard Real-Time (SSE)

> *"Non ti chiamo ogni 5 secondi per sapere se c'è posta. Ti urlo dalla finestra quando arriva."*

---

## Il problema — spiegazione da bar

Hai una dashboard web che mostra lo stato del broker: sessioni attive, agenti registrati, log in tempo reale. Come la tieni aggiornata?

**Polling:** la dashboard chiede ogni 5 secondi "ci sono novità?" Il 99% delle volte la risposta è "no". Spreco di banda, carico sul server, latenza media di 2.5 secondi.

**WebSocket:** connessione bidirezionale permanente. Potente ma complesso — serve per la chat tra agenti, non per una dashboard che riceve solo notifiche.

**SSE (Server-Sent Events):** il server manda eventi al client quando vuole. Connessione unidirezionale (server → client). Semplice, leggero, perfetto per notifiche dashboard.

```
Polling:
  Client: "Novità?" → Server: "No"       (ogni 5 sec)
  Client: "Novità?" → Server: "No"
  Client: "Novità?" → Server: "No"
  Client: "Novità?" → Server: "Sì! Nuova sessione"
  → 3 richieste inutili prima della notifica

SSE:
  Client: "Tienimi aggiornato" → connessione aperta
  ... silenzio ...
  Server: "Nuova sessione!"    → istantaneo, zero spreco
  ... silenzio ...
  Server: "Agente registrato!" → istantaneo
```

---

## SSE — come funziona il protocollo

SSE è parte dello standard HTML5. Il formato è semplicissimo — testo plain con un formato specifico:

```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

data: {"event_type": "broker.session.opened", "categories": ["sessions", "overview"]}

data: {"event_type": "registry.agent.registered", "categories": ["agents", "overview"]}

```

Ogni evento è una riga `data:` seguita da una riga vuota. Il browser li riceve via l'API `EventSource`:

```javascript
// Frontend — 3 righe per il real-time
const source = new EventSource("/dashboard/sse");

source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log("Evento:", data.event_type);
    // Aggiorna solo le sezioni della dashboard interessate
    data.categories.forEach(cat => refreshSection(cat));
};

source.onerror = () => {
    console.log("Connessione persa, riconnessione automatica...");
    // EventSource si riconnette da solo!
};
```

**Riconnessione automatica:** se la connessione cade, `EventSource` si riconnette da solo dopo qualche secondo. Non serve gestire nulla lato client.

---

## L'architettura SSE in Cullis

```
                    ┌───────────────────────────────────────┐
                    │            Broker FastAPI              │
                    │                                       │
  Azione           │  log_event()                          │
  (nuova sessione, │      │                                │
   agente registrato,│     ▼                                │
   cert revocato)   │  sse_manager.broadcast()             │
                    │      │                                │
                    │      ├──▶ Client 1 (Queue) ──▶ SSE stream
                    │      ├──▶ Client 2 (Queue) ──▶ SSE stream
                    │      └──▶ Client 3 (Queue) ──▶ SSE stream
                    │                                       │
                    └───────────────────────────────────────┘
```

### Il DashboardSSEManager (`app/dashboard/sse.py`)

Il cuore del sistema è il manager SSE — un singleton che gestisce tutti i client connessi:

```python
class DashboardSSEManager:
    def __init__(self):
        self._clients: dict[int, _Client] = {}   # client_id → Client
        self._counter = 0                          # ID incrementale

    def connect(self) -> tuple[int, Queue]:
        """Un nuovo browser si connette alla dashboard."""
        self._counter += 1
        client = _Client()                         # Queue con maxsize=64
        self._clients[self._counter] = client
        return self._counter, client.queue

    def disconnect(self, client_id: int):
        """Il browser chiude la tab o perde la connessione."""
        self._clients.pop(client_id, None)

    async def broadcast(self, event_type: str, data: dict | None = None):
        """Invia un evento a TUTTI i client connessi."""
        if not self._clients:
            return                                 # nessuno ascolta, skip

        categories = _categorize_event(event_type)
        payload = json.dumps({
            "event_type": event_type,
            "categories": list(categories),
            "ts": time.time(),
        })

        disconnected = []
        for cid, client in self._clients.items():
            try:
                client.queue.put_nowait(payload)   # non-blocking
            except asyncio.QueueFull:
                disconnected.append(cid)           # client troppo lento → disconnetti

        for cid in disconnected:
            self._clients.pop(cid, None)

# Singleton globale
sse_manager = DashboardSSEManager()
```

### Dettagli importanti

**Queue con maxsize=64:** ogni client ha una coda di massimo 64 eventi in attesa. Se il client non li consuma abbastanza velocemente (browser bloccato, rete lenta), la coda si riempie e il client viene disconnesso. Questo previene memory leak se un client si "dimentica" di consumare.

**`put_nowait` non-blocking:** il broadcast non aspetta che i client consumino. Mette in coda e va avanti. Se la coda è piena → QueueFull → client rimosso.

---

## Le categorie — refresh selettivo

Non tutti gli eventi riguardano tutte le pagine della dashboard. Il sistema di **categorie** permette di aggiornare solo le sezioni interessate:

```python
_EVENT_CATEGORY_MAP = {
    "broker.session":           "sessions",
    "broker.message":           "sessions",
    "registry.agent":           "agents",
    "agent.cert":               "agents",
    "cert.revoked":             "agents",
    "registry.org":             "orgs",
    "onboarding":               "orgs",
    "rfq":                      "rfqs",
    "policy":                   "policies",
    "admin":                    "overview",
}
```

Ogni evento viene categorizzato, più overview e audit che si aggiornano sempre:

```python
def _categorize_event(event_type: str) -> set[str]:
    categories = set()
    for prefix, category in _EVENT_CATEGORY_MAP.items():
        if event_type.startswith(prefix):
            categories.add(category)
    categories.add("overview")    # le stats si aggiornano sempre
    categories.add("audit")       # il log si aggiorna sempre
    return categories
```

**Esempio:**

```
Evento: "registry.agent.registered"
  → categories: {"agents", "overview", "audit"}

Il frontend:
  - Pagina agenti? → REFRESH (c'è "agents")
  - Pagina sessioni? → no refresh (non c'è "sessions")
  - Pagina overview? → REFRESH (c'è sempre)
```

### Lato frontend — `data-sse-page`

Ogni pagina della dashboard ha un attributo che indica la sua categoria:

```html
<!-- agents.html -->
<div data-sse-page="agents">
  <!-- contenuto agenti -->
</div>

<!-- JavaScript nel base.html -->
<script>
const source = new EventSource("/dashboard/sse");
const myPage = document.querySelector("[data-sse-page]")?.dataset.ssePage;

source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.categories.includes(myPage)) {
        // HTMX partial refresh — ricarica solo il contenuto, non tutta la pagina
        htmx.trigger(document.body, "sse-refresh");
    }
};
</script>
```

L'indicatore **"Live"** nella sidebar si accende quando la connessione SSE è attiva:

```html
<span id="live-indicator" class="text-green-500 hidden">● Live</span>

<script>
source.onopen = () => document.getElementById("live-indicator").classList.remove("hidden");
source.onerror = () => document.getElementById("live-indicator").classList.add("hidden");
</script>
```

---

## L'hook in log_event() — il collegamento

Ogni evento di audit nel broker passa per `log_event()` in `app/db/audit.py`. L'hook SSE è agganciato lì:

```python
# In app/db/audit.py
async def log_event(db, event_type, details, ...):
    # 1. Salva nel DB (audit hash chain)
    record = AuditLog(event_type=event_type, ...)
    db.add(record)
    await db.flush()

    # 2. Notifica SSE (dashboard real-time)
    await sse_manager.broadcast(event_type, {"event_id": record.id})
```

Questo significa che **ogni azione auditata** è automaticamente una notifica SSE. Non serve aggiungere notifiche esplicite: se passi per l'audit log, la dashboard si aggiorna da sola.

---

## L'endpoint SSE (`GET /dashboard/sse`)

```python
@router.get("/sse")
async def dashboard_sse(request: Request):
    client_id, queue = sse_manager.connect()

    async def event_stream():
        try:
            while True:
                try:
                    # Aspetta un evento (con timeout per keepalive)
                    payload = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Keepalive ogni 30 secondi — mantiene la connessione viva
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            sse_manager.disconnect(client_id)

    return StreamingResponse(event_stream(), media_type="text/event-stream")
```

**Keepalive ogni 30 secondi:** se non ci sono eventi per 30 secondi, il server manda un commento SSE (`: keepalive`). Questo impedisce a proxy/load balancer di chiudere la connessione per inattività. I commenti SSE (righe che iniziano con `:`) sono ignorati dal browser.

---

## SSE vs WebSocket vs Polling — confronto

| | Polling | SSE | WebSocket |
|---|---|---|---|
| Direzione | Client → Server | **Server → Client** | Bidirezionale |
| Protocollo | HTTP ripetuto | HTTP streaming | Upgrade a WS |
| Riconnessione | Manuale | **Automatica** | Manuale |
| Complessità | Bassa | **Bassa** | Alta |
| Latenza | Alta (intervallo) | **Istantanea** | Istantanea |
| Uso in Cullis | — | **Dashboard** | Chat agenti |

Cullis usa **entrambi**: SSE per la dashboard admin (notifiche unidirezionali) e WebSocket per la comunicazione agente-agente (messaggi bidirezionali).

---

## Riepilogo — cosa portarti a casa

- **SSE** (Server-Sent Events) = stream unidirezionale server → client, perfetto per notifiche
- Il `DashboardSSEManager` è un singleton con Queue per client (maxsize=64)
- Il **broadcast** è non-blocking — client lenti vengono disconnessi
- Le **categorie** permettono refresh selettivo (agents, sessions, orgs...) — non tutta la pagina
- L'hook in `log_event()` collega l'audit trail alla dashboard: ogni azione auditata = notifica SSE
- **Keepalive** ogni 30 secondi mantiene la connessione viva
- `EventSource` nel browser si riconnette automaticamente
- SSE per la dashboard, WebSocket per gli agenti — strumenti diversi per problemi diversi
- Codice: `app/dashboard/sse.py` (manager), `app/db/audit.py` (hook), `base.html` (frontend)

---

*Prossimo capitolo: [30 — Python SDK](30-python-sdk.md) — il pacchetto che rende tutto accessibile*
