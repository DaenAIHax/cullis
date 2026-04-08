# Capitolo 27 — Audit Ledger Crittografico

> *"Il registro del notaio dove ogni pagina e sigillata con la ceralacca della pagina precedente. Strappa una pagina, e il sigillo della successiva non torna piu."*

---

## Cos'e un audit log — spiegazione da bar

In ogni azienda seria c'e un **registro delle operazioni**. Chi ha fatto cosa, quando, con quale risultato. Serve per:

- **Compliance**: il revisore dei conti vuole vedere che le regole sono state rispettate
- **Forensics**: se succede qualcosa di brutto, devi poter ricostruire cosa e successo
- **Non-repudiazione**: nessuno puo dire "non sono stato io" se c'e la prova scritta

Ma un semplice log ha un problema: **chiunque con accesso al database puo modificarlo**. Un attaccante (o un admin disonesto) potrebbe cancellare le tracce del proprio operato.

**Analogia:** Immagina il registro presenze di un palazzo. Se il guardiano usa una matita, puo cancellare la riga "Mario Rossi — ore 3:00 di notte — sala server". Con la penna, non puo cancellare ma puo strappare la pagina. Serve qualcosa di meglio.

---

## La hash chain — la ceralacca digitale

Cullis risolve con una **hash chain crittografica**: ogni entry dell'audit log contiene l'hash SHA-256 della entry precedente. Se qualcuno modifica, cancella, o riordina un record, la catena si rompe.

```
Entry #1                     Entry #2                     Entry #3
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│ event: agent_join │        │ event: session    │        │ event: message   │
│ agent: acme::buy │        │ session: sess-001 │        │ session: sess-001│
│ result: ok       │        │ result: ok        │        │ result: ok       │
│                  │        │                   │        │                  │
│ prev_hash: null  │        │ prev_hash: a3f2.. │        │ prev_hash: 7b1d..│
│ entry_hash:      │───────▶│ entry_hash:       │───────▶│ entry_hash:      │
│   a3f2c8...      │        │   7b1d5e...       │        │   e9a4f1...      │
└──────────────────┘        └──────────────────┘        └──────────────────┘
                                                              │
                                                              ▼
                                Se qualcuno modifica Entry #2,
                                il suo hash cambia → prev_hash
                                di Entry #3 non corrisponde piu
                                → TAMPERING RILEVATO
```

**Analogia:** Ogni pagina del registro ha un sigillo di ceralacca che include l'impronta della pagina precedente. Se strappi o modifichi una pagina, il sigillo della pagina successiva non corrisponde piu. E la catena e rotta da quel punto in poi — non puoi "aggiustare" solo una pagina senza rifare tutte le successive (e per quello ti servirebbe l'hash della prima, che non puoi falsificare).

---

## L'implementazione in Cullis

### Il modello — la tabella audit_log

```python
# Da app/db/audit.py — AuditLog

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(128), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    org_id = Column(String(128), nullable=True, index=True)
    details = Column(Text, nullable=True)        # JSON serializzato
    result = Column(String(16), nullable=False)   # "ok" | "denied" | "error"
    entry_hash = Column(String(64), nullable=True, index=True)
    previous_hash = Column(String(64), nullable=True)
```

Ogni riga ha:
- **Chi**: `agent_id`, `org_id`
- **Cosa**: `event_type`, `details` (JSON con i dettagli specifici)
- **Quando**: `timestamp` con timezone
- **Esito**: `result` — ok, denied, o error
- **La catena**: `entry_hash` (hash di questa riga) e `previous_hash` (hash della riga precedente)

### Il calcolo dell'hash

```python
# Da app/db/audit.py — compute_entry_hash

def compute_entry_hash(
    entry_id, timestamp, event_type,
    agent_id, session_id, org_id,
    result, details, previous_hash,
) -> str:
    canonical = (
        f"{entry_id}|{timestamp.isoformat()}|{event_type}|"
        f"{agent_id or ''}|{session_id or ''}|{org_id or ''}|"
        f"{result}|{details or ''}|{previous_hash or 'genesis'}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

L'hash e **deterministico**: dati gli stessi input, produce sempre lo stesso output. La stringa canonica include **tutti i campi** — se cambi anche un solo carattere di un qualsiasi campo, l'hash e completamente diverso.

Il primo entry della catena ha `previous_hash = 'genesis'` — il "blocco genesi", come in una blockchain.

### log_event() — l'inserimento atomico

```python
# Da app/db/audit.py — log_event (semplificato)

_audit_chain_lock = asyncio.Lock()

async def log_event(db, event_type, result, agent_id=None,
                    session_id=None, org_id=None, details=None):

    async with _audit_chain_lock:
        # 1. Leggi l'hash dell'ultimo entry
        last = await db.execute(
            select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        previous_hash = last.scalar_one_or_none()

        # 2. Crea il nuovo entry
        entry = AuditLog(
            event_type=event_type,
            agent_id=agent_id,
            previous_hash=previous_hash,
            result=result,
            ...
        )
        db.add(entry)
        await db.flush()  # assegna l'ID auto-incrementale

        # 3. Calcola e salva l'hash
        entry.entry_hash = compute_entry_hash(
            entry.id, entry.timestamp, event_type,
            agent_id, session_id, org_id, result,
            details_json, previous_hash,
        )
        await db.commit()

    # 4. Notifica la dashboard via SSE
    from app.dashboard.sse import sse_manager
    await sse_manager.broadcast(event_type)
```

Il punto critico e il **lock**: `_audit_chain_lock` serializza gli inserimenti. Perche? Senza lock, due coroutine concorrenti potrebbero:

1. Leggere lo stesso `previous_hash`
2. Inserire entrambe con lo stesso `previous_hash`
3. La catena si **biforca** — due rami paralleli, impossibile da verificare

Il lock garantisce che read → insert → commit sia atomico.

**Analogia:** Solo un notaio alla volta puo scrivere nel registro. Il secondo aspetta che il primo abbia finito, sigillato la pagina, e passato il sigillo per la pagina successiva.

---

## Verifica dell'integrita

A cosa serve una hash chain se non la verifichi? Cullis ha una funzione `verify_chain` che cammina l'intera catena:

```python
# Da app/db/audit.py — verify_chain

async def verify_chain(db) -> tuple[bool, int, int]:
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.id.asc())
    )
    entries = result.scalars().all()

    expected_previous = None
    for i, entry in enumerate(entries):
        # 1. Il previous_hash corrisponde all'hash dell'entry precedente?
        if entry.previous_hash != expected_previous:
            return (False, i, entry.id)  # catena rotta!

        # 2. L'hash salvato corrisponde al ricalcolo?
        expected_hash = compute_entry_hash(...)
        if entry.entry_hash != expected_hash:
            return (False, i, entry.id)  # entry alterato!

        expected_previous = entry.entry_hash

    return (True, len(entries), 0)  # tutto ok
```

Due controlli per ogni entry:
1. **Continuita**: il `previous_hash` di questa entry corrisponde all'`entry_hash` della precedente?
2. **Integrita**: l'`entry_hash` salvato corrisponde al ricalcolo su tutti i campi?

Se un attaccante modifica anche un solo byte, il ricalcolo produce un hash diverso. Se cancella un entry, il `previous_hash` del successivo non corrisponde.

---

## Export — NDJSON e CSV

L'audit log puo essere esportato per analisi esterna, SIEM, o archiviazione:

```python
# Da app/onboarding/router.py — export_audit_logs

@admin_router.get("/audit/export")
async def export_audit_logs(
    db, start=None, end=None, org_id=None,
    event_type=None, format="json", limit=10000,
):
    entries = await query_audit_logs(db, start, end, org_id, event_type, limit)

    if format == "csv":
        # Header + righe CSV
        writer.writerow(["id", "timestamp", "event_type", ...])
        for e in entries:
            writer.writerow([e.id, e.timestamp.isoformat(), ...])
        return StreamingResponse(media_type="text/csv")

    # Default: NDJSON (newline-delimited JSON)
    def _generate():
        for e in entries:
            yield json.dumps({
                "id": e.id, "event_type": e.event_type,
                "entry_hash": e.entry_hash, ...
            }) + "\n"
    return StreamingResponse(media_type="application/x-ndjson")
```

### NDJSON vs JSON normale

| Formato | Struttura | Vantaggio |
|---------|-----------|-----------|
| JSON | `[{...}, {...}, {...}]` | Va parsato tutto in memoria |
| NDJSON | `{...}\n{...}\n{...}\n` | Ogni riga e un JSON indipendente — puoi processare riga per riga, anche con milioni di entry |

**Analogia:** JSON e un libro che devi leggere tutto per trovare una pagina. NDJSON e un raccoglitore ad anelli — puoi prendere un foglio alla volta.

### Filtri disponibili

```
GET /v1/admin/audit/export?org_id=acme&event_type=auth.token&start=2026-04-01&end=2026-04-08&format=csv&limit=1000
```

| Filtro | Descrizione |
|--------|-------------|
| `org_id` | Solo eventi di una organizzazione |
| `event_type` | Solo un tipo specifico (auth.token, session.create, ecc.) |
| `start` / `end` | Intervallo temporale |
| `format` | `json` (NDJSON) o `csv` |
| `limit` | Massimo numero di righe (default 10000, max 50000) |

---

## Integrazione SIEM

Un **SIEM** (Security Information and Event Management) e il "centro di controllo" della sicurezza di un'organizzazione. Raccoglie log da tutti i sistemi e li correla per rilevare minacce.

Cullis si integra con i SIEM in due modi:

1. **Export periodico**: un job esterno chiama `/v1/admin/audit/export` e invia i dati al SIEM
2. **Log strutturati JSON**: con `LOG_FORMAT=json` i log applicativi sono gia in formato SIEM-friendly

```yaml
# Da docker-compose.prod.yml

broker:
  environment:
    LOG_FORMAT: "json"    # log strutturati per il SIEM
```

```
┌─────────────┐     NDJSON export     ┌──────────────┐
│ Cullis Broker│─────────────────────▶│    SIEM      │
│             │     ogni 5 min        │ (Splunk,     │
│  audit_log  │◀─── verify_chain ───│  Sentinel,   │
│  hash chain │     periodica        │  ELK)        │
└─────────────┘                      └──────────────┘
```

Il SIEM puo anche verificare la hash chain indipendentemente: basta ricalcolare gli hash riga per riga e confrontare. Se trova una discrepanza, allarme immediato.

---

## Riepilogo — cosa portarti a casa

- L'audit log di Cullis e **append-only** con **hash chain SHA-256** — ogni entry contiene l'hash della precedente
- Se qualcuno modifica, cancella, o riordina un record, la catena si rompe e il **tampering e rilevabile**
- Il `_audit_chain_lock` serializza gli inserimenti per evitare biforcazioni della catena
- `verify_chain()` cammina l'intera catena e verifica continuita + integrita di ogni entry
- Export in **NDJSON** (streaming, una riga = un JSON) o **CSV**, con filtri per org, tipo, data, e limite
- Ogni `log_event()` notifica la dashboard via **SSE** — aggiornamenti in tempo reale
- Integrazione SIEM tramite export periodico o log strutturati JSON

---

*Prossimo capitolo: [28 — OpenTelemetry e Jaeger](28-opentelemetry-jaeger.md) — osservabilita distribuita per capire cosa succede dentro il broker*
