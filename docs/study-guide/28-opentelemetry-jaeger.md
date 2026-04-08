# Capitolo 28 — OpenTelemetry e Jaeger

> *"Le telecamere di sicurezza del palazzo: registrano tutto cio che succede, stanza per stanza, cosi se qualcosa va storto puoi rivedere il filmato e capire dove si e rotto."*

---

## Cos'e l'osservabilita — spiegazione da bar

Immagina di gestire un ristorante con 50 coperti. Tutto sembra funzionare, ma i clienti si lamentano che il servizio e lento. Dove sta il problema?

- Il cuoco e lento? (backend lento)
- I camerieri sono pochi? (troppe connessioni)
- La cassa si blocca? (database sotto stress)
- Ci sono troppi ordini contemporanei? (rate limiting)

Senza dati, puoi solo indovinare. Con **l'osservabilita**, hai:

1. **Traces** — il percorso completo di ogni ordine: dal momento in cui il cliente chiede il menu fino a quando paga il conto
2. **Metrics** — i numeri aggregati: quanti ordini al minuto, tempo medio in cucina, quanti piatti restituiti
3. **Logs** — il diario del cuoco: "ho bruciato la bistecca alle 20:15"

**OpenTelemetry** e lo standard aperto per raccogliere tutti e tre. **Jaeger** e l'interfaccia per visualizzare le traces.

---

## I tre pilastri dell'osservabilita

```
┌──────────────────────────────────────────────────────────┐
│                    OSSERVABILITA                         │
│                                                          │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐      │
│  │  TRACES  │      │ METRICS  │      │   LOGS   │      │
│  │          │      │          │      │          │      │
│  │ percorso │      │ contatori│      │ messaggi │      │
│  │ di una   │      │ e medie  │      │ testuali │      │
│  │ richiesta│      │ aggregate│      │ dettaglio│      │
│  └──────────┘      └──────────┘      └──────────┘      │
│                                                          │
│  "Questa richiesta  "10 auth/min,     "Errore: cert     │
│   ha impiegato      latenza media     scaduto per       │
│   150ms, di cui     12ms per x509,    agente acme::buy" │
│   80ms in x509"     3 sessioni/ora"                     │
└──────────────────────────────────────────────────────────┘
```

### Traces — il viaggio della richiesta

Una **trace** segue una richiesta dal punto di ingresso fino alla risposta, attraversando tutti i componenti del sistema.

```
Trace: "POST /v1/auth/token" (totale: 145ms)
│
├── Span: FastAPI handler ────────────────────── 145ms
│   ├── Span: x509 verify chain ──────────────  80ms
│   ├── Span: DPoP proof verify ──────────────  12ms
│   ├── Span: Redis SET NX (JTI) ────────────   2ms
│   ├── Span: Postgres INSERT (audit) ───────  15ms
│   └── Span: JWT sign ──────────────────────  10ms
```

Ogni blocco e uno **span**: un'operazione con un inizio e una fine. Gli span sono annidati — lo span padre contiene i figli.

**Analogia:** La ricevuta dettagliata del ristorante. Non dice solo "pranzo: 45 euro" — dice "antipasto: 12 euro (8 min), primo: 15 euro (12 min), secondo: 18 euro (20 min)". Sai esattamente dove e andato il tempo.

### Metrics — i numeri aggregati

Le metriche sono **contatori** e **istogrammi** che danno una visione d'insieme:

- Quante autenticazioni riuscite/fallite al minuto?
- Qual e la latenza media della verifica x509?
- Quante richieste sono state bloccate dal rate limiter?

Non ti dicono il dettaglio di una singola richiesta, ma mostrano i trend: "alle 14:00 la latenza e raddoppiata" o "le sessioni negate sono aumentate del 300%".

### Logs — il dettaglio testuale

I log classici: messaggi testuali con timestamp, livello (INFO, WARNING, ERROR), e contesto. Utili per il debug, ma difficili da correlare senza traces.

---

## OpenTelemetry — lo standard vendor-neutral

OpenTelemetry (OTel) e il progetto CNCF che unifica la raccolta di telemetria. Il vantaggio? **Scrivi il codice una volta, e puoi inviare i dati a qualsiasi backend**: Jaeger, Grafana Tempo, Datadog, New Relic — basta cambiare l'exporter.

```
┌──────────────────────────────────────────────────────────┐
│                    CULLIS BROKER                         │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ FastAPI      │  │ SQLAlchemy  │  │ Redis       │    │
│  │  auto-instr  │  │  auto-instr │  │  auto-instr │    │
│  └──────┬───────┘  └──────┬──────┘  └──────┬──────┘    │
│         └─────────────────┼─────────────────┘           │
│                    ┌──────▼──────┐                      │
│                    │ OTel SDK    │                      │
│                    │ BatchSpan   │                      │
│                    │ Processor   │                      │
│                    └──────┬──────┘                      │
│                           │ OTLP/gRPC                   │
└───────────────────────────┼──────────────────────────────┘
                            │
                     ┌──────▼──────┐
                     │   Jaeger    │
                     │  porta 4317 │
                     │  (OTLP)     │
                     │             │
                     │  UI: 16686  │
                     └─────────────┘
```

---

## L'implementazione in Cullis

### Inizializzazione — `app/telemetry.py`

```python
# Da app/telemetry.py — init_telemetry (semplificato)

def init_telemetry() -> None:
    settings = get_settings()

    if not settings.otel_enabled:
        _log.info("OpenTelemetry disabled (OTEL_ENABLED=false)")
        return

    # Resource: identifica questo servizio
    resource = Resource.create({SERVICE_NAME: settings.otel_service_name})

    # Traces: BatchSpanProcessor → OTLP exporter → Jaeger
    span_exporter = OTLPSpanExporter(
        endpoint=settings.otel_exporter_otlp_endpoint,
        insecure=settings.otel_exporter_insecure,
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # Metrics: PeriodicExportingMetricReader → OTLP exporter → Jaeger
    metric_exporter = OTLPMetricExporter(
        endpoint=settings.otel_exporter_otlp_endpoint,
    )
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter,
        export_interval_millis=settings.otel_metrics_export_interval_ms,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
```

Punti chiave:
- **Resource**: identifica il servizio come `cullis-broker` — cosi in Jaeger sai da dove arrivano le traces
- **BatchSpanProcessor**: raggruppa gli span e li invia in batch (efficiente, non blocca)
- **OTLP/gRPC**: il protocollo standard per l'invio — porta 4317
- **Graceful degradation**: se OTel non riesce a inizializzarsi, il broker funziona comunque con tracer/meter no-op

### Auto-instrumentazione

La parte piu potente: con tre righe di codice, OTel instrumenta automaticamente tutte le librerie:

```python
# Da app/telemetry.py — auto-instrumentation

from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

SQLAlchemyInstrumentor().instrument()    # ogni query DB → span
RedisInstrumentor().instrument()          # ogni comando Redis → span
HTTPXClientInstrumentor().instrument()    # ogni HTTP client call → span
```

**Senza scrivere una riga di codice**, ogni query al database, ogni comando Redis, e ogni chiamata HTTP in uscita (es. verso i PDP webhook) genera automaticamente uno span nella trace.

**Analogia:** Invece di piazzare una telecamera manualmente in ogni stanza, installi un sistema che mette automaticamente una telecamera ovunque ci sia una porta.

### Custom metrics — `app/telemetry_metrics.py`

Oltre all'auto-instrumentazione, Cullis definisce metriche di business:

```python
# Da app/telemetry_metrics.py

# Contatori
AUTH_SUCCESS_COUNTER = meter.create_counter(
    name="atn.auth.success",
    description="Successful token issuances",
)
AUTH_DENY_COUNTER = meter.create_counter(
    name="atn.auth.deny",
    description="Denied token requests",
)
SESSION_CREATED_COUNTER = meter.create_counter(name="atn.session.created", ...)
SESSION_DENIED_COUNTER = meter.create_counter(name="atn.session.denied", ...)
POLICY_ALLOW_COUNTER = meter.create_counter(name="atn.policy.allow", ...)
POLICY_DENY_COUNTER = meter.create_counter(name="atn.policy.deny", ...)
RATE_LIMIT_REJECT_COUNTER = meter.create_counter(name="atn.ratelimit.reject", ...)

# Istogrammi (distribuzione dei tempi)
AUTH_DURATION_HISTOGRAM = meter.create_histogram(
    name="atn.auth.duration",
    description="Full auth token issuance duration",
    unit="ms",
)
X509_VERIFY_DURATION_HISTOGRAM = meter.create_histogram(
    name="atn.x509.verify_duration",
    unit="ms",
)
PDP_WEBHOOK_LATENCY_HISTOGRAM = meter.create_histogram(
    name="atn.pdp_webhook.latency",
    unit="ms",
)
```

Queste metriche vengono usate nel codice con una singola riga:

```python
AUTH_SUCCESS_COUNTER.add(1, {"org": org_id})
AUTH_DURATION_HISTOGRAM.record(elapsed_ms)
```

Quando OTel e disabilitato, queste sono **no-op**: la chiamata `.add()` non fa nulla — zero overhead.

---

## La configurazione Docker

```yaml
# Da docker-compose.yml

jaeger:
  image: jaegertracing/all-in-one:1.58
  ports:
    - "16686:16686"     # UI web
    - "4317:4317"       # OTLP gRPC (riceve traces e metriche)
  environment:
    COLLECTOR_OTLP_ENABLED: "true"

broker:
  environment:
    OTEL_ENABLED: "true"
    OTEL_SERVICE_NAME: "cullis-broker"
    OTEL_EXPORTER_OTLP_ENDPOINT: "http://jaeger:4317"
    OTEL_EXPORTER_INSECURE: "true"
```

In produzione, il sampling viene ridotto per non sovraccaricare:

```yaml
# Da docker-compose.prod.yml
OTEL_TRACES_SAMPLER_ARG: "0.1"   # Solo il 10% delle traces
```

E la UI di Jaeger non viene esposta pubblicamente:

```yaml
jaeger:
  ports: []   # Accesso solo via SSH tunnel o VPN
```

---

## La Jaeger UI — leggere le traces

Dopo `docker compose up`, apri `http://localhost:16686` e puoi:

1. **Cercare traces** per servizio, operazione, durata, o tag
2. **Visualizzare il waterfall** — lo span tree di una richiesta
3. **Confrontare traces** — due richieste simili, una veloce e una lenta: dove sta la differenza?
4. **Analizzare errori** — gli span con errori sono evidenziati in rosso

```
Jaeger UI — esempio di trace:

cullis-broker: POST /v1/auth/token (145ms)
├── x509_verify_chain ████████████████████████████░░░  80ms
├── dpop_verify        ███░░░░░░░░░░░░░░░░░░░░░░░░░░  12ms
├── redis SET NX       █░░░░░░░░░░░░░░░░░░░░░░░░░░░░   2ms
├── postgres INSERT    ████░░░░░░░░░░░░░░░░░░░░░░░░░░  15ms
└── jwt_sign           ███░░░░░░░░░░░░░░░░░░░░░░░░░░░  10ms

→ L'80% del tempo e nella verifica x509. Ottimizzazione: cache OCSP.
```

---

## Graceful shutdown

Quando il broker si spegne, le traces in coda devono essere inviate prima di chiudere:

```python
# Da app/telemetry.py — shutdown_telemetry

def shutdown_telemetry() -> None:
    provider = trace.get_tracer_provider()
    if hasattr(provider, "shutdown"):
        provider.shutdown()           # flush pending spans
    m_provider = metrics.get_meter_provider()
    if hasattr(m_provider, "shutdown"):
        m_provider.shutdown()         # flush pending metrics
```

Senza questo, le ultime traces prima dello shutdown andrebbero perse.

---

## Riepilogo — cosa portarti a casa

- **OpenTelemetry** e lo standard vendor-neutral per traces, metriche, e log
- **Traces** mostrano il percorso completo di una richiesta attraverso tutti i componenti
- **Auto-instrumentazione**: SQLAlchemy, Redis, HTTPX instrumentati con tre righe di codice
- **Custom metrics**: contatori (auth success/deny) e istogrammi (latenza x509, PDP webhook)
- **Jaeger** visualizza le traces — UI su porta 16686
- Quando OTel e disabilitato, tracer e meter diventano **no-op** — zero overhead
- In produzione: sampling al 10%, Jaeger non esposta pubblicamente

---

*Prossimo capitolo: [29 — Dashboard Real-Time (SSE)](29-sse-dashboard.md) — aggiornamenti istantanei nella dashboard con Server-Sent Events*
