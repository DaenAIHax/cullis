# Capitolo 07 — SPIFFE — Secure Production Identity Framework

> *"Non mi interessa su quale server giri. Mi interessa CHI SEI."*

---

## Il problema — spiegazione da bar

Nel mondo degli umani, l'identità è semplice: nome, cognome, codice fiscale. Ma nel mondo dei software?

Immagina un microservizio che gira in un container Docker. Quel container può essere distrutto e ricreato 100 volte al giorno, su server diversi, con IP diversi. Come lo identifichi? Per IP? Cambia. Per hostname? Cambia. Per nome del container? È un hash casuale.

E se quel microservizio deve dimostrare la propria identità a un altro servizio in un'altra rete? Serve un sistema di identità che funzioni **a prescindere dall'infrastruttura**.

**SPIFFE** (Secure Production Identity Framework for Everyone) è la risposta: un'identità per workload (software in esecuzione), standardizzata, verificabile, indipendente da dove gira.

---

## SPIFFE ID — il "codice fiscale" dei workload

### Il formato

Uno SPIFFE ID è un **URI** con schema `spiffe://`:

```
spiffe://trust-domain/path/components

Esempi:
  spiffe://atn.local/acmebuyer/buyer
  spiffe://mycompany.com/payments/processor
  spiffe://k8s-cluster.prod/ns/default/sa/frontend
```

### Le parti

```
spiffe://  atn.local    / acmebuyer / buyer
────────   ──────────     ─────────   ─────
schema     trust domain   org_id      agent_name
(fisso)    (chi gestisce   (path components - significato
            la radice       definito dall'implementazione)
            di fiducia)
```

| Parte | Cos'è | Regole |
|---|---|---|
| **Schema** | Sempre `spiffe://` | Fisso, non cambia |
| **Trust domain** | Il dominio di fiducia | Lowercase, alfanumerico, punti, trattini. Es: `atn.local`, `prod.mycompany.com` |
| **Path** | Identifica il workload dentro il trust domain | Uno o più componenti separati da `/` |

### Cosa NON è uno SPIFFE ID

```
✗ spiffe://atn.local                        → path vuoto (non valido)
✗ spiffe://atn.local/buyer?role=admin        → query string (non permessa)
✗ spiffe://ATN.LOCAL/buyer                   → maiuscole nel trust domain (non permesse)
✗ spiffe://atn.local/buyer#section           → fragment (non permesso)
✗ https://atn.local/buyer                    → schema sbagliato (deve essere spiffe://)
```

---

## SPIFFE in Cullis — come lo usiamo

### Formato Cullis

```
Formato interno Cullis:     acme::buyer
                            ────   ─────
                            org    agent_name

SPIFFE ID equivalente:      spiffe://atn.local/acme/buyer
                            ────────  ─────────  ────  ─────
                            schema    domain     org   agent

Conversione bidirezionale:
  "acme::buyer" ←→ "spiffe://atn.local/acme/buyer"
```

### Il modulo `app/spiffe.py`

Cullis ha un modulo dedicato per la conversione bidirezionale. Ecco le funzioni principali:

```python
# Interno → SPIFFE
internal_id_to_spiffe("acme::buyer", "atn.local")
# → "spiffe://atn.local/acme/buyer"

# SPIFFE → Interno
spiffe_to_internal_id("spiffe://atn.local/acme/buyer")
# → "acme::buyer"

# Scomponi SPIFFE in parti
spiffe_to_agent_id("spiffe://atn.local/acme/buyer")
# → ("acme", "buyer")

# Costruisci da parti
agent_id_to_spiffe("acme", "buyer", "atn.local")
# → "spiffe://atn.local/acme/buyer"

# Valida
validate_spiffe_id("spiffe://atn.local/acme/buyer")
# → True (o ValueError se invalido)
```

La validazione è rigorosa:

```python
# Trust domain: solo lowercase, cifre, trattini, punti
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")

# Componenti path: lettere, cifre, trattini, underscore, punti
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")
```

### Dove appare lo SPIFFE ID

Lo SPIFFE ID appare in **tre posti** nel sistema:

#### 1. Nel certificato x509 — SAN URI

```
Certificato dell'agente acme::buyer:
  Subject Alternative Name:
    URI: spiffe://atn.local/acme/buyer
```

Generato in `generate_certs.py:204`:
```python
x509.SubjectAlternativeName([
    x509.UniformResourceIdentifier(spiffe_id),
])
```

#### 2. Nel JWT client_assertion — claim `sub` e `iss`

```json
{
  "sub": "spiffe://atn.local/acme/buyer",
  "iss": "spiffe://atn.local/acme/buyer",
  "aud": "agent-trust-broker",
  "exp": 1712345678,
  "jti": "uuid-random"
}
```

#### 3. Nel database registry — campo `agent_uri`

```
agents table:
  agent_id:  "acme::buyer"
  org_id:    "acme"
  agent_uri: "spiffe://atn.local/acme/buyer"
```

### Verifica SPIFFE SAN durante l'autenticazione

In `app/auth/x509_verifier.py:220-238`, il broker verifica che lo SPIFFE ID nel certificato corrisponda:

```python
# Estrai gli URI SAN dal certificato
san_ext = agent_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]

# Calcola lo SPIFFE ID atteso basandoti su agent_id e trust_domain
expected_spiffe = internal_id_to_spiffe(agent_id, settings.trust_domain)

# Verifica
if spiffe_sans:
    if expected_spiffe not in spiffe_sans:
        raise HTTPException(401, "SPIFFE ID in SAN does not match")
elif settings.require_spiffe_san:
    raise HTTPException(401, "Certificate missing SPIFFE SAN URI")
```

Due modalità:
- **`require_spiffe_san=false`** (default): se il cert ha un SAN SPIFFE, lo verifica. Se non ce l'ha, accetta comunque (backward compatibility).
- **`require_spiffe_san=true`**: il cert DEVE avere un SAN SPIFFE. Senza → rifiutato.

---

## SVID — SPIFFE Verifiable Identity Document

Lo standard SPIFFE definisce anche il formato per **dimostrare** l'identità: lo SVID (SPIFFE Verifiable Identity Document).

Esistono due tipi:

### x509-SVID (quello che usa Cullis)

Un certificato x509 con lo SPIFFE ID nel SAN URI:

```
Certificato x509-SVID:
  Subject: CN=acme::buyer
  SAN URI: spiffe://atn.local/acme/buyer    ← lo SPIFFE ID
  Key Usage: digitalSignature
  BasicConstraints: CA=false
  
  Firmato dalla CA dell'org (che è nella catena SPIFFE)
```

**Vantaggi:** usa l'infrastruttura PKI esistente (stessi certificati), il SPIFFE ID è semplicemente un campo in più.

### JWT-SVID

Un JWT con lo SPIFFE ID nel claim `sub`:

```json
{
  "sub": "spiffe://atn.local/acme/buyer",
  "aud": ["spiffe://atn.local/widgets/supplier"],
  "exp": 1712345678
}
```

**Vantaggi:** non serve gestire certificati, basta firmare JWT. Meno sicuro (bearer token) ma più semplice.

**Cullis usa x509-SVID** perché la sicurezza è la priorità e la PKI c'è già.

---

## SPIRE — l'implementazione di riferimento (contesto)

**SPIRE** (SPIFFE Runtime Environment) è l'implementazione ufficiale di SPIFFE, mantenuta dalla CNCF.

```
SPIRE Architecture:
  ┌──────────────┐
  │  SPIRE Server │  ← gestisce le identità, emette SVID
  └──────┬───────┘
         │
  ┌──────┴───────┐
  │  SPIRE Agent │  ← gira su ogni nodo, distribuisce SVID ai workload
  └──────┬───────┘
         │
  ┌──────┴───────┐
  │   Workload   │  ← riceve l'SVID via Workload API (Unix socket)
  └──────────────┘
```

**Cullis NON usa SPIRE.** Cullis ha la propria PKI e gestione identità. Ma usa il **formato SPIFFE** per le identità, così:

- Gli SPIFFE ID sono standard e interoperabili
- Se un'org usa SPIRE internamente, può integrare i propri SVID con Cullis
- I tool che capiscono SPIFFE (Envoy, Istio, Consul Connect) possono riconoscere gli agenti Cullis

---

## Perché SPIFFE e non un formato custom?

| Approccio | Problema |
|---|---|
| Usare l'agent_id come identità (`acme::buyer`) | Formato custom, non standard, non interoperabile |
| Usare un UUID | Non leggibile, non gerarchico, non dice niente sull'org |
| Usare un email (`buyer@acme.com`) | È per umani, implica un dominio email, non adatto a workload |
| **Usare SPIFFE** (`spiffe://atn.local/acme/buyer`) | Standard CNCF, gerarchico (trust domain > org > agent), interoperabile, tool ecosystem |

SPIFFE è lo standard emergente per l'identità workload nel cloud-native. Usandolo, Cullis parla la stessa lingua di Kubernetes, Istio, Envoy, HashiCorp Consul, e tutto l'ecosistema service mesh.

---

## Riepilogo — cosa portarti a casa

- **SPIFFE** è un framework per dare identità ai software (workload), indipendentemente da dove girano
- Uno **SPIFFE ID** è un URI: `spiffe://trust-domain/path` — il "codice fiscale" dei workload
- In Cullis: `spiffe://atn.local/{org}/{agent}` — equivale all'interno `org::agent`
- Lo SPIFFE ID va nel **SAN URI** del certificato x509 e nel claim `sub` del JWT
- Cullis verifica lo SPIFFE SAN durante l'autenticazione (opzionale o obbligatorio via config)
- **x509-SVID** (cert con SPIFFE SAN) è il tipo usato da Cullis
- **SPIRE** è l'implementazione di riferimento — Cullis non lo usa ma è compatibile col formato
- Codice: `app/spiffe.py` per conversioni, `app/auth/x509_verifier.py:220-238` per la verifica

---

*Prossimo capitolo: [08 — Revoca Certificati](08-revoca-certificati.md) — cosa fare quando un certificato viene compromesso*
