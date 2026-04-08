# Capitolo 01 — Zero Trust Architecture

> *"Non fidarti di nessuno. Verifica sempre. Dai solo il minimo necessario."*

---

## Cos'è Zero Trust — spiegazione da bar

Immagina un palazzo di uffici negli anni '90. C'è un guardiano all'ingresso: mostri il badge, entri, e poi puoi andare ovunque — ogni piano, ogni stanza, la sala server. Una volta dentro, sei "trusted".

Questo è il modello **perimetrale** (castle-and-moat): muro fuori, fiducia dentro.

Il problema? Se qualcuno ruba un badge, o entra da una finestra, ha accesso a tutto. Ed è esattamente quello che succede con le reti tradizionali: una volta superato il firewall, il traffico interno è "fidato".

**Zero Trust ribalta tutto:** non esiste un "dentro" e un "fuori". Ogni singola richiesta viene verificata, ogni volta, indipendentemente da dove arriva.

È come se ogni stanza del palazzo avesse la sua serratura, la sua telecamera, e il suo guardiano che ti chiede il badge ogni volta che entri — anche se sei appena uscito dalla stanza accanto.

---

## I tre principi fondamentali

### 1. Never Trust, Always Verify

Non importa chi sei, da dove vieni, o se ti ho già verificato 5 secondi fa. Ogni richiesta viene autenticata e autorizzata da zero.

**Esempio quotidiano:** Vai al bancomat. Anche se ci sei andato stamattina, devi rimettere la carta e il PIN. La banca non dice "ah, ti ho già visto oggi, vai pure."

### 2. Least Privilege (minimo privilegio)

Dai a ciascuno solo l'accesso strettamente necessario per fare il suo lavoro, niente di più.

**Esempio quotidiano:** In un hotel, la tessera della camera apre solo la tua stanza e la palestra. Non apre le altre camere, non apre la cucina, non apre la cassaforte. Anche se sei un ospite pagante.

### 3. Assume Breach (dài per scontato che qualcuno è già dentro)

Progetta il sistema partendo dal presupposto che un attaccante è già nella rete. Quindi ogni componente deve proteggersi autonomamente.

**Esempio quotidiano:** In un sottomarino, ogni sezione ha una porta stagna. Se un siluro buca lo scafo, si allaga solo una sezione — non tutto il sottomarino. Ogni sezione si assume che le altre possano essere compromesse.

---

## I componenti chiave di Zero Trust

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   SOGGETTO   │────────▶│     PEP      │────────▶│   RISORSA    │
│  (chi chiede)│         │ (chi blocca) │         │ (cosa vuole) │
└──────────────┘         └──────┬───────┘         └──────────────┘
                                │
                         ┌──────▼───────┐
                         │     PDP      │
                         │(chi decide)  │
                         └──────────────┘
```

### Soggetto
Chi fa la richiesta. Può essere un utente, un servizio, un agente AI.

### PEP — Policy Enforcement Point
Il "buttafuori". Sta davanti alla risorsa e blocca tutto per default. Se il PDP dice "ok", lascia passare. Se il PDP dice "no" (o non risponde), blocca.

**Analogia:** Il buttafuori di un locale. Non decide lui chi entra — chiede al responsabile (PDP) e poi esegue.

### PDP — Policy Decision Point
Il "cervello". Riceve la richiesta dal PEP, valuta le regole (policy), e risponde allow o deny.

**Analogia:** Il responsabile del locale che ha la lista degli invitati e le regole ("niente scarpe da ginnastica", "solo maggiorenni", "VIP al privé").

### Risorsa
Quello che il soggetto vuole raggiungere: un file, un'API, una sessione di comunicazione.

---

## Perché Zero Trust per agenti AI?

Nel mondo tradizionale, Zero Trust protegge **persone** che accedono a **risorse** (file, API, database).

Ma cosa succede quando due agenti AI di **aziende diverse** devono parlare tra loro?

### Il problema nuovo

Immagina: l'agente AI della tua azienda (un buyer) deve negoziare con l'agente AI di un fornitore (un supplier). Sono due software, di due organizzazioni diverse, che comunicano via internet.

Domande critiche:
- **Come sai che quell'agente è davvero del fornitore** e non un impostore?
- **Chi decide se possono parlare?** La tua azienda? Il fornitore? Entrambi?
- **Se qualcosa va storto**, come dimostri cosa è successo e chi ha detto cosa?
- **L'agente buyer può vedere solo le informazioni che gli servono**, non i dati interni del fornitore?

Il modello tradizionale (API key condivisa, o OAuth con un solo authorization server) non basta:
- Un'API key è un segreto condiviso — se la rubi, sei dentro
- OAuth standard ha un solo server di autorizzazione — ma qui le org sono DUE, ciascuna con le sue regole

**Serve Zero Trust, ma federato tra organizzazioni.**

---

## Come Cullis implementa Zero Trust

Cullis è un **trust broker federato** — il "notaio" neutrale tra organizzazioni. Ogni principio Zero Trust è implementato concretamente:

### Never Trust, Always Verify → x509 + DPoP + verifiche a ogni richiesta

In Cullis, un agente non ha un semplice username/password. Ha:

1. **Un certificato x509** firmato dalla CA della sua organizzazione (come un passaporto firmato dal governo del suo paese)
2. **Un token DPoP** che lega il token alla chiave crittografica dell'agente (come un biglietto nominativo con la tua foto)
3. **Verifiche a ogni chiamata:** il broker controlla il certificato, la firma DPoP, la validità del token, e se il certificato è stato revocato — ogni singola volta

```
Agente                           Broker
  │                                │
  │──── client_assertion ─────────▶│  ← JWT firmato con chiave privata agente
  │     (cert x509 + firma)        │     + catena certificati nell'header
  │                                │
  │                                │── verifica catena cert: agent → org CA → broker CA
  │                                │── verifica firma JWT con pubkey dal cert
  │                                │── verifica cert non revocato
  │                                │── verifica JTI non già usato (anti-replay)
  │                                │
  │◀─── JWT + DPoP binding ───────│  ← token legato alla chiave dell'agente
  │                                │
  │──── richiesta + DPoP proof ──▶│  ← ogni richiesta successiva include una prova
  │                                │     crittografica che il token è tuo
```

> **In Cullis:** guarda `app/auth/x509_verifier.py` per la verifica della catena, e `app/auth/dpop.py` per il DPoP binding.

### Least Privilege → capability-scoped sessions + binding

Un agente non ha "accesso a tutto il broker". Ha:

- Un **binding** che specifica quali capability può usare (es. `["supply", "quote"]`)
- Le **sessioni** sono scoped: quando apri una sessione, dichiari le capability che ti servono
- Se chiedi una capability che non hai nel binding → **deny**

```
Binding dell'agente "acme::buyer":
  org: acmebuyer
  role: buyer
  capabilities: ["purchase", "negotiate"]

Sessione richiesta:
  target: "widgets::supplier"
  capabilities: ["purchase"]         ← OK, è nel binding
  
Sessione richiesta:
  target: "widgets::supplier"  
  capabilities: ["admin"]            ← DENY, non è nel binding
```

> **In Cullis:** guarda `app/registry/binding_store.py` per i binding, e `app/broker/session_store.py` per lo scope check sulle sessioni.

### Assume Breach → E2E encryption + audit chain

Cullis assume che anche il broker stesso potrebbe essere compromesso:

- I **messaggi sono cifrati end-to-end** — il broker li inoltra ma non può leggerli (zero-knowledge forwarding)
- L'**audit log è una hash chain crittografica** — ogni entry contiene l'hash della precedente, come una blockchain. Se qualcuno altera un record, la catena si rompe e il tampering è rilevabile

```
Messaggio da Buyer a Supplier:
  ┌─────────────────────────────────────────┐
  │ Crittografato AES-256-GCM               │
  │ Chiave AES wrappata con RSA-OAEP        │
  │ Firmato RSA-PSS (inner + outer)         │
  │                                         │
  │ Il broker vede: blob opaco              │
  │ Solo il supplier può decifrare          │
  └─────────────────────────────────────────┘

Audit chain:
  Event #1: hash = SHA256("agent joined" + "0000")
  Event #2: hash = SHA256("session opened" + hash_evento_1)
  Event #3: hash = SHA256("message sent" + hash_evento_2)
  ...
  → Se qualcuno altera Event #2, hash_evento_3 non torna più
```

> **In Cullis:** guarda `cullis_sdk/crypto/e2e.py` per l'E2E, e `app/db/audit.py` per la hash chain.

### Default Deny → dual-org policy evaluation

In Cullis, **niente è permesso finché entrambe le organizzazioni non dicono "sì":**

```
Buyer (org A) vuole aprire sessione con Supplier (org B):

  Broker chiede a PDP di Org A: "Il tuo buyer può parlare con questo supplier?"
    → Org A: "allow"
    
  Broker chiede a PDP di Org B: "Vuoi che questo buyer parli col tuo supplier?"
    → Org B: "allow"
    
  Solo se ENTRAMBI dicono allow → sessione creata
  Se anche UNO dice deny (o non risponde) → sessione rifiutata
```

**Analogia:** È come un matrimonio — servono entrambi i "sì". Un "no" da chiunque blocca tutto.

> **In Cullis:** guarda `app/policy/engine.py` per la dual evaluation, e `enterprise-kit/pdp-template/` per il webhook PDP.

---

## NIST SP 800-207 — il documento di riferimento

Il National Institute of Standards and Technology (NIST) degli USA ha pubblicato nel 2020 il documento **SP 800-207** che definisce Zero Trust Architecture. È il riferimento che tutti citano.

### I punti chiave (quelli che ci servono)

1. **Tutte le sorgenti di dati e servizi sono considerate risorse** — non solo i server, anche le API, i dati, gli agenti
2. **Tutta la comunicazione è protetta** — non importa se è "interna" alla rete
3. **L'accesso è concesso per sessione** — non "ti autentifico una volta e sei dentro per sempre"
4. **L'accesso è determinato da policy dinamiche** — non solo "chi sei" ma anche "cosa stai facendo", "da dove", "quando"
5. **L'enterprise monitora e misura l'integrità** — audit continuo, non "controlliamo una volta l'anno"

Cullis implementa tutti e cinque:

| NIST SP 800-207 | Cullis |
|---|---|
| Tutto è una risorsa | Ogni agente, sessione, messaggio è protetto |
| Comunicazione sempre protetta | E2E encryption + TLS |
| Accesso per sessione | Sessioni scoped con TTL |
| Policy dinamiche | PDP webhook/OPA, dual-org |
| Monitoraggio continuo | Audit hash chain + OpenTelemetry |

---

## Riepilogo — cosa portarti a casa

- **Zero Trust** = non fidarti di nessuno, verifica sempre, dai solo il minimo
- I componenti chiave sono **PEP** (buttafuori) e **PDP** (chi decide)
- Per agenti AI inter-aziendali serve **Zero Trust federato** — ogni org mantiene la sovranità
- Cullis implementa tutti i principi: **x509+DPoP** (verify), **capability binding** (least privilege), **E2E+audit** (assume breach), **dual-org policy** (default deny)
- Il riferimento è **NIST SP 800-207**

---

*Prossimo capitolo: [02 — Federazione e Trust Domain](02-federazione-trust-domain.md) — come funziona la fiducia tra organizzazioni diverse*
