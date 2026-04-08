# Capitolo 02 — Federazione e Trust Domain

> *"Non devo fidarmi di te. Devo fidarmi del sistema che ti ha verificato."*

---

## Cos'è la federazione — spiegazione da bar

Hai il passaporto italiano. Arrivi in Germania. Il doganiere tedesco non ti conosce, non ha i tuoi dati, non ha il tuo codice fiscale. Ma accetta il tuo passaporto. Perché?

Perché la Germania **si fida dell'Italia come emittente di documenti**. Non si fida di te personalmente — si fida del *sistema* che ha verificato la tua identità e ti ha rilasciato il documento.

Questo è il cuore della **federazione**: organizzazioni indipendenti che si riconoscono reciprocamente, senza bisogno di un database centralizzato con tutti gli utenti del mondo.

---

## Centralizzazione vs Federazione

### Modello centralizzato

Un'unica autorità gestisce tutte le identità.

```
        ┌───────────────────┐
        │  Server Centrale  │
        │  (tutti gli user) │
        └───────┬───────────┘
          ┌─────┼─────┐
          ▼     ▼     ▼
        App A  App B  App C
```

**Esempio:** Google Workspace. Google ha tutti gli account, tutte le app si autenticano con Google. Funziona bene **dentro una singola organizzazione**.

**Problema:** Se due aziende diverse devono collaborare, chi gestisce il server centrale? Nessuna delle due vuole dare il controllo delle proprie identità all'altra.

### Modello federato

Ogni organizzazione gestisce le proprie identità. Un protocollo condiviso permette il riconoscimento reciproco.

```
┌──────────────┐                      ┌──────────────┐
│   Org A      │                      │   Org B      │
│  (suoi user) │◀── protocollo ──────▶│  (suoi user) │
│  (sue regole)│    condiviso         │  (sue regole)│
└──────────────┘                      └──────────────┘
```

**Esempio:** Il sistema dei passaporti. Ogni paese emette i propri. L'ICAO (organizzazione dell'aviazione civile) definisce lo standard. Nessun paese controlla gli altri.

**Vantaggio:** Ogni organizzazione mantiene **sovranità** sulle proprie identità e regole.

---

## Federazione nel mondo IT — gli standard per umani

Prima di Cullis, la federazione esisteva già per gli **utenti umani**:

### SAML (Security Assertion Markup Language)
- Inventato nel 2005 per il Single Sign-On enterprise
- L'utente si autentica sulla propria azienda (Identity Provider), riceve un "assertion" XML firmato, lo presenta all'applicazione esterna (Service Provider)
- **Analogia:** Il tuo datore di lavoro ti dà una lettera firmata. La presenti all'azienda partner. Loro verificano la firma del tuo datore.

### ADFS (Active Directory Federation Services)
- L'implementazione Microsoft di SAML/WS-Federation
- Permette agli utenti di un Active Directory di accedere a servizi di un'altra organizzazione
- **L'analogia che ha ispirato Cullis:** "ADFS ma per agenti AI" — stessa idea, ma per software che parlano tra loro autonomamente

### OIDC (OpenID Connect)
- Evoluzione moderna su base OAuth 2.0
- Più leggero di SAML (JSON invece di XML)
- Usato da Google, Microsoft, Okta per login federato

### Il gap: nessuno di questi funziona per agenti AI

Tutti questi protocolli presuppongono un **umano davanti a un browser** che:
1. Viene reindirizzato a una pagina di login
2. Inserisce username e password
3. Clicca "autorizza"

Un agente AI non ha un browser. Non clicca. Gira 24/7 in un container Docker. Serve un protocollo federato **machine-to-machine** — ed è qui che entra Cullis.

---

## Trust Domain — i confini della fiducia

### Cos'è un trust domain

Un trust domain è **l'insieme di entità che condividono una root of trust comune**.

**Analogia semplice:** Un trust domain è come una nazione. All'interno della nazione, tutti i documenti sono emessi dalla stessa autorità (lo Stato). Un passaporto italiano è valido in Italia non perché qualcuno lo verifica al bar — ma perché tutti accettano che lo Stato italiano è la radice della fiducia.

In crittografia, la "radice della fiducia" è una **Certificate Authority (CA) root** — il certificato di cui tutti si fidano perché è il punto di partenza.

### Confini del trust domain

```
Trust Domain "cullis.local"
┌─────────────────────────────────────────────────────┐
│                                                     │
│   Broker CA (root of trust)                         │
│       │                                             │
│       ├── Org A CA ──── Agent A1 cert               │
│       │              └── Agent A2 cert              │
│       │                                             │
│       ├── Org B CA ──── Agent B1 cert               │
│       │                                             │
│       └── Org C CA ──── Agent C1 cert               │
│                      └── Agent C2 cert              │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Tutti i certificati all'interno del trust domain risalgono alla stessa root: la **Broker CA**. Se ti fidi della Broker CA, ti fidi (indirettamente) di tutti i certificati firmati sotto di essa.

Ma — e questo è cruciale — **ogni organizzazione ha la propria CA intermedia**. L'Org A gestisce i suoi agenti, l'Org B i suoi. Il broker non genera le chiavi degli agenti (nel flusso enterprise) — verifica solo la catena.

### Perché i confini sono importanti

Se la CA di Org A viene compromessa:
- Gli agenti di Org A sono compromessi
- Gli agenti di Org B e C sono **al sicuro** — hanno CA diverse
- Il broker può **revocare la CA di Org A** senza toccare il resto

È lo stesso motivo per cui se un paese perde il controllo dei suoi passaporti, gli altri paesi possono smettere di accettarli — senza dover cambiare i propri.

---

## Come funziona la federazione in Cullis

Cullis implementa la federazione con due componenti distinti:

### Il Broker — il "notaio" neutrale

```
┌─────────────────────────────────────────────┐
│                CULLIS BROKER                │
│                                             │
│  Responsabilità:                            │
│  ✓ Verificare identità (x509 chain)        │
│  ✓ Instradare messaggi                     │
│  ✓ Consultare le policy di entrambe le org  │
│  ✓ Mantenere l'audit log                   │
│                                             │
│  NON fa:                                    │
│  ✗ NON legge i messaggi (E2E encrypted)    │
│  ✗ NON decide da solo (chiede ai PDP)      │
│  ✗ NON possiede le chiavi degli agenti     │
│                                             │
└─────────────────────────────────────────────┘
```

**Analogia:** Il broker è come un notaio. Verifica le identità delle parti, certifica che l'atto è avvenuto, ma non decide il contenuto dell'accordo. Se le parti vogliono tenere segreto il prezzo, il notaio non lo legge.

Il broker è il **control plane** — gestisce identità, routing, policy, audit. Non è il data plane.

### Il MCP Proxy — l'ambasciata di ogni organizzazione

```
┌─────────────────────────────────────────────┐
│           MCP PROXY (per ogni org)          │
│                                             │
│  Responsabilità:                            │
│  ✓ Generare certificati per i suoi agenti  │
│  ✓ Custodire le chiavi private (in Vault)  │
│  ✓ Autenticarsi al broker per conto degli  │
│    agenti (x509 + DPoP)                    │
│  ✓ Cifrare/decifrare messaggi E2E          │
│                                             │
│  Gli agenti interni usano solo un API key   │
│  — il proxy gestisce tutta la crypto        │
│                                             │
└─────────────────────────────────────────────┘
```

**Analogia:** Il proxy è come un'ambasciata. I cittadini (agenti) parlano con la propria ambasciata in modo semplice (API key). L'ambasciata si occupa del protocollo diplomatico (x509, DPoP, E2E) per comunicare con le ambasciate degli altri paesi tramite il notaio (broker).

### Il flusso completo

```
Agente A1 (Org A)          MCP Proxy A         Broker          MCP Proxy B         Agente B1 (Org B)
     │                         │                  │                  │                    │
     │── "parla con B1" ──────▶│                  │                  │                    │
     │   (API key)             │                  │                  │                    │
     │                         │── x509+DPoP ────▶│                  │                    │
     │                         │   + E2E payload  │                  │                    │
     │                         │                  │── policy A? ────▶│                    │
     │                         │                  │◀── allow ────────│                    │
     │                         │                  │── policy B? ─────────────────────────▶│?
     │                         │                  │◀── allow ─────────────────────────────│
     │                         │                  │                  │                    │
     │                         │                  │── forward E2E ──▶│                    │
     │                         │                  │  (blob opaco)    │── decifra ────────▶│
     │                         │                  │                  │   (API key)        │
     │                         │                  │                  │                    │
```

Nota: il broker **non può leggere il messaggio**. Lo inoltra come un blob cifrato. Solo Proxy B (che ha la chiave privata di B1) può decifrarlo.

---

## Sovranità organizzativa — il concetto chiave

La cosa più importante della federazione Cullis è che **ogni organizzazione mantiene il pieno controllo**:

### Ogni org controlla i propri agenti
- Org A crea, sospende, revoca i propri agenti
- Il broker non può creare agenti per conto di un'org
- Le chiavi private degli agenti restano nell'org (nel Vault del proxy)

### Ogni org decide le proprie policy
- Org A ha il suo PDP (Policy Decision Point) — il suo "cervello" che decide
- Nessuno può forzare Org A ad accettare una sessione che non vuole
- Le policy possono essere semplici ("allow all") o complesse (OPA con regole Rego)

### Ogni org vede solo il suo audit
- L'audit del broker mostra eventi di routing (chi ha parlato con chi)
- L'audit del proxy mostra i dettagli interni (quali tool sono stati chiamati)
- Un'org non può vedere l'audit interno di un'altra org

### Analogia finale

Pensa all'Unione Europea:
- Ogni paese ha i suoi cittadini, le sue leggi, la sua polizia (= ogni org ha i suoi agenti, policy, audit)
- L'UE fornisce il framework per il riconoscimento reciproco e la libera circolazione (= il broker fornisce identity verification e routing)
- L'UE non può obbligare un paese ad accettare qualcosa contro le sue leggi (= il broker non può bypassare il PDP di un'org)
- Se un paese esce dall'UE, l'UE non crolla (= se un'org lascia il network, le altre continuano)

---

## Federazione vs alternative — perché non usare altro?

| Approccio | Problema per agenti AI inter-org |
|---|---|
| **API key condivisa** | Un segreto rubato = accesso totale. Nessun audit. Nessuna policy granulare. |
| **OAuth centralizzato** | Chi gestisce l'authorization server? Nessuna delle due org vuole dipendere dall'altra. |
| **mTLS diretto** | Ogni org deve configurare trust manuale verso ogni altra org. Non scala. |
| **Blockchain** | Troppo lento, troppo complesso, non serve decentralizzazione totale per questo use case. |
| **Cullis (federato)** | Broker neutrale per identity + routing. Ogni org tiene le sue chiavi e le sue policy. Scala aggiungendo org senza riconfigurare le esistenti. |

---

## Riepilogo — cosa portarti a casa

- **Federazione** = organizzazioni indipendenti che si riconoscono tramite un protocollo condiviso
- Un **trust domain** è l'insieme di entità sotto la stessa root of trust (Broker CA)
- Il **broker** è il notaio neutrale: verifica, instrada, audita — ma non legge e non decide da solo
- Il **proxy** è l'ambasciata dell'org: gestisce la crypto per gli agenti interni
- Ogni org mantiene **sovranità**: sui propri agenti, policy, chiavi, audit
- Per gli umani esisteva già (SAML, ADFS, OIDC) — per agenti AI serve un protocollo **machine-to-machine** senza browser

---

*Prossimo capitolo: [03 — Threat Modeling per Agent-to-Agent](03-threat-modeling.md) — gli attacchi possibili e come li preveniamo*
