# Capitolo 32 — TypeScript SDK

> *"Stessa lingua, accento diverso: Python e TypeScript dicono le stesse cose, ma con sintassi diversa."*

---

## Perche' un SDK TypeScript — spiegazione da bar

Immagina un ristorante che serve solo piatti italiani. Va benissimo per chi ama la cucina italiana, ma se arriva un cliente che vuole sushi? Lo mandi via?

Il Python SDK e' il menu' italiano. Ma il mondo backend non parla solo Python — tantissimi servizi, microservizi, edge function e applicazioni sono scritti in **Node.js/TypeScript**. L'SDK TypeScript (`@agent-trust/sdk`) permette a questi servizi di parlare con il broker Cullis senza dover riscrivere tutto in Python.

**Stesse API, stessa crittografia, stessa sicurezza — linguaggio diverso.**

---

## Struttura del progetto: sdk-ts/

```
sdk-ts/
├── package.json          ← metadata npm, dipendenze
├── tsconfig.json         ← configurazione TypeScript
├── src/
│   ├── index.ts          ← re-export pubblici
│   ├── client.ts         ← BrokerClient (equivalente di CullisClient)
│   ├── auth.ts           ← x509 assertion + DPoP proof
│   ├── crypto.ts         ← firma messaggi + E2E encrypt/decrypt
│   ├── types.ts          ← interfacce TypeScript
│   └── utils.ts          ← helper base64url, canonical JSON
└── examples/             ← esempi d'uso
```

**Analogia:** Se il Python SDK e' una Fiat Panda (pratica, essenziale), il TypeScript SDK e' una Toyota Yaris — stessa categoria, stessa funzione, diverso costruttore. Entrambe ti portano a destinazione.

---

## BrokerClient: il gemello di CullisClient

In Python hai `CullisClient`. In TypeScript hai `BrokerClient`. Fanno esattamente la stessa cosa.

```
┌────────────────────────────────────────────────────┐
│                   BrokerClient                     │
│                                                    │
│  ┌──────────┐  ┌───────────┐  ┌────────────────┐   │
│  │   Auth   │  │ Sessions  │  │   Messaging    │   │
│  │ login()  │  │ openSess  │  │ send() poll()  │   │
│  │ DPoP     │  │ acceptS   │  │ decryptPayload │   │
│  │ x509     │  │ closeS    │  │ E2E encrypt    │   │
│  └────┬─────┘  └─────┬─────┘  └───────┬────────┘   │
│       │              │                │             │
│  ┌────▼──────────────▼────────────────▼──────────┐  │
│  │           authedRequest()                     │  │
│  │   Authorization: DPoP + nonce retry           │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │                              │
│  ┌───────────────────▼───────────────────────────┐  │
│  │            Node.js fetch()                    │  │
│  │   HTTP, TLS, AbortSignal timeout              │  │
│  └───────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

### Creazione e login

```typescript
import { BrokerClient } from "@agent-trust/sdk";

const client = new BrokerClient({
  baseUrl: "https://broker.cullis.tech",
  verifyTls: true,        // default: true
  timeoutMs: 10_000,      // default: 10s
});

// Login — legge cert e key da file, autentica con x509 + DPoP
await client.login(
  "acme::buyer",          // agentId
  "acme",                 // orgId
  "certs/buyer.pem",      // certPath
  "certs/buyer-key.pem",  // keyPath
);
```

Sotto il cofano, `login()` fa esattamente gli stessi passi del Python SDK:

1. Legge cert e key da file (`readFile`)
2. Costruisce `client_assertion` JWT con x5c header
3. Genera coppia EC P-256 efimera per DPoP
4. Manda POST `/v1/auth/token` con assertion + DPoP proof
5. Gestisce retry su `use_dpop_nonce`
6. Salva `access_token`

> **In Cullis:** guarda `sdk-ts/src/client.ts` metodo `login()` e `sdk-ts/src/auth.ts` per `createClientAssertion()` e `createDPoPProof()`.

---

## Discovery e Sessioni

### Discover

```typescript
// Cerca agenti per capability
const agents = await client.discover(["gpu.supply"]);

for (const agent of agents) {
  console.log(`${agent.display_name} (${agent.agent_id})`);
  console.log(`  Capabilities: ${agent.capabilities.join(", ")}`);
}
```

### Sessioni

```typescript
// Apri sessione
const sessionId = await client.openSession(
  "chipfactory::sales",    // targetAgentId
  "chipfactory",           // targetOrgId
  ["order.write"],         // capabilities
);

// Accetta sessione pendente
await client.acceptSession(sessionId);

// Lista sessioni (opzionale filtro per stato)
const sessions = await client.listSessions("active");

// Chiudi sessione
await client.closeSession(sessionId);
```

**Nota la differenza di stile:** Python usa `snake_case` (`open_session`), TypeScript usa `camelCase` (`openSession`). Le API sono identiche nel contenuto, diverse solo nella convenzione di naming.

---

## Messaggi E2E crittografati

### Invio

```typescript
await client.send(
  sessionId,                // sessione attiva
  "acme::buyer",           // sender
  { type: "order", item: "A100", qty: 500 },  // payload
  "chipfactory::sales",    // recipient
);
```

Il flusso interno e' identico al Python:

```
send()
  ├─ 1. signMessage()         ← inner sig (RSA-PSS-SHA256)
  ├─ 2. getAgentPublicKey()   ← fetch + cache (5min TTL)
  ├─ 3. encryptForAgent()     ← AES-256-GCM + RSA-OAEP
  ├─ 4. signMessage()         ← outer sig sul ciphertext
  ├─ 5. build envelope        ← session_id, nonce, timestamp, client_seq
  └─ 6. authedRequest(POST)   ← con retry (3 tentativi)
```

### Ricezione e decrittazione

```typescript
// Poll per nuovi messaggi — decrittazione automatica
const messages = await client.poll(sessionId, -1);

for (const msg of messages) {
  console.log(`[${msg.sender_agent_id}]: ${JSON.stringify(msg.payload)}`);
}
```

`poll()` chiama internamente `decryptPayload()` su ogni messaggio — se il payload contiene un campo `ciphertext`, viene decrittato automaticamente con la chiave privata dell'agente.

---

## Crittografia: interoperabilita' Python-TypeScript

Il punto critico di avere due SDK in linguaggi diversi e' l'**interoperabilita'**: un messaggio crittografato dal Python SDK deve essere decrittabile dal TypeScript SDK e viceversa.

```
Python Agent                          TypeScript Agent
  │                                        │
  │ encrypt_for_agent()                    │
  │ (AES-256-GCM + RSA-OAEP)              │
  │ canonical JSON: sort_keys, no spaces   │
  │                                        │
  │──── ciphertext blob ──────────────────▶│
  │                                        │
  │                          decryptFromAgent()
  │                          (stessa AES-GCM + RSA-OAEP)
  │                          canonicalJson() identica
```

Per garantire l'interoperabilita', entrambi gli SDK usano **lo stesso formato canonico** per le stringhe da firmare:

```
Python:  json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
TS:      canonicalJson(payload)  ← reimplementa la stessa logica
```

E lo stesso schema per l'E2E:

```
Schema identico:
  - plaintext = JSON({payload, inner_signature})
  - AES-256-GCM con AAD = "{session_id}|{sender}|{client_seq}"
  - AES key wrappata con RSA-OAEP-SHA256
  - GCM auth tag appendato al ciphertext (16 bytes in coda)
  - Tutto codificato in base64url
```

**Analogia:** E' come due persone che parlano lingue diverse ma usano lo stesso codice Morse. Il canale di comunicazione (la crittografia) e' identico — solo il "linguaggio di superficie" cambia.

> **In Cullis:** guarda `sdk-ts/src/crypto.ts` per `signMessage()`, `encryptForAgent()` e `decryptFromAgent()`.

---

## RFQ e Transaction Token

### Request For Quote

```typescript
// Broadcast RFQ
const rfq = await client.createRfq(
  ["gpu.supply"],                    // capability filter
  { item: "A100", quantity: 1000 },  // payload
  30,                                // timeout in secondi
);

// Rispondi a un RFQ
await client.respondToRfq(rfq.rfq_id, {
  price_per_unit: 850,
  delivery_days: 14,
});

// Controlla lo stato
const result = await client.getRfq(rfq.rfq_id);
for (const quote of result.quotes) {
  console.log(`${quote.agent_id}: $${quote.payload.price_per_unit}`);
}
```

### Transaction Token

```typescript
const txn = await client.requestTransactionToken(
  "order.confirm",         // tipo transazione
  "sha256-del-payload",    // hash del payload
  {
    sessionId: sessionId,
    counterpartyAgentId: "chipfactory::sales",
  },
);
// txn.transaction_token: JWT monouso per questa operazione
```

---

## Tipi TypeScript: type safety completa

A differenza del Python SDK che usa dataclass, il TypeScript SDK usa **interfacce** — type safety a compile time senza overhead a runtime.

```typescript
// Esempio: SessionResponse
interface SessionResponse {
  session_id: string;
  status: "pending" | "active" | "closed" | "denied";
  initiator_agent_id: string;
  target_agent_id: string;
  created_at: string;
  expires_at?: string | null;
}

// Esempio: InboxMessage
interface InboxMessage {
  seq: number;
  sender_agent_id: string;
  payload: Record<string, unknown>;
  nonce: string;
  timestamp: string;
  signature?: string | null;
  client_seq?: number | null;
}

// Esempio: CipherBlob
interface CipherBlob {
  ciphertext: string;
  encrypted_key: string;
  iv: string;
}
```

I tipi principali sono:

| Interfaccia | Python equivalente | Uso |
|------------|-------------------|-----|
| `AgentResponse` | `AgentInfo` | Risultato di `discover()` |
| `SessionResponse` | `SessionInfo` | Risultato di `listSessions()` |
| `InboxMessage` | `InboxMessage` | Risultato di `poll()` |
| `RfqResponse` | `RfqResult` | Risultato di `createRfq()` |
| `CipherBlob` | `dict` (non tipato) | Blob crittografato E2E |
| `TokenPayload` | (non esposto) | Payload del JWT broker |
| `BrokerClientOptions` | (kwargs) | Opzioni del costruttore |

> **In Cullis:** guarda `sdk-ts/src/types.ts` per tutte le interfacce.

---

## Dipendenze e requisiti

```json
{
  "name": "@agent-trust/sdk",
  "version": "0.1.0",
  "engines": { "node": ">=18.0.0" },
  "dependencies": {
    "jose": "^5.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "@types/node": "^20.0.0"
  }
}
```

**Una sola dipendenza runtime: `jose`** (per JWT encode/decode/verify). Tutto il resto usa le API native di Node.js:

- `node:crypto` — RSA, EC, AES-GCM, OAEP, hash, firma
- `node:fs/promises` — lettura file cert/key
- `fetch()` — HTTP client (nativo da Node 18)

**Analogia:** Se il Python SDK ha 4 utensili nella cassetta (httpx, cryptography, PyJWT, websockets), il TypeScript SDK ne ha 1 (jose) — il resto e' gia' integrato nel motore di Node.js.

---

## Differenze chiave Python vs TypeScript

```
┌───────────────────┬─────────────────────┬─────────────────────┐
│    Aspetto        │     Python SDK      │   TypeScript SDK    │
├───────────────────┼─────────────────────┼─────────────────────┤
│ Classe principale │ CullisClient        │ BrokerClient        │
│ API style         │ snake_case          │ camelCase           │
│ Sincrono/Async    │ Sincrono (httpx)    │ Async (await)       │
│ HTTP client       │ httpx.Client        │ fetch() nativo      │
│ JWT library       │ PyJWT               │ jose                │
│ Crypto library    │ cryptography        │ node:crypto         │
│ Tipi dati         │ dataclass           │ interface           │
│ EC key support    │ RSA + EC            │ Solo RSA*           │
│ WebSocket         │ Si (sincrono)       │ Non ancora          │
│ MCP server        │ Si (mcp_server.py)  │ Non ancora          │
│ login_from_pem    │ Si                  │ Non ancora          │
│ Dipendenze        │ 4                   │ 1                   │
│ Node minimo       │ N/A                 │ >= 18               │
│ Python minimo     │ >= 3.10             │ N/A                 │
└───────────────────┴─────────────────────┴─────────────────────┘

* Il TypeScript SDK attualmente supporta solo RSA per E2E encryption.
  Il supporto EC (ECDH + HKDF) e' presente nel Python SDK.
```

### Differenza principale: sincrono vs asincrono

Il Python SDK e' **sincrono** — ogni chiamata blocca finche' non riceve risposta:

```python
# Python — sincrono
session_id = client.open_session(target, org, caps)  # blocca qui
client.send(session_id, sender, payload, recipient)  # blocca qui
```

Il TypeScript SDK e' **completamente asincrono** con `async/await`:

```typescript
// TypeScript — asincrono
const sessionId = await client.openSession(target, org, caps);  // non blocca
await client.send(sessionId, sender, payload, recipient);       // non blocca
```

**Analogia:** Python e' come ordinare al bancone — aspetti che ti diano il caffe' e poi ti siedi. TypeScript e' come ordinare al tavolo — fai l'ordine, e nel frattempo puoi fare altro finche' non arriva.

---

## Esempio completo: agente Node.js

```typescript
import { BrokerClient } from "@agent-trust/sdk";

async function main() {
  const client = new BrokerClient({
    baseUrl: "https://broker.cullis.tech",
  });

  // 1. Login
  await client.login(
    "acme::buyer", "acme",
    "certs/buyer.pem", "certs/buyer-key.pem",
  );

  // 2. Discover
  const suppliers = await client.discover(["gpu.supply"]);
  console.log(`Found ${suppliers.length} suppliers`);

  // 3. Open session
  const target = suppliers[0];
  const sid = await client.openSession(
    target.agent_id, target.org_id, ["gpu.supply"],
  );

  // 4. Send E2E encrypted order
  await client.send(sid, "acme::buyer",
    { type: "order", item: "A100", qty: 500 },
    target.agent_id,
  );

  // 5. Poll for response
  const messages = await client.poll(sid);
  for (const msg of messages) {
    console.log(`${msg.sender_agent_id}: ${JSON.stringify(msg.payload)}`);
  }

  // 6. Close
  await client.closeSession(sid);
}

main().catch(console.error);
```

---

## Riepilogo — cosa portarti a casa

- **BrokerClient** e' l'equivalente TypeScript di CullisClient — stesse API, stile camelCase
- **Interoperabilita' garantita**: stesso formato canonico, stessa crittografia, agenti Python e TypeScript comunicano senza problemi
- **1 sola dipendenza** runtime (`jose`) — il resto e' Node.js nativo (`node:crypto`, `fetch`)
- **Completamente asincrono** con `async/await` — ideale per microservizi e edge function
- **Type safety** con interfacce TypeScript — errori a compile time, non a runtime
- E2E encryption **attualmente solo RSA** (ECDH in arrivo) — il Python SDK supporta gia' entrambi
- **Node.js >= 18** richiesto (per `fetch()` nativo e `AbortSignal.timeout`)

---

*Prossimo capitolo: [33 — MCP Proxy — Enterprise Gateway](33-mcp-proxy.md) — il gateway che semplifica l'adozione per le organizzazioni*
