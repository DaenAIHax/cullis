# Capitolo 06 — PKI — Public Key Infrastructure

> *"Non basta avere una chiave. Devi dimostrare chi te l'ha data."*

---

## Il problema — spiegazione da bar

Hai una chiave pubblica. Qualcuno ti dice "questa è la chiave di Alice". Come sai che è vero? Qualcuno potrebbe averti dato la propria chiave fingendosi Alice.

La crittografia asimmetrica risolve il problema dello scambio chiavi, ma ne crea un altro: **come leghi un'identità a una chiave pubblica?**

**Analogia:** Un passaporto non è solo una foto e un nome. È un documento emesso da un'autorità (lo Stato), stampato con elementi di sicurezza, con una scadenza. Chiunque lo può verificare perché sa chi lo ha emesso e come controllarlo.

Un **certificato digitale** è il passaporto delle chiavi pubbliche. E la **PKI** è l'infrastruttura che li emette, li verifica, e li revoca.

---

## Cos'è un certificato x509

x509 è lo standard (dal 1988, aggiornato nel RFC 5280) che definisce il formato dei certificati digitali. Ogni volta che vai su un sito HTTPS, il tuo browser verifica un certificato x509.

### Anatomia di un certificato — versione semplificata

```
┌──────────────────────────────────────────────────────────┐
│                    CERTIFICATO x509 v3                    │
│                                                          │
│  Subject: CN=acme::buyer, O=acmebuyer                    │  ← Chi sei
│  Issuer:  CN=acmebuyer Intermediate CA, O=acmebuyer      │  ← Chi ti ha certificato
│                                                          │
│  Public Key: RSA 2048-bit                                │  ← La tua chiave pubblica
│  Serial Number: 0x3A7F...                                │  ← Numero unico
│                                                          │
│  Not Before: 2026-04-01 00:00:00 UTC                     │  ← Valido da
│  Not After:  2027-04-01 00:00:00 UTC                     │  ← Valido fino a
│                                                          │
│  Extensions:                                             │
│    Basic Constraints: CA=false                           │  ← Non è una CA
│    Subject Alternative Name:                             │
│      URI: spiffe://atn.local/acmebuyer/buyer             │  ← Identità SPIFFE
│    Subject Key Identifier: A4:3B:...                     │  ← Fingerprint
│                                                          │
│  Signature Algorithm: SHA-256 with RSA                   │
│  Signature: [firmato dalla CA di acmebuyer]              │  ← Prova che la CA l'ha emesso
└──────────────────────────────────────────────────────────┘
```

**Analogia campo per campo:**

| Campo cert | Equivalente passaporto |
|---|---|
| Subject (CN, O) | Nome e cognome, nazionalità |
| Issuer | Autorità che l'ha emesso (es. "Repubblica Italiana") |
| Public Key | La tua foto (ti identifica) |
| Serial Number | Numero del passaporto |
| Not Before / Not After | Data emissione / scadenza |
| Basic Constraints CA=false | "Non è un ufficio passaporti, è un cittadino" |
| SAN (SPIFFE URI) | Codice fiscale (identità univoca alternativa) |
| Signature | Timbro e ologramma dell'autorità |

---

## La catena di fiducia (Certificate Chain)

Un certificato da solo non basta. Devi poter risalire a un'autorità di cui ti fidi. Ecco la catena:

```
Livello 0 — ROOT CA (Broker CA)
  ┌────────────────────────────────────────────────┐
  │  Subject: "Agent Trust Network Root CA"         │
  │  Issuer:  "Agent Trust Network Root CA"         │  ← si auto-firma (self-signed)
  │  Key: RSA 4096                                  │
  │  Validity: 10 anni                              │
  │  BasicConstraints: CA=true, pathLength=1        │  ← può firmare CA intermedie
  │                                                 │
  │  Questa è la RADICE della fiducia.              │
  │  Tutti devono averne una copia e fidarsi.       │
  └────────────────────────────────────────────────┘
                        │
                        │ firma
                        ▼
Livello 1 — ORG CA (Intermediate CA)
  ┌────────────────────────────────────────────────┐
  │  Subject: "acmebuyer Intermediate CA"           │
  │  Issuer:  "Agent Trust Network Root CA"         │  ← firmato dalla Root
  │  Key: RSA 4096                                  │
  │  Validity: 5 anni                               │
  │  BasicConstraints: CA=true, pathLength=0        │  ← può firmare cert end-entity
  │                                                 │     (ma NON altre CA)
  │  Ogni organizzazione ha la propria.             │
  └────────────────────────────────────────────────┘
                        │
                        │ firma
                        ▼
Livello 2 — AGENT CERT (End Entity)
  ┌────────────────────────────────────────────────┐
  │  Subject: CN=acme::buyer, O=acmebuyer           │
  │  Issuer:  "acmebuyer Intermediate CA"           │  ← firmato dalla Org CA
  │  Key: RSA 2048                                  │
  │  Validity: 1 anno                               │
  │  BasicConstraints: CA=false                     │  ← NON può firmare niente
  │  SAN: spiffe://atn.local/acmebuyer/buyer        │
  │                                                 │
  │  Questo è il "passaporto" dell'agente.          │
  └────────────────────────────────────────────────┘
```

### Come si verifica la catena

Quando un agente si presenta al broker, il broker fa questa verifica:

```
1. Estrai il cert dell'agente dal header x5c del JWT
2. Leggi il campo Issuer → "acmebuyer Intermediate CA"
3. Cerca nel database la CA registrata per l'org "acmebuyer"
4. Verifica che la CA sia attiva e abbia BasicConstraints CA=true
5. Verifica la FIRMA del cert agente con la chiave pubblica della CA
   → Se la firma è valida: il cert è stato davvero emesso da quella CA
6. Verifica che il cert non sia scaduto (Not Before ≤ now ≤ Not After)
7. Verifica che il cert non sia stato revocato (tabella revoked_certs)
8. Verifica il SPIFFE SAN (se presente o richiesto)
9. Estrai la chiave pubblica dal cert → usala per verificare la firma del JWT

Se QUALSIASI step fallisce → 401 Unauthorized
```

> **In Cullis:** tutta questa logica è in `app/auth/x509_verifier.py`, funzione `verify_client_assertion()` — 12 step, dalla riga 38 alla 254.

### pathLength — il "quanti livelli sotto di me"

Nota il campo `pathLength` nei BasicConstraints:

```
Root CA:    pathLength=1  → può firmare 1 livello di CA sotto (le Org CA)
Org CA:     pathLength=0  → può firmare 0 livelli di CA sotto (solo end-entity)
Agent cert: CA=false      → non può firmare niente
```

Questo impedisce che un agente crei una propria "sub-CA" e inizi a emettere certificati per conto suo. La gerarchia è fissa a 3 livelli.

---

## PKI a 3 livelli di Cullis — nel codice

### Livello 0: Broker CA (`generate_certs.py:86-118`)

```python
# RSA 4096, self-signed, validità 10 anni
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

cert = (
    x509.CertificateBuilder()
    .subject_name(name)                            # "Agent Trust Network Root CA"
    .issuer_name(name)                             # stesso → self-signed
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOW)
    .not_valid_after(NOW + timedelta(days=365*10))  # 10 anni
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=1),  # CA=true, può firmare 1 livello
        critical=True,
    )
    .sign(key, hashes.SHA256())                    # si firma da sola
)
```

Produce:
- `certs/broker-ca.pem` — certificato pubblico (dato a tutti)
- `certs/broker-ca-key.pem` — chiave privata (ULTRA-SEGRETA, solo il broker)

### Livello 1: Org CA (`generate_certs.py:121-160`)

```python
# RSA 2048, firmato dalla Broker CA, validità 5 anni
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)                         # "acmebuyer Intermediate CA"
    .issuer_name(broker_ca_cert.subject)            # issuer = Broker CA
    .public_key(key.public_key())
    .not_valid_after(NOW + timedelta(days=365*5))   # 5 anni
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=0),  # CA=true, ma NON può creare sub-CA
        critical=True,
    )
    .sign(broker_ca_key, hashes.SHA256())           # firmato con la chiave della Broker CA
)
```

> **Nel flusso enterprise (MCP Proxy):** l'org genera la propria CA localmente e carica solo il certificato pubblico sul broker. La chiave privata della CA **non lascia mai l'organizzazione**.

### Livello 2: Agent Cert (`generate_certs.py:163-213`)

```python
# RSA 2048, firmato dalla Org CA, validità 1 anno, con SPIFFE SAN
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

spiffe_id = f"spiffe://atn.local/{org_id}/{agent_name}"

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)                         # CN=acme::buyer, O=acmebuyer
    .issuer_name(org_ca_cert.subject)               # issuer = Org CA
    .public_key(key.public_key())
    .not_valid_after(NOW + timedelta(days=365))     # 1 anno
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),  # NON è una CA
        critical=True,
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(spiffe_id),  # SPIFFE identity
        ]),
        critical=False,
    )
    .sign(org_ca_key, hashes.SHA256())              # firmato con la chiave della Org CA
)
```

---

## La verifica — 12 step nel codice

`app/auth/x509_verifier.py` — funzione `verify_client_assertion()`. Ecco cosa fa, passo per passo:

### Step 1-2: Estrai il certificato dal JWT

```python
header = jwt.get_unverified_header(assertion)   # leggi header SENZA verificare
x5c = header.get("x5c")                         # array di cert in base64(DER)

cert_der = base64.b64decode(x5c[0])             # primo cert = agent cert
agent_cert = x509.load_der_x509_certificate(cert_der)
cert_thumbprint = hashlib.sha256(cert_der).hexdigest()  # fingerprint SHA-256
```

**x5c** è un header standard JWT (RFC 7515 §4.1.6). Contiene la catena di certificati codificati in base64 DER. Il primo è il cert dell'agente.

### Step 3: Estrai identità dal certificato

```python
agent_id = agent_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
org_id = agent_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
```

Il Common Name (CN) contiene l'agent_id (es. `acme::buyer`).
L'Organization Name (O) contiene l'org_id (es. `acmebuyer`).

### Step 4: Carica la CA dell'org dal database

```python
org = await get_org_by_id(db, org_id)
# Verifica: org esiste, status == "active", ca_certificate presente
org_ca = x509.load_pem_x509_certificate(org.ca_certificate.encode())
# Verifica: BasicConstraints CA=true
```

### Step 5: Verifica la catena crittografica

```python
ca_pub = org_ca.public_key()
ca_pub.verify(
    agent_cert.signature,                    # la firma nel cert
    agent_cert.tbs_certificate_bytes,        # i dati firmati (to-be-signed)
    padding.PKCS1v15(),                      # padding per x509
    agent_cert.signature_hash_algorithm,     # SHA-256
)
```

Questo è il cuore della verifica: **la firma nel certificato dell'agente è stata prodotta dalla chiave privata della CA dell'org?** Se sì, il cert è autentico.

### Step 5b-5c: Controlli aggiuntivi

```python
# Dimensione minima chiave RSA: 2048 bit
if agent_pub_key.key_size < 2048:
    raise HTTPException(401, "RSA key too small")

# Se c'è Extended Key Usage, deve includere clientAuth
if ExtendedKeyUsageOID.CLIENT_AUTH not in eku_ext.value:
    raise HTTPException(401, "EKU missing clientAuth")
```

### Step 6-7: Validità temporale e revoca

```python
# Il cert non deve essere scaduto
if now > not_after or now < not_before:
    raise HTTPException(401, "Certificate expired")

# Il cert non deve essere nella lista di revoca
await check_cert_not_revoked(db, serial_hex)
```

### Step 8-10: Verifica firma JWT e claims

```python
# Verifica la firma del JWT con la chiave pubblica estratta dal cert
payload = jwt.decode(assertion, pub_key_pem, algorithms=["RS256", "ES256"])

# sub e iss devono corrispondere all'agent_id o al SPIFFE URI
if sub not in (agent_id, expected_spiffe):
    raise HTTPException(401, "sub mismatch")
```

### Step 11: Verifica SPIFFE SAN

```python
san_ext = agent_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]

if expected_spiffe not in spiffe_sans:
    raise HTTPException(401, "SPIFFE SAN mismatch")
```

### Step 12: JTI blacklist (anti-replay)

```python
jti = payload.get("jti")                 # JWT ID unico
await check_and_consume_jti(db, jti, expires_at)  # segna come usato
# Se il jti è già stato usato → 401 (replay attack rilevato)
```

---

## Certificate Thumbprint Pinning

Il thumbprint pinning è una difesa aggiuntiva contro il **rogue CA swap attack**:

```
Attacco senza pinning:
1. Org A registra la sua CA legittima
2. Un attaccante compromette il flusso di registrazione
3. L'attaccante sostituisce la CA con la propria
4. Ora può emettere cert che il broker accetta come "org A"

Con pinning:
1. Org A registra la sua CA legittima
2. Il broker calcola SHA-256(cert_der) = thumbprint
3. Il thumbprint viene salvato nel DB
4. Anche se qualcuno sostituisce la CA, il thumbprint non corrisponde
5. Il broker rifiuta il cert
```

> **In Cullis:** `cert_thumbprint = hashlib.sha256(cert_der).hexdigest()` — calcolato a ogni login e confrontato con quello registrato.

---

## Validità e rotazione — il ciclo di vita

```
Timeline delle validità:

Broker CA:  ├──────────────────────────────────────────────┤  10 anni
Org CA:     ├──────────────────────────┤                       5 anni
Agent cert: ├───────────┤                                      1 anno

Anno:    2026  2027  2028  2029  2030  2031  2032  2033  2034  2035  2036
```

Perché validità diverse?

| Livello | Durata | Motivo |
|---|---|---|
| Root CA | 10 anni | Cambiare la root è doloroso (tutti devono aggiornarsi). Lunga durata. |
| Org CA | 5 anni | Compromesso tra sicurezza e praticità. L'org deve poter rotare. |
| Agent cert | 1 anno | Gli agenti cambiano spesso. Cert corti = meno rischio se rubato. |

### Rotazione

Quando un cert scade o viene compromesso:
1. **Agent cert:** l'org emette un nuovo cert con la stessa CA → l'agente si ri-autentica
2. **Org CA:** l'org genera una nuova CA → carica il nuovo cert sul broker → ri-emette tutti i cert agenti
3. **Broker CA:** scenario catastrofico → tutte le org devono ri-registrarsi

---

## Due flussi: dev vs enterprise

### Flusso dev (generate_certs.py + join.py)

```
python generate_certs.py
  → Genera broker CA in certs/

python join.py --org-id acmebuyer --agents acme::buyer
  → Genera org CA (firmata dalla broker CA)
  → Genera agent cert (firmato dalla org CA)
  → Registra tutto sul broker via API
  → Salva file .env con le credenziali
```

Tutto in locale, tutto su file. Comodo per lo sviluppo.

### Flusso enterprise (MCP Proxy)

```
1. Admin broker genera invite token dal dashboard
2. Org admin apre il Proxy dashboard → inserisce invite token
3. Proxy genera la Org CA LOCALMENTE (RSA-4096, 10 anni)
4. Proxy invia solo il CERTIFICATO PUBBLICO al broker (mai la chiave privata!)
5. Broker admin approva l'org
6. Org admin crea agenti dal Proxy dashboard
7. Proxy genera agent cert LOCALMENTE, li salva in Vault
8. Agenti ricevono un API key locale — il proxy gestisce x509/DPoP

La chiave privata della CA e degli agenti NON ESCE MAI dall'organizzazione.
```

> **Questo è il flusso BYOCA (Bring Your Own CA)** — il pattern che Cullis promuove per production.

---

## Riepilogo — cosa portarti a casa

- Un **certificato x509** lega un'identità a una chiave pubblica, firmato da un'autorità
- La **catena di fiducia** ha 3 livelli in Cullis: Root CA (broker) → Org CA → Agent cert
- **pathLength** controlla quanti livelli sotto di sé una CA può firmare
- La **verifica** è un processo a 12 step: dall'estrazione del cert alla blacklist JTI
- Il **thumbprint pinning** (SHA-256) protegge contro la sostituzione della CA
- Validità crescente: 1 anno (agent) → 5 anni (org CA) → 10 anni (root CA)
- Nel flusso enterprise, la **chiave privata non lascia mai l'organizzazione**
- Tutto il codice di generazione è in `generate_certs.py`, la verifica in `app/auth/x509_verifier.py`

---

*Prossimo capitolo: [07 — SPIFFE — Secure Production Identity Framework](07-spiffe.md) — identità workload in ambienti distribuiti*
