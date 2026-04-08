# Capitolo 14 — End-to-End Encryption

> *"Il postino porta la lettera, ma solo tu hai la chiave per aprirla."*

---

## Perche serve l'E2E — spiegazione da bar

Immagina di mandare un pacco tramite corriere. Il corriere sa da dove parte e dove arriva, ma il pacco e sigillato: non puo leggere il contenuto. Se il corriere viene rapito (o e corrotto), il contenuto resta al sicuro.

In Cullis, il **broker** e il corriere. Trasporta i messaggi da un agente all'altro, ma **non puo leggerne il contenuto**. Anche se qualcuno buca il broker, i messaggi restano cifrati.

```
Senza E2E:
  Agente A  ──[testo in chiaro]──►  Broker  ──[testo in chiaro]──►  Agente B
                                       │
                                  LEGGE TUTTO!

Con E2E:
  Agente A  ──[blob cifrato]──►  Broker  ──[blob cifrato]──►  Agente B
                                    │
                              vede solo spazzatura
```

Questo e fondamentale perche in un sistema **federato** come Cullis, il broker potrebbe essere gestito da un'organizzazione diversa da quella degli agenti. Zero trust = il broker non deve leggere nulla.

---

## Il problema: perche non cifrare tutto con RSA?

RSA e potente, ma **lento** e ha un **limite di dimensione**. Con una chiave RSA-2048, puoi cifrare al massimo ~190 byte di dati. Un messaggio tra agenti puo essere molto piu grande.

La soluzione e la **crittografia ibrida**: usi un algoritmo veloce (AES) per i dati, e RSA solo per proteggere la chiave AES.

```
Analogia — la cassaforte e la chiave:

  1. Generi una chiave AES casuale (la "chiave della cassaforte")
  2. Metti il messaggio nella cassaforte AES (veloce, nessun limite di dimensione)
  3. Metti la chiave della cassaforte in una busta RSA (cifri la chiave con la pubkey del destinatario)
  4. Mandi tutto: cassaforte + busta

  Il destinatario:
  1. Apre la busta RSA con la sua chiave privata → ottiene la chiave AES
  2. Apre la cassaforte AES → legge il messaggio
```

---

## Schema crittografico completo

Cullis usa uno schema a **doppia firma + cifratura ibrida**:

```
Mittente (Agente A):
  1. FIRMA INTERNA (non-repudiation):
     inner_sig = RSA-PSS-SHA256( plaintext )        ← "io ho scritto questo"

  2. CIFRATURA (confidenzialita):
     aes_key = random(32 byte)                       ← chiave AES usa-e-getta
     iv      = random(12 byte)                       ← initialization vector
     blob    = AES-256-GCM( {payload, inner_sig} )   ← cifra payload + firma
     wrapped = RSA-OAEP( aes_key )                   ← cifra la chiave AES

  3. FIRMA ESTERNA (integrita trasporto):
     outer_sig = RSA-PSS-SHA256( blob )              ← "il blob non e stato alterato"

Broker:
  4. VERIFICA FIRMA ESTERNA → il blob e integro
  5. INOLTRA il blob opaco (non puo decifrare)

Destinatario (Agente B):
  6. DECIFRA: RSA-OAEP( wrapped ) → aes_key
  7. DECIFRA: AES-256-GCM( blob ) → {payload, inner_sig}
  8. VERIFICA FIRMA INTERNA → il mittente ha davvero scritto quel testo
```

Perche **due firme**?

| Firma | Cosa protegge | Chi la verifica | Scopo |
|-------|---------------|-----------------|-------|
| **Interna** (inner) | Il plaintext originale | Solo il destinatario | **Non-repudiation**: puoi dimostrare che A ha scritto quel messaggio |
| **Esterna** (outer) | Il blob cifrato | Il broker | **Integrita trasporto**: nessuno ha manomesso il pacchetto in transito |

---

## Generazione chiave AES e IV

Ogni messaggio usa una chiave AES e un IV **unici**, generati con randomness crittografica:

```python
# cullis_sdk/crypto/e2e.py — righe 79-80

aes_key = os.urandom(32)   # 256 bit di entropia per AES-256
iv = os.urandom(12)        # 96 bit per GCM (dimensione raccomandata NIST)
```

`os.urandom()` usa il CSPRNG del sistema operativo (`/dev/urandom` su Linux, `CryptGenRandom` su Windows). Non e `random.random()` — quello e prevedibile!

```
Perche chiave nuova ogni messaggio?

  Se riusi la stessa chiave AES per piu messaggi, un attaccante che
  decifra un messaggio puo leggere anche gli altri. Con chiave
  usa-e-getta, ogni messaggio e indipendente.

  Messaggio 1: aes_key_1 = random(32)  →  cifrato con key_1
  Messaggio 2: aes_key_2 = random(32)  →  cifrato con key_2
  Messaggio 3: aes_key_3 = random(32)  →  cifrato con key_3

  Bucare key_1 non aiuta con key_2 o key_3.
```

---

## AES-256-GCM e Additional Authenticated Data (AAD)

AES-256-GCM e un cifrario **autenticato**: non solo cifra i dati, ma genera anche un **tag** che verifica che nulla sia stato modificato. Se qualcuno altera anche un solo bit del ciphertext, la decifratura fallisce.

Ma c'e un trucco in piu: l'**AAD** (Additional Authenticated Data). L'AAD non viene cifrato, ma viene **incluso nel calcolo del tag**. Se cambi l'AAD, il tag non torna e la decifratura fallisce.

```python
# cullis_sdk/crypto/e2e.py — righe 82-86

if client_seq is not None:
    aad = f"{session_id}|{sender_agent_id}|{client_seq}".encode()
else:
    aad = f"{session_id}|{sender_agent_id}".encode()
ciphertext = aesgcm.encrypt(iv, plaintext, aad)
```

Cosa include l'AAD e perche:

```
AAD = "sess-abc-123|acme::buyer|42"
       ─────┬─────  ────┬─────  ┬
             │           │       └── client_seq: anti-reorder
             │           └── sender: anti-impersonation
             └── session: anti-cross-session replay

Attacco sventato:
  Un attaccante ruba il blob dalla sessione A e lo reinserisce
  nella sessione B. La decifratura fallisce perche l'AAD contiene
  session_id diverso → il tag GCM non corrisponde.
```

---

## Key Encapsulation: RSA-OAEP-SHA256

La chiave AES deve arrivare al destinatario in modo sicuro. Il metodo principale e **RSA-OAEP** (Optimal Asymmetric Encryption Padding):

```python
# cullis_sdk/crypto/e2e.py — righe 24-34

def _encrypt_aes_key_rsa(pubkey, aes_key: bytes) -> dict:
    """Wrap AES key with RSA-OAEP."""
    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode()}
```

```
Analogia — la busta di sicurezza:

  OAEP aggiunge "imbottitura" casuale alla chiave AES prima di cifrarla.
  Cosi anche se cifri la stessa chiave due volte, il risultato e diverso.

  Senza padding:  encrypt(key) → sempre lo stesso blob  ← MALE
  Con OAEP:       encrypt(pad(key)) → blob diverso ogni volta  ← BENE

  MGF1(SHA-256): la funzione di generazione della maschera
  SHA-256: l'algoritmo di hash per il padding
```

Lato destinatario, la decifratura:

```python
# cullis_sdk/crypto/e2e.py — righe 103-113

def _decrypt_aes_key_rsa(privkey, cipher_blob: dict) -> bytes:
    """Unwrap AES key with RSA-OAEP."""
    encrypted_key = base64.urlsafe_b64decode(cipher_blob["encrypted_key"])
    return privkey.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
```

---

## Alternativa: ECDH + HKDF per chiavi ellittiche

Cullis supporta anche chiavi **Elliptic Curve** (EC). Con EC non puoi "cifrare" direttamente come con RSA. Invece usi un protocollo di **key agreement**: ECDH (Elliptic Curve Diffie-Hellman).

```python
# cullis_sdk/crypto/e2e.py — righe 37-52

def _encrypt_aes_key_ec(pubkey, aes_key: bytes) -> dict:
    """Wrap AES key with ECDH + HKDF."""
    ephemeral_key = ec.generate_private_key(pubkey.curve)          # 1
    shared_secret = ephemeral_key.exchange(ec.ECDH(), pubkey)       # 2
    derived_key = HKDF(                                             # 3
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"cullis-e2e-v1",
    ).derive(shared_secret)
    encrypted_key = bytes(a ^ b for a, b in zip(aes_key, derived_key))  # 4
    ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(      # 5
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode(),
        "ephemeral_pubkey": base64.urlsafe_b64encode(ephemeral_pub_bytes).decode(),
    }
```

Passo per passo:

```
1. GENERA chiave effimera EC (usa-e-getta, stessa curva del destinatario)

2. ECDH: combina chiave effimera privata + pubkey destinatario → shared secret
   Solo il mittente (con la chiave effimera) e il destinatario (con la sua privkey)
   possono derivare lo stesso shared secret

3. HKDF: deriva una chiave da 32 byte dallo shared secret
   - info="cullis-e2e-v1": separa questo uso da altri usi della stessa chiave
   - SHA-256: hash per la derivazione

4. XOR: cifra la chiave AES con la chiave derivata
   aes_key XOR derived_key = encrypted_key
   (funziona perche entrambe sono 32 byte di randomness)

5. ALLEGA la chiave pubblica effimera al messaggio
   Il destinatario ne ha bisogno per ricostruire lo shared secret
```

```
Flusso ECDH:

  Mittente                                    Destinatario
  ────────                                    ────────────
  genera ephemeral_key                        ha la sua privkey
  shared = ECDH(ephemeral_priv, dest_pub)     shared = ECDH(dest_priv, ephemeral_pub)
           ──────────────────────────────────────────────────────────────
           Entrambi ottengono lo STESSO shared secret!

  derived = HKDF(shared)                      derived = HKDF(shared)
  encrypted = aes_key XOR derived             aes_key = encrypted XOR derived
```

---

## La firma interna — non-repudiation

La firma interna garantisce che il **mittente ha davvero scritto quel messaggio**. Viene calcolata sul plaintext PRIMA della cifratura, quindi il destinatario puo verificarla DOPO la decifratura.

### Formato canonico

La firma non e sul payload grezzo, ma su una **stringa canonica** deterministica:

```python
# cullis_sdk/crypto/message_signer.py — righe 26-32

def _canonical(session_id, sender_agent_id, nonce, timestamp,
               payload, client_seq=None) -> bytes:
    """Deterministic canonical string to be signed."""
    payload_str = json.dumps(payload, sort_keys=True,
                             separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}".encode("utf-8")
    return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")
```

Esempio concreto:

```
canonical = "sess-abc|acme::buyer|nonce-xyz|1712345678|42|{"action":"buy","item":"steel"}"
             ───┬───  ────┬─────  ───┬────  ────┬─────  ┬  ──────────┬──────────────
                │         │          │          │        │            │
           session_id  sender     nonce    timestamp  seq    JSON canonico
                                                            (sort_keys, no spaces)
```

Perche **canonical JSON**? Se il payload fosse `{"item":"steel","action":"buy"}` (ordine diverso), la firma sarebbe diversa. Con `sort_keys=True`, l'ordine e sempre lo stesso.

### Algoritmo di firma: RSA-PSS

```python
# cullis_sdk/crypto/message_signer.py — righe 20-23, 48-51

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,     # sale randomico di lunghezza massima
)

# Firma
signature = priv_key.sign(canonical, _PSS_PADDING, hashes.SHA256())
return base64.urlsafe_b64encode(signature).decode()
```

```
RSA-PSS vs RSA-PKCS1v15:

  PKCS1v15: padding deterministico → stessa firma per stesso messaggio
  PSS:      padding con SALE RANDOM → firma diversa ogni volta

  PSS e il gold standard moderno. Il sale (MAX_LENGTH = massimo possibile)
  aggiunge entropia: anche se firmi lo stesso messaggio 100 volte,
  ogni firma e diversa.
```

Per chiavi EC, si usa ECDSA:

```python
# cullis_sdk/crypto/message_signer.py — righe 52-53

elif isinstance(priv_key, ec_alg.EllipticCurvePrivateKey):
    signature = priv_key.sign(canonical, ec_alg.ECDSA(hashes.SHA256()))
```

---

## La firma esterna — integrita trasporto

La firma esterna e quella che il **broker verifica**. E calcolata sul **ciphertext** (il blob cifrato), non sul plaintext. Il broker non puo leggere il messaggio, ma puo verificare che:

1. Il mittente e chi dice di essere
2. Il blob non e stato alterato in transito

```python
# app/broker/router.py — righe 441-451

verify_message_signature(
    agent_rec.cert_pem,        # certificato del mittente
    envelope.signature,         # firma esterna (outer)
    session_id,
    current_agent.agent_id,
    envelope.nonce,
    envelope.timestamp,
    envelope.payload,           # payload cifrato (il blob opaco)
    client_seq=envelope.client_seq,
)
```

---

## Il flusso completo: encrypt → send → forward → decrypt

Ecco il flusso completo di un messaggio E2E tra Agente A e Agente B:

```
Agente A (mittente)                    Broker                    Agente B (destinatario)
───────────────────                    ──────                    ───────────────────────

1. Prepara il payload:
   {"action":"buy","qty":100}

2. Firma interna (plaintext):
   canonical = "sess|a|nonce|ts|seq|{json}"
   inner_sig = RSA-PSS(canonical)

3. Cifra con la pubkey di B:
   aes_key = random(32)
   iv = random(12)
   aad = "sess|a|seq"
   blob = AES-GCM(
     {payload, inner_sig},
     key=aes_key, iv=iv, aad=aad
   )
   wrapped_key = RSA-OAEP(aes_key, B.pubkey)

4. Firma esterna (ciphertext):
   outer_sig = RSA-PSS(blob)

5. Invia envelope:                ──────────►
   POST /broker/sessions/{id}/messages
   {
     session_id, sender, nonce,
     timestamp, client_seq,
     payload: {ciphertext, iv,
               encrypted_key},
     signature: outer_sig
   }
                                   6. Verifica outer_sig
                                      con il cert di A     ✓

                                   7. Verifica nonce
                                      (anti-replay)       ✓

                                   8. Verifica timestamp
                                      (finestra 60s)      ✓

                                   9. Inoltra il blob     ──────────►
                                      (opaco, non leggibile)

                                                          10. Decifra wrapped_key:
                                                              aes_key = RSA-OAEP-decrypt(
                                                                wrapped_key, B.privkey)

                                                          11. Decifra blob:
                                                              aad = "sess|a|seq"
                                                              data = AES-GCM-decrypt(
                                                                blob, aes_key, iv, aad)

                                                          12. Estrae:
                                                              payload = data["payload"]
                                                              inner_sig = data["inner_signature"]

                                                          13. Verifica inner_sig:
                                                              canonical = ricostruisci
                                                              RSA-PSS-verify(
                                                                inner_sig, canonical, A.cert)
                                                                                          ✓
                                                          14. Messaggio autentico
                                                              e confidenziale!
```

---

## Sequence numbers e anti-reorder

Il campo `client_seq` e un contatore progressivo mantenuto dal mittente. Serve per rilevare se qualcuno riordina i messaggi:

```
Scenario di attacco senza sequence number:

  A manda:  msg_1 = "vendi 100 azioni"
            msg_2 = "annulla tutto"

  Attaccante riordina: B riceve prima msg_2 poi msg_1
  → B esegue "vendi 100 azioni" (l'ultimo ricevuto)

Con client_seq:
  msg_1 = {client_seq: 0, "vendi 100 azioni"}
  msg_2 = {client_seq: 1, "annulla tutto"}

  Anche riordinati, B vede i numeri e li processa nell'ordine giusto.
```

Il `client_seq` e incluso sia nell'AAD della cifratura AES-GCM (riga 83 di `e2e.py`) che nella stringa canonica della firma (riga 31 di `message_signer.py`). Modificare il sequence number invalida sia il tag GCM che la firma.

---

## Encoding: base64url

Tutti i dati binari (ciphertext, IV, chiave cifrata, firme) sono codificati in **base64url** (RFC 4648 sezione 5):

```python
# cullis_sdk/crypto/e2e.py — righe 95-99

result = {
    "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
    "iv": base64.urlsafe_b64encode(iv).decode(),
}
```

```
base64 standard:  ABC+DEF/GHI=   ← i caratteri +, / e = danno problemi in URL e JSON
base64url:        ABC-DEF_GHI    ← usa - e _ invece, niente padding =

Cullis usa base64url ovunque: firme JWT, payload cifrati, chiavi wrappate.
Cosi puoi mettere tutto in JSON e URL senza escape.
```

---

## Verifica della firma interna dopo decifratura

Quando il destinatario decifra il messaggio, deve verificare la firma interna per garantire la non-repudiation:

```python
# cullis_sdk/crypto/e2e.py — righe 166-209

def verify_inner_signature(
    sender_cert_pem,       # certificato del mittente
    inner_signature_b64,   # firma interna (base64url)
    session_id, sender_agent_id, nonce, timestamp,
    payload, client_seq=None,
):
    cert = crypto_x509.load_pem_x509_certificate(sender_cert_pem.encode())
    pub_key = cert.public_key()
    sig = base64.urlsafe_b64decode(inner_signature_b64)

    # Ricostruisce la stringa canonica (identica a sign_message)
    payload_str = json.dumps(payload, sort_keys=True,
                             separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}"
    else:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}"

    # Verifica con RSA-PSS o ECDSA
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key.verify(sig, canonical.encode(), PSS_PADDING, hashes.SHA256())
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(sig, canonical.encode(), ec.ECDSA(hashes.SHA256()))
```

Se la verifica fallisce, viene lanciato un `ValueError`:

```python
# cullis_sdk/crypto/e2e.py — riga 209
raise ValueError("Inner signature verification failed - message may have been tampered with")
```

---

## La funzione encrypt_for_agent() — il cuore della cifratura

Mettiamo tutto insieme. Questa e la funzione principale che un agente chiama per cifrare un messaggio:

```python
# cullis_sdk/crypto/e2e.py — righe 55-100

def encrypt_for_agent(
    recipient_pubkey_pem,   # PEM della pubkey del destinatario
    plaintext_dict,         # il payload da cifrare
    inner_signature,        # firma interna gia calcolata
    session_id,             # ID sessione
    sender_agent_id,        # chi manda
    client_seq=None,        # sequence number opzionale
) -> dict:
    # 1. Carica la pubkey del destinatario
    pubkey = serialization.load_pem_public_key(recipient_pubkey_pem.encode())

    # 2. Serializza payload + firma interna
    plaintext = json.dumps(
        {"payload": plaintext_dict, "inner_signature": inner_signature},
        sort_keys=True, separators=(",", ":"),
    ).encode()

    # 3. Genera chiave AES e IV
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    # 4. Cifra con AES-256-GCM + AAD
    aesgcm = AESGCM(aes_key)
    aad = f"{session_id}|{sender_agent_id}|{client_seq}".encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)

    # 5. Wrappa la chiave AES (RSA-OAEP o ECDH)
    if isinstance(pubkey, rsa.RSAPublicKey):
        key_data = _encrypt_aes_key_rsa(pubkey, aes_key)
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_data = _encrypt_aes_key_ec(pubkey, aes_key)

    # 6. Restituisce tutto in base64url
    return {
        "ciphertext": base64url(ciphertext),
        "iv": base64url(iv),
        **key_data,   # encrypted_key + eventuale ephemeral_pubkey
    }
```

---

## Threat model — cosa protegge l'E2E

| Attacco | Protezione | Meccanismo |
|---------|-----------|------------|
| Broker compromesso legge i messaggi | **Confidenzialita** | AES-256-GCM + key wrapping |
| Man-in-the-middle altera il blob | **Integrita trasporto** | Firma esterna RSA-PSS |
| Qualcuno nega di aver mandato un messaggio | **Non-repudiation** | Firma interna RSA-PSS sul plaintext |
| Replay di un messaggio vecchio | **Anti-replay** | Nonce unico + cache + DB UNIQUE |
| Riordino dei messaggi | **Anti-reorder** | client_seq nell'AAD e nella firma |
| Cross-session replay | **Binding** | session_id nell'AAD |
| Attaccante impersona il mittente | **Autenticita** | sender_agent_id nell'AAD e nella firma |
| Chiave AES riusata | **Forward secrecy parziale** | Chiave AES random per ogni messaggio |

---

## Riepilogo — cosa portarti a casa

- **E2E** = il broker trasporta i messaggi ma non puo leggerli. Zero trust applicato alla messaggistica.
- **Crittografia ibrida**: AES-256-GCM per i dati (veloce, senza limiti), RSA-OAEP o ECDH+HKDF per la chiave AES (sicuro).
- **Chiave AES usa-e-getta**: ogni messaggio ha la sua chiave, generata con `os.urandom(32)`.
- **AAD** (Additional Authenticated Data): lega il ciphertext a session_id + sender + sequence number. Previene replay cross-session e riordino.
- **Doppia firma**: interna (non-repudiation, sul plaintext) + esterna (integrita trasporto, sul ciphertext). Il broker verifica l'esterna, il destinatario verifica l'interna.
- **RSA-PSS con MAX_LENGTH salt**: firma randomizzata, gold standard moderno.
- **ECDH + HKDF**: alternativa per chiavi ellittiche, con chiave effimera per ogni messaggio e derivazione via HKDF con info `cullis-e2e-v1`.
- **base64url** ovunque: nessun problema con URL, JSON o header HTTP.
- **client_seq**: contatore progressivo per rilevare riordino dei messaggi.

---

Prossimo capitolo: [Capitolo 15 — Sessioni Inter-Agente](15-sessioni.md)
