# Capitolo 05 — Crittografia Simmetrica (AES-GCM)

> *"Una chiave, una serratura. Veloce, semplice, brutale. Ma come te la passi?"*

---

## Simmetrica vs Asimmetrica — il matrimonio

Nel capitolo precedente abbiamo visto la crittografia asimmetrica (due chiavi). È potente ma ha un difetto: è **lentissima**. Cifrare 1 MB con RSA richiederebbe migliaia di operazioni.

La crittografia **simmetrica** (una sola chiave condivisa) è **~1000x più veloce**. Ma ha un problema: come condividi la chiave?

La soluzione che usa tutto il mondo (e Cullis): **ibrida**.

```
Cifratura ibrida — come funziona in pratica:

1. Genera una chiave AES casuale (32 byte = 256 bit)          ← veloce
2. Cifra il MESSAGGIO con AES-GCM usando quella chiave         ← veloce
3. Cifra la CHIAVE AES con RSA-OAEP (pubkey del destinatario)  ← lento, ma è solo 32 byte
4. Invia: [chiave AES cifrata] + [messaggio cifrato]

Il destinatario:
1. Decifra la chiave AES con la sua chiave privata RSA         ← lento, ma è solo 32 byte
2. Decifra il messaggio con AES-GCM                             ← veloce

Risultato: sicurezza dell'asimmetrica + velocità della simmetrica
```

Questa è esattamente l'architettura E2E di Cullis.

---

## AES — Advanced Encryption Standard

### Cos'è

AES (2001) è lo standard mondiale per la cifratura simmetrica. Lo usano tutti: HTTPS, WhatsApp, Signal, BitLocker, FileVault, 7-Zip, WPA2, VPN, e anche Cullis.

È stato scelto dal NIST tra 15 candidati dopo 5 anni di analisi pubblica. L'algoritmo originale si chiama Rijndael (dai nomi dei creatori belgi).

### Come funziona — versione semplificata

AES è un **block cipher**: prende blocchi di 128 bit (16 byte) e li cifra con una chiave.

```
Plaintext (16 byte):   "Ciao mondo 12345"
Chiave AES-256:        [32 byte casuali]
                            │
                            ▼
                    ┌───────────────┐
                    │   AES Engine  │  ← 14 round di trasformazioni
                    │   (14 round)  │     (sostituzione, shift, mix, xor)
                    └───────┬───────┘
                            │
                            ▼
Ciphertext (16 byte):  0xA3 0x7B 0x1F 0x9C ...  (incomprensibile)
```

Ma i messaggi reali sono più lunghi di 16 byte. Come si cifra un messaggio di 1 KB? Servono le **modalità di operazione**.

---

## Modalità di operazione — perché contano

### ECB — Electronic Codebook (la modalità SBAGLIATA)

Ogni blocco da 16 byte viene cifrato indipendentemente:

```
Blocco 1: "Ordine: 100 pe" → cifra → 0xA3B7...
Blocco 2: "zzi a 10 euro  " → cifra → 0x5C2E...
Blocco 3: "Ordine: 100 pe" → cifra → 0xA3B7...  ← STESSO output del blocco 1!
```

**Problema:** blocchi uguali producono ciphertext uguali. Un attaccante può vedere i pattern. Il famoso esempio è il "pinguino ECB" — cifrare un'immagine con ECB lascia vedere la sagoma.

**Mai usare ECB. Mai.**

### CBC — Cipher Block Chaining (il vecchio standard)

Ogni blocco viene XOR-ato con il ciphertext del blocco precedente prima di cifrare. I pattern spariscono.

```
Blocco 1: plain ⊕ IV     → cifra → C1
Blocco 2: plain ⊕ C1     → cifra → C2
Blocco 3: plain ⊕ C2     → cifra → C3
```

Funziona, ma ha due problemi:
1. Non è parallelizzabile (ogni blocco dipende dal precedente)
2. Non fornisce **autenticazione** — non sai se il ciphertext è stato modificato

### GCM — Galois/Counter Mode (lo standard moderno)

GCM combina **cifratura** e **autenticazione** in un'unica operazione. Ecco perché si chiama "authenticated encryption".

```
Input:
  - Chiave (32 byte per AES-256)
  - Nonce/IV (12 byte, DEVE essere unico per ogni messaggio)
  - Plaintext (il messaggio)
  - AAD (Additional Authenticated Data — opzionale, vedi sotto)

Output:
  - Ciphertext (stessa dimensione del plaintext)
  - Tag (16 byte — il "sigillo" di autenticità)

Proprietà:
  ✓ Confidentiality — il messaggio è cifrato
  ✓ Integrity — se il ciphertext viene modificato, la decifratura fallisce
  ✓ Authentication — il tag prova che chi ha cifrato aveva la chiave
  ✓ Parallelizzabile — counter mode, ogni blocco indipendente
```

---

## AES-256-GCM — come lo usa Cullis

### Struttura completa di un messaggio E2E in Cullis

```
┌─────────────────────────────────────────────────────────────┐
│                    MESSAGGIO E2E CULLIS                      │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ wrapped_key                        │                     │
│  │ RSA-OAEP(pubkey_destinatario,      │ ← chiave AES cifrata│
│  │          aes_session_key)          │    con RSA           │
│  └────────────────────────────────────┘                     │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ iv (12 byte)                       │ ← nonce unico       │
│  └────────────────────────────────────┘                     │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ ciphertext                         │ ← messaggio cifrato  │
│  │ AES-256-GCM(key, iv, plaintext,    │                     │
│  │             aad)                   │                     │
│  └────────────────────────────────────┘                     │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ tag (16 byte)                      │ ← sigillo integrità  │
│  └────────────────────────────────────┘                     │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ inner_signature (RSA-PSS)          │ ← non-repudiation    │
│  └────────────────────────────────────┘                     │
│                                                             │
│  ┌────────────────────────────────────┐                     │
│  │ outer_signature (RSA-PSS)          │ ← transport integrity│
│  └────────────────────────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### Il Nonce/IV — perché è critico

Il nonce (Number used ONCE) per AES-GCM è di 12 byte. **Non deve MAI essere riutilizzato con la stessa chiave.**

```
Stessa chiave + stesso nonce = CATASTROFE

Se cifri due messaggi diversi con la stessa chiave e lo stesso nonce:
  C1 = plaintext1 ⊕ keystream
  C2 = plaintext2 ⊕ keystream

  C1 ⊕ C2 = plaintext1 ⊕ plaintext2
  → L'attaccante può XOR i due ciphertext e ottenere
    la relazione tra i due plaintext
  → Con tecniche statistiche, può recuperare entrambi
```

**Come Cullis lo gestisce:** genera un nonce casuale da 12 byte per ogni messaggio con `os.urandom(12)`. Con 96 bit di randomness, la probabilità di collisione è trascurabile per volumi normali (~2^48 messaggi prima di preoccuparsi).

### AAD — Additional Authenticated Data

L'AAD è la parte geniale di GCM: dati che NON vengono cifrati, ma che SONO protetti dall'autenticazione.

```
Perché serve?

Immagina un messaggio cifrato con l'intestazione "session_id: abc123".
L'intestazione deve viaggiare in chiaro (il broker deve instradare).
Ma se qualcuno la cambia da "abc123" a "xyz789"?
Il messaggio arriva alla sessione sbagliata!

Con AAD:
  Cifra: AES-GCM(key, nonce, plaintext, aad="session:abc123,seq:42")
  
  Se qualcuno cambia il session_id nell'header:
    → La decifratura fallisce perché l'AAD non corrisponde
    → Il tag di autenticazione non è valido
    → L'alterazione è rilevata
```

**In Cullis:** l'AAD include il `session_id` e il `sequence_number`. Questo previene:
- **Reindirizzamento:** spostare un messaggio da una sessione a un'altra
- **Reorder:** riordinare i messaggi (il sequence number deve crescere)

---

## Codice reale — cifrare e decifrare con AES-256-GCM

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === CIFRATURA ===

# Genera chiave AES-256 (32 byte casuali)
aes_key = os.urandom(32)

# Genera nonce (12 byte, DEVE essere unico)
nonce = os.urandom(12)

# Plaintext: il messaggio da cifrare
plaintext = b'{"order": "100 units", "price": 10.50}'

# AAD: dati autenticati ma non cifrati
aad = b"session:abc123,seq:42"

# Cifra
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
# ciphertext include il tag di autenticazione (ultimi 16 byte)

# === DECIFRATURA ===

# Il destinatario ha la stessa chiave (decifrata da RSA-OAEP)
aesgcm = AESGCM(aes_key)
try:
    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
    print(decrypted)  # b'{"order": "100 units", "price": 10.50}'
except Exception:
    print("ERRORE: messaggio corrotto o manomesso!")
```

### Cosa succede se qualcuno altera il ciphertext?

```python
# Eve modifica un byte del ciphertext
tampered = bytearray(ciphertext)
tampered[5] ^= 0xFF  # flip un byte

try:
    aesgcm.decrypt(nonce, bytes(tampered), aad)
except Exception as e:
    print("InvalidTag!")  # GCM rileva la modifica!
```

### Cosa succede se qualcuno cambia l'AAD?

```python
# Eve cambia il session_id nell'AAD
wrong_aad = b"session:HACKED,seq:42"

try:
    aesgcm.decrypt(nonce, ciphertext, wrong_aad)
except Exception as e:
    print("InvalidTag!")  # L'AAD non corrisponde!
```

---

## Il flusso completo in Cullis — dal messaggio all'E2E

```
Buyer vuole inviare {"order": "100 widgets"} a Supplier:

LATO BUYER:
  1. Genera chiave AES random (32 byte)
  2. Cifra il messaggio con AES-256-GCM
     - nonce: 12 byte random
     - aad: session_id + sequence_number
     → ciphertext + tag
  3. Wrappa la chiave AES con RSA-OAEP(pubkey_supplier)
     → wrapped_key
  4. Firma inner: RSA-PSS(privkey_buyer, hash(plaintext))
     → inner_signature
  5. Firma outer: RSA-PSS(privkey_buyer, hash(ciphertext+wrapped_key+iv))
     → outer_signature
  6. Invia al broker:
     {wrapped_key, iv, ciphertext, tag, inner_sig, outer_sig}

LATO BROKER:
  → Riceve il blob
  → Verifica outer_signature (integrità trasporto)
  → NON può decifrare (non ha la chiave privata del Supplier)
  → Inoltra al Supplier (zero-knowledge forwarding)

LATO SUPPLIER:
  1. Verifica outer_signature con pubkey_buyer
  2. Decripta wrapped_key con RSA-OAEP(privkey_supplier)
     → chiave AES
  3. Decifra il messaggio con AES-256-GCM
     - nonce: dal pacchetto
     - aad: session_id + sequence_number (devono corrispondere!)
     → plaintext
  4. Verifica inner_signature con pubkey_buyer
     → Non-repudiation: il Buyer ha davvero scritto questo
```

---

## Attacchi e difese — riepilogo

| Attacco | Come funziona | Difesa AES-GCM in Cullis |
|---|---|---|
| **Bit flipping** | Cambiare bit nel ciphertext | Tag di autenticazione → decifratura fallisce |
| **Nonce reuse** | Riutilizzare stesso IV/nonce | Nonce random 12 byte per messaggio |
| **Reorder** | Scambiare ordine dei messaggi | Sequence number nell'AAD |
| **Cross-session** | Spostare messaggio ad altra sessione | Session ID nell'AAD |
| **Replay** | Ri-inviare un messaggio catturato | Sequence number + JTI blacklist |
| **Brute force** | Provare tutte le chiavi | AES-256 = 2^256 combinazioni → impossibile |

---

## Riepilogo — cosa portarti a casa

- **AES** è lo standard mondiale per la cifratura simmetrica — veloce, sicuro, ovunque
- **GCM** (Galois/Counter Mode) fornisce cifratura + autenticazione in un colpo solo
- Il **nonce** deve essere unico per ogni messaggio — riutilizzarlo è catastrofico
- L'**AAD** protegge dati in chiaro (come session_id) senza cifrarli
- Cullis usa **cifratura ibrida**: AES-256-GCM per il payload, RSA-OAEP per wrappare la chiave AES
- Il **tag** (16 byte) è il "sigillo" — qualsiasi modifica al ciphertext o all'AAD lo rompe
- Il **sequence number** nell'AAD previene reorder e replay dei messaggi

---

*Prossimo capitolo: [06 — PKI — Public Key Infrastructure](06-pki.md) — la struttura dei certificati e la catena di fiducia*
