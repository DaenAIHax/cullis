# Capitolo 04 — Crittografia Asimmetrica (RSA, ECDSA, ECDH)

> *"Due chiavi: una la dai a tutti, l'altra la tieni nel caveau. Questo cambia tutto."*

---

## Il problema fondamentale — spiegazione da bar

Immagina di voler mandare un messaggio segreto a qualcuno che non hai mai incontrato. Non potete vedervi per scambiarvi una password. Chiunque potrebbe intercettare il messaggio.

Con la crittografia **simmetrica** (una sola chiave, come un lucchetto con una sola copia della chiave), avete un problema: come vi passate la chiave senza che nessuno la intercetti? È il classico paradosso dell'uovo e la gallina.

La crittografia **asimmetrica** risolve questo: ogni persona ha **due chiavi** matematicamente legate.

```
Chiave Pubblica (public key)     Chiave Privata (private key)
━━━━━━━━━━━━━━━━━━━━━━━━━━━     ━━━━━━━━━━━━━━━━━━━━━━━━━━━
La dai a tutti                   La tieni segreta
Come il tuo indirizzo di casa    Come la chiave del portone
Chiunque può SPEDIRTI lettere    Solo tu puoi APRIRE la cassetta
```

Le due chiavi funzionano in coppia ma non sono interscambiabili:
- Ciò che **cifri con la pubblica**, solo la **privata** può decifrarlo (riservatezza)
- Ciò che **firmi con la privata**, chiunque con la **pubblica** può verificarlo (autenticità)

---

## Come funziona — l'analogia del lucchetto

### Cifratura (riservatezza)

```
Alice vuole mandare un segreto a Bob:

1. Bob ha un lucchetto speciale (chiave pubblica) — ne fa copie e le dà a tutti
2. Alice mette il messaggio in una scatola e chiude con il lucchetto di Bob
3. Una volta chiuso, nemmeno Alice può riaprirlo
4. Solo Bob ha la chiave del suo lucchetto (chiave privata)
5. Bob apre la scatola e legge il messaggio

Se Eve intercetta la scatola:
  → Ha la scatola chiusa
  → Ha il lucchetto di Bob (è pubblico)
  → Ma NON ha la chiave di Bob
  → Non può aprire la scatola
```

### Firma digitale (autenticità)

```
Alice vuole dimostrare che il messaggio è suo:

1. Alice ha un timbro unico (chiave privata) — solo lei ce l'ha
2. Alice timbra il messaggio
3. Tutti hanno una lente per verificare il timbro di Alice (chiave pubblica)
4. Chiunque può verificare: "sì, questo timbro è di Alice"

Se Eve prova a falsificare il timbro:
  → Non ha il timbro di Alice (chiave privata)
  → Qualsiasi tentativo di imitazione fallisce la verifica con la lente
```

---

## RSA — il veterano

### Cos'è

RSA (Rivest-Shamir-Adleman, 1977) è il primo algoritmo di crittografia asimmetrica usato in pratica. Ancora oggi è ovunque: HTTPS, email, SSH, PDF firmati.

### Come funziona — versione semplificata

L'idea geniale di RSA si basa su un fatto matematico:

> **Moltiplicare due numeri primi grandi è facile. Scomporli (fattorizzazione) è praticamente impossibile.**

```
Facile:  61 × 53 = 3233                    (un computer lo fa in nanosecondi)
Difficile: 3233 = ? × ?                    (con numeri di 2048 bit, ci vogliono milioni di anni)
```

In pratica:
1. Scegli due numeri primi enormi `p` e `q` (ciascuno di ~1024 bit per RSA-2048)
2. Calcoli `n = p × q` — questo va nella chiave pubblica
3. Da `p` e `q` derivi l'esponente privato `d` — questo è la chiave privata
4. Chiunque ha `n` (pubblico) ma non può ricavare `p` e `q` (fattorizzazione troppo difficile)

### Dimensioni delle chiavi RSA

| Dimensione | Sicurezza equivalente | Uso |
|---|---|---|
| 1024 bit | ~80 bit simmetrici | **DEPRECATA** — crackabile |
| 2048 bit | ~112 bit simmetrici | Minimo accettabile oggi |
| 3072 bit | ~128 bit simmetrici | Raccomandato NIST |
| 4096 bit | ~140 bit simmetrici | Alta sicurezza, più lento |

> **Regola pratica:** i bit della chiave RSA NON sono la sicurezza effettiva. RSA-2048 equivale a ~112 bit di sicurezza simmetrica. Per avere 128 bit effettivi (standard moderno), servirebbero 3072 bit RSA.

### Operazioni RSA

| Operazione | Chiave usata | Scopo |
|---|---|---|
| **Cifratura** (RSA-OAEP) | Pubblica del destinatario | Riservatezza |
| **Decifratura** | Privata del destinatario | Leggere il messaggio |
| **Firma** (RSA-PSS) | Privata del mittente | Autenticità + non-repudiation |
| **Verifica firma** | Pubblica del mittente | Verificare l'autore |

### RSA-OAEP vs RSA-PKCS1v15

Ci sono due modi per cifrare con RSA:

- **PKCS#1 v1.5** — il vecchio modo. Vulnerabile a padding oracle attacks (attacco di Bleichenbacher, 1998). **Non usarlo mai per roba nuova.**
- **RSA-OAEP** (Optimal Asymmetric Encryption Padding) — il modo moderno. Sicuro contro padding oracle. È quello che usa Cullis.

```
RSA-OAEP in Cullis:
  Cifra la chiave AES di sessione con la pubkey RSA del destinatario
  Hash: SHA-256
  → Solo il destinatario può recuperare la chiave AES
  → Vedi: cullis_sdk/crypto/e2e.py
```

### RSA-PSS vs RSA-PKCS1v15 (per firme)

Stesso discorso delle firme:

- **PKCS#1 v1.5** — il vecchio modo. Funziona, ma ci sono stati attacchi (Bleichenbacher anche qui).
- **RSA-PSS** (Probabilistic Signature Scheme) — il modo moderno. Include randomness, dimostrabilmente sicuro. È quello che usa Cullis.

```
RSA-PSS in Cullis:
  Inner signature: l'agente firma il messaggio con la propria chiave privata
    → Non-repudiation: "io l'ho scritto"
  Outer signature: firma per integrità di trasporto
    → Se qualcuno altera il blob in transito, la verifica fallisce
  → Vedi: cullis_sdk/crypto/message_signer.py
```

### RSA in Cullis — dove lo trovi

| Componente | Algoritmo | Chiave | File |
|---|---|---|---|
| Broker CA | RSA-4096 | Firma cert org | `generate_certs.py` |
| Org CA | RSA-4096 | Firma cert agenti | `generate_certs.py`, MCP Proxy auto-PKI |
| Agent cert | RSA-2048 | Auth + firma messaggi | `generate_certs.py`, MCP Proxy |
| JWT broker | RS256 (RSA-PKCS1v15-SHA256) | Firma token sessione | `app/auth/jwt_utils.py` |
| Client assertion | RS256 | Agente firma il login JWT | `cullis_sdk/auth.py` |
| E2E key wrap | RSA-OAEP-SHA256 | Cifra chiave AES sessione | `cullis_sdk/crypto/e2e.py` |
| Message sign | RSA-PSS-SHA256 | Firma messaggi | `cullis_sdk/crypto/message_signer.py` |

---

## Curve Ellittiche — il moderno

### Perché servono

RSA funziona, ma ha un problema: le chiavi sono **enormi**. RSA-4096 = chiave pubblica di 512 byte. Per ottenere la stessa sicurezza con le curve ellittiche, bastano 32 byte.

### Cos'è una curva ellittica — versione semplificata

Una curva ellittica è una curva matematica del tipo `y² = x³ + ax + b`. Ha una proprietà magica: puoi definire una "somma" tra punti sulla curva, e questa somma è:

- **Facile da calcolare** (sommare punti)
- **Praticamente impossibile da invertire** (dato il risultato, trovare quante volte hai sommato)

Questo è il **problema del logaritmo discreto sulle curve ellittiche (ECDLP)** — l'equivalente della fattorizzazione per RSA, ma molto più difficile per bit di chiave.

```
La "trappola" delle curve ellittiche:

Facile:   P × 42 = Q                    (moltiplica il punto P per 42)
Difficile: P × ? = Q                    (dato P e Q, trova il 42)

Con numeri di 256 bit, "trovare il 42" richiederebbe
più energia di quanta ne produca il sole nella sua vita.
```

### Confronto RSA vs EC

| | RSA | Curve Ellittiche |
|---|---|---|
| Sicurezza 128 bit | 3072 bit di chiave | **256 bit** di chiave |
| Sicurezza 256 bit | 15360 bit di chiave | **512 bit** di chiave |
| Velocità firma | Più lento | **~10x più veloce** |
| Velocità verifica | Più veloce | Più lento |
| Adozione | Ovunque dal 1977 | Standard dal ~2010 |
| Resistenza quantistica | No | No (entrambi vulnerabili) |

> **Regola pratica:** per chiavi nuove, EC è quasi sempre meglio. RSA si usa ancora per backward compatibility e dove servono chiavi di lunga durata (come le CA root).

### Le curve importanti

| Curva | Dimensione | Dove |
|---|---|---|
| **P-256** (secp256r1, prime256v1) | 256 bit = ~128 bit sicurezza | TLS, DPoP, JWT ES256, la più usata |
| **P-384** (secp384r1) | 384 bit = ~192 bit sicurezza | Government, alta sicurezza |
| **P-521** (secp521r1) | 521 bit = ~256 bit sicurezza | Massima sicurezza |
| **Ed25519** (Curve25519) | 256 bit | SSH, Signal, Wireguard — non NIST |

### ECDSA — firma con curve ellittiche

ECDSA (Elliptic Curve Digital Signature Algorithm) fa la stessa cosa di RSA-PSS (firmare), ma con chiavi molto più piccole.

```
RSA-2048 firma:  256 byte
ECDSA P-256 firma: 64 byte    (4x più piccola, stessa sicurezza)
```

In Cullis, ECDSA non è usato per le firme dei messaggi (si usa RSA-PSS per i cert x509). Ma è usato per **DPoP**.

### ECDH — key agreement con curve ellittiche

ECDH (Elliptic Curve Diffie-Hellman) serve per **concordare un segreto condiviso** senza mai trasmetterlo:

```
Alice ha:  chiave privata a, chiave pubblica A = a×G
Bob ha:    chiave privata b, chiave pubblica B = b×G

Alice calcola: a × B = a × b × G = S (segreto)
Bob calcola:   b × A = b × a × G = S (stesso segreto!)

Eve vede: A e B (chiavi pubbliche)
Eve dovrebbe calcolare: a × b × G
Ma non conosce né a né b → impossibile

Risultato: Alice e Bob hanno lo stesso segreto S
           senza averlo mai trasmesso
```

**In Cullis:** ECDH è usato nella demo legacy (AES key derivation tra buyer e supplier). Nel flusso production, si usa RSA-OAEP per il key wrapping (più semplice quando il destinatario è identificato dal certificato).

### EC P-256 in Cullis — dove lo trovi

| Componente | Algoritmo | Scopo | File |
|---|---|---|---|
| DPoP proof | EC P-256 (ES256) | Chiave effimera per proof-of-possession | `app/auth/dpop.py` |
| JWKS thumbprint | EC P-256 | `jkt` claim nel token | `app/auth/dpop.py` |

---

## Generare chiavi in Python — codice reale

La libreria `cryptography` è lo standard Python per la crittografia. Ecco come si generano le chiavi:

### RSA

```python
from cryptography.hazmat.primitives.asymmetric import rsa

# Genera una chiave privata RSA-4096 (per una CA)
private_key = rsa.generate_private_key(
    public_exponent=65537,     # standard, quasi sempre 65537
    key_size=4096,             # bit della chiave
)

# La chiave pubblica è derivata dalla privata
public_key = private_key.public_key()
```

**`public_exponent=65537`**: perché 65537? È un numero primo con pochi bit a 1 in binario (10000000000000001), il che rende le operazioni RSA veloci. È lo standard dal 2000+. Non cambiarlo mai.

### EC P-256

```python
from cryptography.hazmat.primitives.asymmetric import ec

# Genera una chiave privata EC P-256 (per DPoP)
private_key = ec.generate_private_key(ec.SECP256R1())

# La chiave pubblica è un punto sulla curva
public_key = private_key.public_key()
```

### Serializzazione PEM vs DER

Le chiavi possono essere salvate in due formati:

```
PEM (Privacy Enhanced Mail):
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8...
  -----END RSA PRIVATE KEY-----
  → Testo Base64, leggibile, comodo per file e config

DER (Distinguished Encoding Rules):
  0x30 0x82 0x04 0xa3 0x02 0x01 0x00 0x02 0x82...
  → Binario, compatto, usato nei certificati x509
```

```python
from cryptography.hazmat.primitives import serialization

# Salva la chiave privata in PEM
pem_data = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()  # o BestAvailableEncryption(b"password")
)

# Salva la chiave pubblica in PEM
pub_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
```

> **In Cullis:** `generate_certs.py` genera tutta la PKI (CA + org + agent) e salva in PEM. Il MCP Proxy genera le chiavi automaticamente e le salva in Vault o nel DB cifrato.

---

## Firmare e verificare — codice reale

### RSA-PSS (come fa Cullis per i messaggi)

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# FIRMARE (con la chiave privata del mittente)
signature = private_key.sign(
    data=message_bytes,
    padding=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),    # Mask Generation Function
        salt_length=padding.PSS.MAX_LENGTH,   # massima sicurezza
    ),
    algorithm=hashes.SHA256(),
)

# VERIFICARE (con la chiave pubblica del mittente)
try:
    public_key.verify(
        signature,
        data=message_bytes,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        algorithm=hashes.SHA256(),
    )
    print("Firma valida — il messaggio è autentico")
except InvalidSignature:
    print("Firma NON valida — messaggio contraffatto o corrotto")
```

### RSA-OAEP (come fa Cullis per wrappare la chiave AES)

```python
# CIFRARE una chiave AES con la pubkey RSA del destinatario
wrapped_key = recipient_public_key.encrypt(
    aes_key,                                    # 32 byte (AES-256)
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
)

# DECIFRARE (il destinatario, con la sua chiave privata)
aes_key = recipient_private_key.decrypt(
    wrapped_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
)
```

---

## Riepilogo — cosa portarti a casa

- **Crittografia asimmetrica** = due chiavi (pubblica + privata) che lavorano in coppia
- **RSA**: veterano, basato sulla fattorizzazione, chiavi grandi (2048-4096 bit). Cullis lo usa per CA, certificati, firme messaggi (PSS), e key wrapping (OAEP)
- **Curve Ellittiche**: moderno, stessa sicurezza con chiavi 10x più piccole. Cullis lo usa per DPoP (P-256)
- **ECDH**: permette a due parti di concordare un segreto senza trasmetterlo
- **PSS > PKCS1v15** per le firme, **OAEP > PKCS1v15** per la cifratura — sempre i padding moderni
- In Python, la libreria `cryptography` gestisce tutto: generazione, serializzazione PEM/DER, firma, verifica, cifratura

---

*Prossimo capitolo: [05 — Crittografia Simmetrica (AES-GCM)](05-crittografia-simmetrica.md) — come si cifrano effettivamente i messaggi*
