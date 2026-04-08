# Capitolo 23 — HashiCorp Vault

> *"I segreti importanti non si lasciano in un cassetto. Si mettono in una cassaforte, e si annota chi l'ha aperta e quando."*

---

## Cos'e Vault — spiegazione da bar

Immagina di gestire un palazzo con 50 appartamenti. Ogni inquilino ha le sue chiavi. Dove le tieni?

- **Opzione A (file .env):** tutte le chiavi appese a un chiodo dietro la porta d'ingresso. Chiunque entri le vede.
- **Opzione B (Vault):** una cassaforte blindata con combinazione. Ogni chiave e in una busta sigillata. C'e un registro che annota chi ha aperto quale busta e quando. La cassaforte cambia combinazione periodicamente.

HashiCorp Vault e quella cassaforte. E un software specializzato nel gestire **segreti**: password, chiavi private, token, certificati — tutto cio che non deve finire in un file di testo.

---

## Perche non basta .env

Un file `.env` con i segreti sembra comodo, ma:

```
ADMIN_SECRET=super-segreto-123        ← in chiaro su disco
POSTGRES_PASSWORD=atn                 ← chiunque legga il file li vede
VAULT_TOKEN=dev-root-token            ← nessun audit di chi li ha usati
```

Problemi:
- I file vengono commitati per errore su Git
- Nessun controllo di accesso granulare
- Nessun audit log (chi ha letto cosa?)
- Nessun versioning (se cambi il segreto, perdi il vecchio)
- Nessuna rotazione automatica

Vault risolve tutti questi problemi.

---

## KV v2 — il motore di segreti usato da Cullis

Vault ha diversi **secrets engines**. Cullis usa **KV v2** (Key-Value versione 2):

```
KV v2 features:
  +-- Versioning:  ogni aggiornamento crea una nuova versione
  |                puoi leggere la versione 1, 2, 3...
  |
  +-- Metadata:    created_time, deletion_time, destroyed flag
  |
  +-- Soft delete: cancelli la versione corrente, ma puoi recuperarla
  |
  +-- API REST:    GET/POST/DELETE su /v1/secret/data/{path}
```

### Come Cullis archivia i segreti

Il percorso di default e `secret/data/broker`. Lo script `deploy_broker.sh` carica la chiave CA:

```bash
# Legge il file PEM e lo mette in Vault
BROKER_KEY_PEM=$(cat certs/broker-ca-key.pem)
BROKER_CERT_PEM=$(cat certs/broker-ca.pem)

curl -X POST "${VAULT_ADDR}/v1/secret/data/broker" \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -d '{"data": {
    "private_key_pem": "'"${BROKER_KEY_PEM}"'",
    "ca_cert_pem": "'"${BROKER_CERT_PEM}"'"
  }}'
```

Il risultato in Vault:

```
secret/data/broker
  |
  +-- version 1
       +-- private_key_pem: "-----BEGIN RSA PRIVATE KEY-----\n..."
       +-- ca_cert_pem:     "-----BEGIN CERTIFICATE-----\n..."
       +-- metadata:
            created_time: 2026-04-08T10:30:00Z
            version: 1
```

---

## L'adapter KMS di Cullis

Cullis non parla direttamente con Vault ovunque. Ha un'astrazione in `app/kms/` con il pattern **Strategy**:

```
app/kms/
  +-- provider.py     ← Protocol (interfaccia)
  +-- factory.py      ← Factory (sceglie il backend)
  +-- local.py        ← Backend filesystem (dev)
  +-- vault.py        ← Backend Vault (prod)
  +-- secret_encrypt.py ← crittografia segreti a riposo
```

### Il Protocol — l'interfaccia

`app/kms/provider.py` definisce cosa deve saper fare un backend:

```python
@runtime_checkable
class KMSProvider(Protocol):
    async def get_broker_private_key_pem(self) -> str: ...
    async def get_broker_public_key_pem(self) -> str: ...
    async def encrypt_secret(self, plaintext: str) -> str: ...
    async def decrypt_secret(self, stored: str) -> str: ...
```

Qualsiasi backend (Vault, AWS KMS, Azure Key Vault) deve implementare questi 4 metodi. Il resto del codice non sa e non gli importa quale backend sta usando.

### La Factory — la scelta

`app/kms/factory.py` legge `KMS_BACKEND` e crea il provider giusto:

```python
def _build_provider() -> KMSProvider:
    backend = settings.kms_backend.lower()

    if backend == "vault":
        return VaultKMSProvider(
            vault_addr=settings.vault_addr,      # http://vault:8200
            vault_token=settings.vault_token,     # token di accesso
            secret_path=settings.vault_secret_path,  # secret/data/broker
        )

    if backend == "local":
        return LocalKMSProvider(
            key_path=settings.broker_ca_key_path,    # certs/broker-ca-key.pem
            cert_path=settings.broker_ca_cert_path,  # certs/broker-ca.pem
        )
```

```
                   KMS_BACKEND
                       |
           +-----------+-----------+
           |                       |
        "vault"                 "local"
           |                       |
  VaultKMSProvider          LocalKMSProvider
  (legge da Vault)          (legge da disco)
```

### Backend Local — sviluppo

`app/kms/local.py` legge i file PEM dal filesystem:

```python
class LocalKMSProvider:
    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            self._private_key_pem = Path(self._key_path).read_text()
        return self._private_key_pem
```

Semplice, diretto, perfetto per lo sviluppo locale.

### Backend Vault — produzione

`app/kms/vault.py` fa una chiamata HTTP a Vault:

```python
class VaultKMSProvider:
    async def _fetch_secret(self) -> dict:
        url = f"{self._vault_addr}/v1/{self._secret_path}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers={"X-Vault-Token": self._vault_token})
            return resp.json()["data"]["data"]

    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            secret = await self._fetch_secret()
            self._private_key_pem = secret["private_key_pem"]
        return self._private_key_pem
```

Caratteristiche di sicurezza:
- **Cache in memoria**: la chiave viene scaricata una sola volta e tenuta in RAM
- **TLS obbligatorio**: se Vault non usa HTTPS, il provider rifiuta di partire (a meno di `VAULT_ALLOW_HTTP=true` per il dev)
- **`invalidate_cache()`**: forza il re-fetch dopo una rotazione di chiave

```
Flusso:
  Broker avvio → KMS factory → VaultKMSProvider
                                    |
                              GET /v1/secret/data/broker
                              X-Vault-Token: xxx
                                    |
                              Vault risponde con PEM
                                    |
                              Cache in memoria
                                    |
                              Tutte le operazioni JWT usano la cache
```

---

## Vault nel Docker Compose

```yaml
vault:
  image: hashicorp/vault:1.17
  ports: ["8200:8200"]
  environment:
    VAULT_DEV_ROOT_TOKEN_ID: ${VAULT_TOKEN:-dev-root-token}
    VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200"
  cap_add:
    - IPC_LOCK          # previene che i segreti finiscano in swap
  healthcheck:
    test: ["CMD", "vault", "status", "-address=http://localhost:8200"]
```

In sviluppo, Vault gira in **dev mode**: KV v2 gia attivato, nessuna unsealing, token root pre-impostato. In produzione, va configurato con unsealing, policy di accesso, e TLS.

---

## login_from_pem() — chiave mai su disco

Per scenari enterprise, la chiave privata dell'agente puo essere in un secret manager (Vault, AWS Secrets Manager) e passata direttamente al SDK senza mai scriverla su filesystem:

```python
# cullis_sdk/client.py
def login_from_pem(self, agent_id: str, org_id: str,
                   private_key_pem: str, cert_chain_pem: str):
    """Login using PEM strings directly — key never touches disk."""
    # Costruisce client_assertion JWT con la chiave in memoria
    # Invia al broker per autenticazione
```

```
Flusso enterprise:
  1. Agent legge chiave privata da Vault/AWS/Azure
  2. Chiama login_from_pem(key_pem_string)
  3. SDK firma il JWT in memoria
  4. La chiave non viene mai scritta su disco
  5. Il broker non riceve mai la chiave privata (solo il JWT firmato)
```

Questo e un principio di sicurezza fondamentale: la chiave privata esiste solo in memoria, per il tempo strettamente necessario.

---

## Configurazione in Cullis

Le variabili d'ambiente rilevanti in `app/config.py`:

```python
kms_backend: str = "vault"                          # "local" o "vault"
vault_addr: str = ""                                # URL di Vault
vault_token: str = ""                               # token di accesso
vault_secret_path: str = "secret/data/broker"       # percorso del segreto
```

La validazione allo startup avvisa se il token e quello di default:

```python
if settings.vault_token == "dev-root-token":
    logger.warning("VAULT_TOKEN is the default dev token")
```

---

## Riepilogo — cosa portarti a casa

- **Vault** e una cassaforte per segreti: password, chiavi private, token — con audit, versioning, e accesso controllato
- **KV v2** e il motore versioned key-value usato da Cullis per archiviare la chiave CA del broker
- L'adapter **KMS** in `app/kms/` astrae il backend: `local` (file su disco) per dev, `vault` per produzione
- Il pattern **Protocol + Factory** permette di aggiungere nuovi backend (AWS, Azure) senza modificare il resto del codice
- La chiave viene scaricata **una volta** da Vault e cachata in memoria per la vita del processo
- **TLS obbligatorio**: il VaultKMSProvider rifiuta connessioni HTTP (override solo con `VAULT_ALLOW_HTTP=true`)
- **`login_from_pem()`** nel SDK permette di passare la chiave come stringa, senza mai scriverla su filesystem
- `deploy_broker.sh` carica automaticamente la chiave CA in Vault dopo il primo avvio

---

**Prossimo capitolo:** [24 — Redis](24-redis.md)
