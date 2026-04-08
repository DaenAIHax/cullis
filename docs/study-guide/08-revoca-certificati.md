# Capitolo 08 — Revoca Certificati

> *"Un passaporto rubato non diventa invalido da solo. Qualcuno deve annullarlo."*

---

## Il problema — spiegazione da bar

Hai dato un certificato a un agente. Il certificato è valido per 1 anno. Ma dopo 3 mesi succede qualcosa:

- La chiave privata dell'agente viene rubata
- Un dipendente malevolo ha accesso all'agente e lo usa per scopi non autorizzati
- L'organizzazione dell'agente lascia il network
- Scopri che il certificato è stato emesso per errore

Il certificato è ancora "valido" (non è scaduto). Ma non dovrebbe più essere accettato. Come lo invalidi prima della scadenza?

**Analogia:** Ti rubano la carta di credito. La carta ha una scadenza tra 2 anni, ma chiami la banca e la **bloccano immediatamente**. Da quel momento, ogni commerciante che prova a usarla riceve un rifiuto.

Questa è la **revoca**: invalidare un certificato prima della sua scadenza naturale.

---

## I tre approcci standard

### 1. CRL — Certificate Revocation List

La CA pubblica periodicamente una lista di certificati revocati:

```
CRL (Certificate Revocation List):
  Emessa da: Agent Trust Network Root CA
  Data emissione: 2026-04-08
  Prossimo aggiornamento: 2026-04-09
  
  Certificati revocati:
    Serial: 0x3A7F2B → revocato il 2026-04-05 (motivo: key compromise)
    Serial: 0x1C8E9D → revocato il 2026-04-07 (motivo: cessation of operation)
```

**Pro:** Standard (RFC 5280), offline (non serve un servizio in tempo reale).

**Contro:** 
- Latenza: la CRL si aggiorna ogni tot ore/giorni. Nel frattempo, il cert revocato è ancora "valido"
- Dimensione: con milioni di cert, la CRL diventa enorme
- Distribuzione: ogni client deve scaricare la CRL aggiornata

### 2. OCSP — Online Certificate Status Protocol

Il client chiede in tempo reale "questo cert è ancora valido?":

```
Client → OCSP Responder: "Il cert con serial 0x3A7F2B è valido?"
OCSP Responder → Client: "No, revocato il 2026-04-05."
```

**Pro:** Tempo reale, risposte piccole.

**Contro:**
- Il OCSP responder deve essere sempre online (single point of failure)
- Privacy: il responder sa chi sta verificando chi
- OCSP Stapling risolve parzialmente (il server allegato la risposta OCSP al TLS handshake)

### 3. Database di revoca (approccio Cullis)

Il broker mantiene una tabella nel database:

```
┌──────────────────────────────────────────────────────────────┐
│  revoked_certs                                               │
├──────────────┬───────────┬─────────────┬────────────────────┤
│ serial_hex   │ org_id    │ revoked_at  │ reason             │
├──────────────┼───────────┼─────────────┼────────────────────┤
│ 3a7f2b...    │ acmebuyer │ 2026-04-05  │ key compromise     │
│ 1c8e9d...    │ widgets   │ 2026-04-07  │ employee terminated│
└──────────────┴───────────┴─────────────┴────────────────────┘
```

Ad ogni autenticazione, il broker controlla se il serial number del cert è nella tabella.

**Pro:** Tempo reale (check nel database, millisecondi), nessun servizio esterno, semplice.

**Contro:** Funziona solo per il broker (non è un protocollo standard che chiunque può consultare). Ma per Cullis va bene: il broker è l'unico punto di verifica.

---

## Come funziona in Cullis

### Il modello dati (`app/auth/revocation.py`)

```python
class RevokedCert(Base):
    __tablename__ = "revoked_certs"

    serial_hex     = Column(String(64),  primary_key=True)   # serial number in hex
    org_id         = Column(String(128), nullable=False)      # quale org
    revoked_at     = Column(DateTime,    nullable=False)      # quando revocato
    revoked_by     = Column(String(128), nullable=False)      # chi ha revocato (admin)
    reason         = Column(String(256), nullable=True)       # motivo (opzionale)
    cert_not_after = Column(DateTime,    nullable=False)      # scadenza originale del cert
    agent_id       = Column(String(256), nullable=True)       # quale agente (opzionale)
```

Ogni record ha il **serial number** del certificato in formato esadecimale. Questo è l'identificatore unico di ogni certificato x509.

### Il check durante l'autenticazione

In `app/auth/x509_verifier.py:181-182`, dopo aver verificato la catena ma PRIMA di verificare il JWT:

```python
serial_hex = format(agent_cert.serial_number, 'x')   # es: "3a7f2b1c9d..."
await check_cert_not_revoked(db, serial_hex)
```

La funzione `check_cert_not_revoked` è semplice:

```python
async def check_cert_not_revoked(db, serial_hex):
    result = await db.execute(
        select(RevokedCert).where(RevokedCert.serial_hex == serial_hex)
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(401, "Certificate has been revoked")
```

**Ordine delle operazioni nella verifica:**

```
1. Estrai cert dall'header x5c        ← chi sei?
2. Carica la CA dell'org dal DB        ← chi ti ha certificato?
3. Verifica la catena crittografica    ← il cert è autentico?
4. Verifica validità temporale         ← il cert è scaduto?
5. ★ CHECK REVOCA ★                    ← il cert è stato annullato?
6. Verifica firma JWT                  ← il JWT è firmato correttamente?
7. Verifica SPIFFE SAN                 ← l'identità corrisponde?
8. Verifica JTI (anti-replay)          ← il token è già stato usato?
```

Il check revoca avviene **prima** della verifica JWT. Questo è importante: anche se il JWT è perfettamente valido, se il cert è revocato → game over.

### Revocare un certificato

L'admin può revocare un cert via API:

```bash
# Revocare un certificato
curl -X POST http://broker:8000/admin/certs/revoke \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -d '{
    "serial_hex": "3a7f2b1c9d...",
    "org_id": "acmebuyer",
    "reason": "key compromise"
  }'
```

O dal dashboard web (pagina gestione agenti).

### La funzione `revoke_cert` — dettagli interessanti

```python
async def revoke_cert(db, serial_hex, org_id, cert_not_after, revoked_by, ...):
    # INSERT atomico con ON CONFLICT DO NOTHING
    # → Due revoche concurrent per lo stesso cert? Solo la prima ha effetto
    stmt = insert(RevokedCert).values(**values)
    stmt = stmt.on_conflict_do_nothing(index_elements=["serial_hex"])
    
    result = await db.execute(stmt)
    
    if result.rowcount == 0:
        raise HTTPException(409, "Certificate already revoked")
    
    # Lazy cleanup: rimuovi cert scaduti da più di 30 minuti
    # → Non serve tenere in lista un cert che è già scaduto naturalmente
    await db.execute(
        delete(RevokedCert).where(
            RevokedCert.cert_not_after < now - timedelta(minutes=30)
        )
    )
```

Tre dettagli notevoli:

1. **`ON CONFLICT DO NOTHING`**: evita race condition. Se due admin revocano lo stesso cert nello stesso istante, solo il primo inserisce. Il secondo riceve 409 Conflict.

2. **Lazy cleanup**: quando si revoca un cert, si fa pulizia dei cert scaduti. Un cert scaduto non serve più nella lista di revoca — è già invalido per scadenza. Il buffer di 30 minuti copre token emessi appena prima della scadenza.

3. **`cert_not_after`**: si salva la data di scadenza del cert revocato. Serve per il lazy cleanup — quando il cert sarebbe scaduto comunque, il record di revoca viene rimosso.

---

## Scenari di revoca

### Scenario 1: Chiave privata compromessa (URGENTE)

```
Timeline:
  T0: L'agente "acme::buyer" funziona normalmente
  T1: Scopri che qualcuno ha rubato la chiave privata
  T2: REVOCA IMMEDIATA
  T3: L'attaccante prova ad autenticarsi con la chiave rubata → 401
  T4: L'org genera un nuovo certificato per l'agente
  T5: L'agente si ri-autentica con il nuovo cert → funziona

L'attaccante ha una finestra tra T1 e T2.
Più veloce sei a revocare, meno danni può fare.
```

### Scenario 2: Dipendente che lascia l'azienda

```
L'org "acmebuyer" ha 5 agenti. Un dipendente che gestiva
l'agente "acme::inventory" lascia l'azienda.

Azioni:
  1. Revoca il cert di "acme::inventory"
  2. Genera un nuovo cert con una nuova chiave privata
  3. Configura il nuovo cert sull'agente
  4. Il vecchio cert (che il dipendente potrebbe avere) è inutile
```

### Scenario 3: Organizzazione che lascia il network

```
L'intera organizzazione "widgets" viene rimossa dal network.

Azioni:
  1. L'admin del broker cambia lo status dell'org a "revoked"
  2. Il check in x509_verifier.py: org.status != "active" → 403
  3. Tutti gli agenti di "widgets" vengono automaticamente bloccati
  4. Non serve revocare ogni singolo cert — lo status dell'org basta
```

---

## CRL vs OCSP vs DB — confronto per Cullis

| | CRL | OCSP | **Cullis (DB)** |
|---|---|---|---|
| Latenza | Ore/giorni | Millisecondi | **Millisecondi** |
| Disponibilità | Offline (file) | Serve un server | **Stesso DB del broker** |
| Scalabilità | File grande con molti cert | Carico sul responder | **Index SQL, O(1)** |
| Privacy | Chiunque vede la lista | Il responder sa chi chiede | **Solo il broker vede** |
| Standard | RFC 5280 | RFC 6960 | **Custom (ma bastante)** |
| Complessità | Media | Alta | **Bassa** |

Per Cullis, il DB approach è il più pragmatico: il broker è già l'unico punto di verifica, quindi una tabella nel suo database è tutto ciò che serve. Non c'è bisogno di un protocollo esterno.

---

## Riepilogo — cosa portarti a casa

- La **revoca** invalida un certificato prima della scadenza — fondamentale per incident response
- Tre approcci: **CRL** (lista periodica), **OCSP** (query in tempo reale), **database** (Cullis)
- Cullis usa una tabella `revoked_certs` nel DB del broker — check a ogni autenticazione
- Il check avviene **prima** della verifica JWT — un cert revocato è bloccato immediatamente
- `ON CONFLICT DO NOTHING` previene race condition su revoche concurrent
- **Lazy cleanup**: i cert scaduti vengono rimossi dalla lista (con 30 min di buffer)
- Tre livelli di revoca: singolo cert, singolo agente, intera organizzazione (via status)
- Codice: `app/auth/revocation.py` (modello + logica), check in `app/auth/x509_verifier.py:181`

---

*Prossimo capitolo: [09 — JWT — JSON Web Token](09-jwt.md) — il token che il broker emette dopo l'autenticazione*
