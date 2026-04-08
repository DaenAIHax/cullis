# Capitolo 31 — MCP — Model Context Protocol

> *"Un LLM senza strumenti e' come un chirurgo senza mani: sa cosa fare, ma non puo' farlo."*

---

## Cos'e' MCP — spiegazione da bar

Immagina un elettricista che arriva a casa tua. Sa come riparare un impianto elettrico, ma ha bisogno dei suoi attrezzi: tester, pinze, cacciavite. Se non li ha, puo' solo dirti cosa fare — ma non puo' farlo lui.

Un LLM (come Claude, GPT, ecc.) e' uguale: sa ragionare, sa pianificare, ma senza **strumenti** non puo' agire nel mondo reale. Non puo' mandare email, non puo' interrogare database, non puo' parlare con altri agenti.

**MCP (Model Context Protocol)** e' lo standard che risolve questo problema. E' il protocollo con cui dai strumenti (tools) a un LLM. Definito da Anthropic, e' aperto e adottato da molti client.

**Analogia:** MCP e' come una presa di corrente universale. Se il tuo elettrodomestico (LLM) ha una spina MCP, puoi attaccarlo a qualsiasi presa MCP (server) e funziona — non importa chi ha fabbricato l'elettrodomestico o la presa.

---

## Come funziona MCP — il modello mentale

```
┌─────────────────┐         ┌─────────────────┐
│   LLM Client    │  MCP    │   MCP Server     │
│ (Claude, GPT)   │◀═══════▶│ (il tuo codice)  │
│                 │         │                  │
│ "Quali tool hai?"│────────▶│ "Ho 10 tool"     │
│                 │◀────────│ [lista tool]      │
│                 │         │                  │
│ "Usa cullis_send│────────▶│ → chiama SDK     │
│  con msg='ciao'"│         │ → ritorna result │
│                 │◀────────│ "Messaggio inviato"│
└─────────────────┘         └─────────────────┘
```

Il flusso e' semplice:

1. **Il client chiede** al server "quali tool hai?"
2. **Il server risponde** con una lista di tool, ciascuno con nome, descrizione e schema dei parametri
3. **L'LLM decide** quale tool usare in base al contesto della conversazione
4. **Il client chiama** il tool sul server con i parametri scelti dall'LLM
5. **Il server esegue** il tool e ritorna il risultato
6. **L'LLM interpreta** il risultato e risponde all'utente

L'LLM non sa come funziona il tool internamente — vede solo il nome, la descrizione e i parametri. E' come un manager che delega: "fai questa cosa e dimmi com'e' andata".

---

## I tre trasporti MCP

MCP supporta tre modi per far comunicare client e server:

### 1. stdio — comunicazione via standard input/output

Il client lancia il server come processo figlio e parlano via stdin/stdout. E' il modo piu' semplice e sicuro: nessuna porta di rete aperta.

```
Client ──stdin──▶ Server
Client ◀─stdout── Server
```

**Analogia:** Due persone che parlano attraverso un tubo pneumatico — diretto, privato, niente intercettazioni.

### 2. SSE (Server-Sent Events) — streaming su HTTP

Il server espone un endpoint HTTP. Il client si connette e riceve eventi in streaming. Usato per deployment remoti.

### 3. HTTP — request/response classico

Semplice HTTP POST/GET. Usato per integrazioni REST standard.

**Cullis usa stdio** come trasporto predefinito — il piu' sicuro e il piu' semplice da configurare.

---

## Tool definition: come si descrive uno strumento

Ogni tool MCP ha tre componenti:

1. **Nome** — identificatore unico (es. `cullis_send`)
2. **Descrizione** — testo che l'LLM legge per capire quando usare il tool
3. **Schema parametri** — JSON Schema che definisce i parametri accettati

Esempio dal codice Cullis:

```python
@mcp.tool()
def cullis_send(message: str) -> str:
    """Send an E2E-encrypted message in the active session.

    Args:
        message: The message text to send
    """
```

L'LLM vede:

```json
{
  "name": "cullis_send",
  "description": "Send an E2E-encrypted message in the active session.",
  "parameters": {
    "type": "object",
    "properties": {
      "message": { "type": "string", "description": "The message text to send" }
    },
    "required": ["message"]
  }
}
```

**La descrizione e' cruciale:** e' cio' che l'LLM usa per decidere *quando* chiamare il tool. Una descrizione vaga = tool mai usato (o usato a sproposito).

---

## cullis_sdk/mcp_server.py — i 10 tool MCP di Cullis

Il file `cullis_sdk/mcp_server.py` espone 10 tool che trasformano qualsiasi LLM compatibile MCP in un agente Cullis completo. Zero righe di codice da scrivere.

```
┌──────────────────────────────────────────────────────┐
│                 Cullis MCP Server                    │
│                                                      │
│  Lifecycle:                                          │
│  ┌──────────────┐                                    │
│  │cullis_connect │ ← primo da chiamare               │
│  └──────────────┘                                    │
│                                                      │
│  Discovery:                                          │
│  ┌────────────────┐                                  │
│  │cullis_discover  │ ← cerca agenti per capability   │
│  └────────────────┘                                  │
│                                                      │
│  Sessioni:                                           │
│  ┌───────────────────┐ ┌───────────────────────┐     │
│  │cullis_open_session │ │cullis_accept_session  │     │
│  └───────────────────┘ └───────────────────────┘     │
│  ┌────────────────────┐ ┌──────────────────────┐     │
│  │cullis_close_session │ │cullis_select_session │     │
│  └────────────────────┘ └──────────────────────┘     │
│  ┌──────────────────────┐                            │
│  │cullis_list_sessions   │                            │
│  └──────────────────────┘                            │
│                                                      │
│  Messaggi:                                           │
│  ┌────────────┐ ┌───────────────────────┐            │
│  │cullis_send  │ │cullis_check_responses │            │
│  └────────────┘ └───────────────────────┘            │
│  ┌───────────────────┐                               │
│  │cullis_check_pending│                               │
│  └───────────────────┘                               │
└──────────────────────────────────────────────────────┘
```

### Tabella riassuntiva dei tool

| Tool | Cosa fa | Parametri |
|------|---------|-----------|
| `cullis_connect` | Login al broker | broker_url, agent_id, org_id, cert/key path |
| `cullis_discover` | Cerca agenti | q, capabilities, org_id, pattern |
| `cullis_open_session` | Apri sessione sicura | target_agent_id, target_org_id, capabilities |
| `cullis_accept_session` | Accetta sessione in arrivo | session_id (anche parziale) |
| `cullis_close_session` | Chiudi sessione attiva | (nessuno — usa sessione attiva) |
| `cullis_select_session` | Cambia sessione attiva | session_id (anche parziale) |
| `cullis_list_sessions` | Lista tutte le sessioni | (nessuno) |
| `cullis_send` | Invia messaggio E2E | message |
| `cullis_check_responses` | Leggi messaggi ricevuti | (nessuno) |
| `cullis_check_pending` | Controlla richieste sessione | (nessuno) |

### Il pattern "sessione attiva"

L'MCP server mantiene lo stato della sessione attiva internamente. Quando apri o accetti una sessione, diventa la sessione attiva. `cullis_send` e `cullis_check_responses` operano sempre sulla sessione attiva — l'LLM non deve passare il session_id ogni volta.

```python
# Stato globale nel modulo
_active_session: str | None = None
_active_peer: str | None = None
```

**Analogia:** E' come una telefonata. Quando chiami qualcuno, la linea e' "attiva". Parli e ascolti su quella linea. Se vuoi cambiare interlocutore, devi prima riagganciare o mettere in attesa.

### Il flusso Vault (opzionale)

`cullis_connect` supporta anche credenziali da HashiCorp Vault:

```
Se VAULT_ADDR e VAULT_TOKEN sono settati:
  → scarica cert_pem e private_key_pem da Vault
  → chiama login_from_pem()

Altrimenti:
  → usa cert_path e key_path da file
  → chiama login()
```

> **In Cullis:** guarda `cullis_sdk/mcp_server.py` per tutti i 10 tool.

---

## Configurazione per Claude Desktop / Claude Code

Per usare il Cullis MCP Server con Claude, basta configurarlo nel file di configurazione MCP.

### Claude Code (claude_desktop_config.json / settings)

```json
{
  "mcpServers": {
    "cullis": {
      "command": "python",
      "args": ["-m", "cullis_sdk.mcp_server"],
      "env": {
        "BROKER_URL": "https://broker.cullis.tech",
        "AGENT_ID": "myorg::assistant",
        "ORG_ID": "myorg",
        "AGENT_CERT_PATH": "/path/to/cert.pem",
        "AGENT_KEY_PATH": "/path/to/key.pem"
      }
    }
  }
}
```

### Con Vault (nessun file chiave su disco)

```json
{
  "mcpServers": {
    "cullis": {
      "command": "python",
      "args": ["-m", "cullis_sdk.mcp_server"],
      "env": {
        "BROKER_URL": "https://broker.cullis.tech",
        "AGENT_ID": "myorg::assistant",
        "ORG_ID": "myorg",
        "VAULT_ADDR": "https://vault.internal:8200",
        "VAULT_TOKEN": "hvs.your-vault-token"
      }
    }
  }
}
```

**Dopo la configurazione, Claude puo' direttamente:**

- "Cerca agenti che vendono componenti elettronici"
- "Apri una sessione con chipfactory::sales"
- "Manda un ordine per 500 GPU A100"
- "Controlla se ci sono risposte"

Claude chiamera' automaticamente i tool MCP appropriati. Tu non scrivi una riga di codice.

---

## Il paradigma: zero code agent

Questo e' il punto chiave dell'MCP server Cullis:

```
PRIMA (senza MCP):
  Sviluppatore → scrive codice Python → usa SDK → agente funziona

DOPO (con MCP):
  Admin → configura JSON → LLM usa tool → agente funziona
```

**Qualsiasi LLM compatibile MCP diventa un agente Cullis.** Non solo Claude — qualsiasi client che implementa MCP puo' usare questi tool.

```
┌────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Claude Code   │     │                  │     │              │
│  Claude Desktop│     │   Cullis MCP     │     │   Cullis     │
│  Cursor        │────▶│   Server         │────▶│   Broker     │
│  VS Code + MCP │     │ (stdio transport)│     │              │
│  Qualsiasi LLM │     │                  │     │              │
└────────────────┘     └──────────────────┘     └──────────────┘
      client               server                  backend
```

**Analogia:** E' come un traduttore simultaneo. L'LLM parla in linguaggio naturale, il traduttore (MCP server) converte in chiamate API, e il broker risponde. L'LLM non sa nulla di crittografia, certificati o sessioni — parla e basta.

---

## Come funziona sotto il cofano

Quando Claude dice "manda un messaggio a chipfactory::sales", ecco cosa succede:

```
1. Claude decide: "devo usare cullis_send"
   ↓
2. Claude Code chiama: cullis_send(message="Ordine 500 GPU A100")
   ↓
3. MCP Server:
   - verifica che _active_session esiste
   - chiama client.send() con payload e2e
   - CullisClient gestisce firma, crittografia, DPoP
   ↓
4. Broker riceve il messaggio crittografato
   ↓
5. MCP Server ritorna: "Message sent to chipfactory::sales."
   ↓
6. Claude risponde all'utente: "Ho inviato l'ordine per 500 GPU A100."
```

Tutto il flusso crittografico (inner sig, E2E encrypt, outer sig, DPoP proof) e' completamente trasparente — l'LLM vede solo stringhe di testo.

---

## Lancio standalone

L'MCP server puo' anche essere lanciato direttamente:

```bash
# Con variabili d'ambiente
export BROKER_URL="https://broker.cullis.tech"
export AGENT_ID="myorg::assistant"
export ORG_ID="myorg"
export AGENT_CERT_PATH="certs/assistant.pem"
export AGENT_KEY_PATH="certs/assistant-key.pem"

python -m cullis_sdk.mcp_server
```

Il server parte in modalita' stdio e resta in ascolto per chiamate MCP.

---

## Libreria usata: FastMCP

Il server e' costruito con `FastMCP` di Anthropic — il framework ufficiale per creare MCP server in Python:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Cullis",
    instructions="Connect to the Cullis federated agent trust network. "
    "Discover agents, open secure sessions, exchange E2E-encrypted messages.",
)

@mcp.tool()
def cullis_connect(...) -> str:
    ...
```

`FastMCP` gestisce:
- Registrazione automatica dei tool dal decoratore `@mcp.tool()`
- Generazione degli schema JSON dai type hint Python
- Trasporto stdio (o SSE se configurato)
- Serializzazione/deserializzazione dei messaggi MCP

---

## Riepilogo — cosa portarti a casa

- **MCP** e' il protocollo standard per dare strumenti agli LLM — definito da Anthropic, adottato da molti
- **Tre trasporti**: stdio (locale, sicuro), SSE (streaming), HTTP (REST) — Cullis usa stdio
- **10 tool** coprono l'intero ciclo: connect, discover, sessioni, messaggi, pending
- **Configurazione JSON** in Claude Desktop/Code — zero codice per avere un agente Cullis
- **Qualsiasi LLM compatibile MCP** puo' diventare un agente Cullis — non solo Claude
- Il server MCP e' un **traduttore**: linguaggio naturale dentro, chiamate SDK fuori
- Credenziali da file o da **Vault** — nessun segreto hardcoded

---

*Prossimo capitolo: [32 — TypeScript SDK](32-typescript-sdk.md) — BrokerClient per Node.js*
