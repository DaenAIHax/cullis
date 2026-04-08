# Capitolo 25 — Nginx e TLS

> *"Il buttafuori del locale controlla i documenti, perquisisce le borse, e poi ti accompagna al bancone. Tu non parli mai direttamente con il barista dalla strada."*

---

## Cos'e un Reverse Proxy — spiegazione da bar

Immagina un ristorante di lusso. Non entri dalla cucina — c'e un **maitre** all'ingresso che:
1. Controlla la prenotazione (autenticazione TLS)
2. Ti da un tavolo (routing)
3. Prende l'ordine e lo porta in cucina (proxy)
4. Ti riporta il piatto (risposta)

Tu non sai nemmeno dove sia la cucina. Il maitre **nasconde** il backend e **protegge** l'accesso.

Nginx e quel maitre per Cullis:

```
Internet                          Rete interna Docker
    |                                   |
    v                                   v
[Client]  ──HTTPS──>  [Nginx :8443]  ──HTTP──>  [Broker :8000]
                        |
                   TLS terminato qui
                   Security headers
                   WebSocket upgrade
                   Rate limiting (opzionale)
```

Il client parla HTTPS (cifrato). Nginx decifra, aggiunge header, e inoltra in HTTP al broker sulla rete Docker interna (sicura, non esposta).

---

## TLS — il lucchetto del browser

### Cos'e TLS

TLS (Transport Layer Security) cifra la comunicazione tra client e server. E il lucchetto che vedi nel browser.

```
Senza TLS:                          Con TLS:

Client → "password=abc123" → Server   Client → "x8#kL!m@..." → Server
                                              (cifrato, illeggibile)
Chiunque intercetti → legge tutto     Chiunque intercetti → vede spazzatura
```

### L'handshake TLS (semplificato)

```
Client                                    Server (Nginx)
  |                                          |
  |──── ClientHello (ciphers supportate) ──→ |
  |                                          |
  | ←── ServerHello + certificato ────────── |
  |                                          |
  |  (verifica certificato con CA root)      |
  |                                          |
  |──── Pre-master secret (cifrato) ──────→  |
  |                                          |
  | ←→  Derivano la session key ←→           |
  |                                          |
  |══════ Traffico cifrato AES ═════════════ |
```

Il certificato del server dimostra: "sono davvero broker.cullis.io, e la CA X lo garantisce".

---

## TLS Termination — Nginx decifra per il broker

Il broker FastAPI non gestisce TLS direttamente. Nginx lo fa per lui:

```
HTTPS :8443         HTTP :8000
    |                   |
    v                   v
[Nginx]  ──────────> [Broker]
    |
    +-- Decifra TLS
    +-- Aggiunge X-Forwarded-For (IP reale)
    +-- Aggiunge X-Forwarded-Proto (https)
    +-- Passa in HTTP sulla rete Docker
```

Perche separare?
- **Performance**: Nginx e ottimizzato per TLS (usa OpenSSL in C)
- **Semplicita**: il broker non deve gestire certificati
- **Flessibilita**: puoi cambiare certificato senza riavviare il broker
- **Sicurezza**: la rete Docker interna e gia isolata

---

## Configurazione Nginx di Cullis

Il file `nginx/nginx.conf`:

```nginx
server {
    listen 443 ssl;
    server_name localhost;

    # ── Certificati TLS ──
    ssl_certificate     /etc/nginx/certs/server.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;        # solo protocolli moderni
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;   # solo cipher forti
    ssl_prefer_server_ciphers on;                 # il server sceglie il cipher

    # ── Security headers ──
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # ── Limite dimensione richiesta ──
    client_max_body_size 2m;

    # ── WebSocket ──
    location /v1/broker/ws {
        proxy_pass http://broker:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;     # 24 ore — le WS devono restare aperte
    }

    # ── Tutto il resto ──
    location / {
        proxy_pass http://broker:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

### proxy_pass — l'inoltro

`proxy_pass http://broker:8000` manda la richiesta al container `broker` sulla porta 8000. `broker` e un nome DNS Docker, risolto automaticamente.

### WebSocket Upgrade

HTTP e request-response. WebSocket e bidirezionale e persistente. Per passare da HTTP a WebSocket serve un "upgrade":

```
Client → Nginx:
  GET /v1/broker/ws
  Upgrade: websocket
  Connection: Upgrade

Nginx → Broker:
  proxy_http_version 1.1;                    # HTTP/1.1 richiesto per upgrade
  proxy_set_header Upgrade $http_upgrade;    # passa l'header Upgrade
  proxy_set_header Connection "upgrade";     # dice al broker di fare upgrade
  proxy_read_timeout 86400;                  # non chiudere dopo 60s default!
```

Senza `proxy_read_timeout 86400`, Nginx chiuderebbe la connessione WebSocket dopo 60 secondi di silenzio.

---

## Certificati — chi firma cosa

### Sviluppo: self-signed

`deploy_broker.sh` genera un certificato autofirmato:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout nginx/certs/server-key.pem \
    -out nginx/certs/server.pem \
    -days 365 \
    -subj "/CN=localhost/O=ATN Dev" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Il browser mostrera un avviso ("certificato non attendibile") perche non e firmato da una CA riconosciuta. Per sviluppo va bene.

### Produzione: Let's Encrypt

`deploy_broker.sh --prod` supporta Let's Encrypt (certificati gratuiti e riconosciuti):

```
1. Nginx parte con cert temporaneo self-signed
2. Certbot esegue la challenge ACME (prova che possiedi il dominio)
3. Let's Encrypt emette il certificato reale
4. Nginx viene ricaricato con il cert reale
5. Cron job rinnova automaticamente ogni 12 ore
```

### Produzione: Enterprise CA

Se l'organizzazione ha la propria CA interna:

```bash
./deploy_broker.sh --prod
# "Use Let's Encrypt?" → No
# Path to certificate: /path/to/company-cert.pem
# Path to private key: /path/to/company-key.pem
```

---

## Security Headers — la difesa in profondita

Cullis aggiunge header di sicurezza sia da Nginx che dal middleware FastAPI:

### HSTS (HTTP Strict Transport Security)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Dice al browser: "per i prossimi 365 giorni, non provare nemmeno a connetterti in HTTP — vai direttamente in HTTPS". Previene attacchi di downgrade.

### X-Frame-Options

```
X-Frame-Options: DENY
```

Impedisce che il sito venga incluso in un iframe. Previene attacchi clickjacking.

### X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

Impedisce al browser di "indovinare" il tipo di file. Se il server dice "questo e JSON", il browser non prova a interpretarlo come HTML (prevenzione XSS).

### Content-Security-Policy (CSP)

Aggiunto dal middleware FastAPI per le pagine dashboard:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none'
```

Dice al browser: "esegui solo script dal nostro dominio (+ Tailwind CDN + HTMX), non caricare risorse da altri domini, non permettere embedding in frame".

### Permissions-Policy

```
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Disabilita API browser non necessarie. Un trust broker non ha bisogno della webcam.

---

## Il flusso completo — dalla richiesta alla risposta

```
1. Client manda HTTPS a :8443
         |
2. Nginx decifra TLS
         |
3. Nginx controlla: e un WebSocket?
         |
    Si → upgrade + proxy_pass http://broker:8000
    No → proxy_pass http://broker:8000
         |
4. Nginx aggiunge headers:
     X-Real-IP: IP del client
     X-Forwarded-For: catena proxy
     X-Forwarded-Proto: https
         |
5. Broker (FastAPI) processa la richiesta
     - Uvicorn legge X-Forwarded-For (--proxy-headers)
     - Middleware aggiunge security headers
     - Router gestisce la logica
         |
6. Broker risponde HTTP
         |
7. Nginx aggiunge HSTS, X-Frame-Options, nosniff
         |
8. Nginx cifra la risposta in TLS
         |
9. Client riceve HTTPS
```

---

## Docker Compose — Nginx nel broker stack

```yaml
nginx:
  image: nginx:alpine
  ports:
    - "8443:443"      # HTTPS esposto all'esterno
    - "80:80"         # HTTP → redirect a HTTPS
  volumes:
    - ./nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    - ./nginx/certs:/etc/nginx/certs:ro
  depends_on:
    broker: { condition: service_healthy }
```

Nginx parte **dopo** che il broker e healthy. I certificati e la configurazione sono montati in read-only.

---

## Riepilogo — cosa portarti a casa

- **Nginx** e il reverse proxy che sta davanti al broker: termina TLS, inoltra HTTP, gestisce WebSocket
- **TLS termination**: Nginx decifra HTTPS sulla porta 8443, il broker riceve HTTP sulla porta 8000
- **WebSocket upgrade** richiede `proxy_http_version 1.1`, header Upgrade, e `proxy_read_timeout 86400`
- **proxy_pass** usa il DNS Docker interno (`http://broker:8000`)
- Certificati: **self-signed** per dev, **Let's Encrypt** o **enterprise CA** per produzione
- **Security headers**: HSTS (forza HTTPS), X-Frame-Options (anti-clickjacking), nosniff, CSP
- Il middleware FastAPI aggiunge ulteriori header (CSP per dashboard, DPoP-Nonce per API)
- `deploy_broker.sh` gestisce automaticamente la generazione certificati e la configurazione Nginx

---

**Prossimo capitolo:** [26 — PostgreSQL](26-postgresql.md)
