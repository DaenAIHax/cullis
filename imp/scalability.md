Mentre a livello potenza computazionale? Come faccio a capire se avere nel neteork 20 agenti funziona o c'è un collo di bottiglia?

Ottima domanda da vero architetto di sistema. Ti rassicuro subito su un numero: 20 agenti per Cullis sono una passeggiata. L'architettura asincrona (FastAPI + asyncpg) regge tranquillamente migliaia di agenti concorrenti senza battere ciglio.

Tuttavia, la tua domanda metodologica è perfetta: "Come faccio a non tirare a indovinare e a vedere con i miei occhi dove il sistema fatica?" e "Se scalassi a 10.000 agenti, cosa si romperebbe per primo?"

Ecco come si risponde a queste due domande nell'architettura di Cullis.

1. Come fai a capirlo: OpenTelemetry e Jaeger 📈
In Cullis non si guardano i log di testo per capire le performance. Si usa l'Osservabilità (Capitolo 28).

Tutto il codice del Broker è strumentato con OpenTelemetry. Questo significa che ogni volta che un agente fa una richiesta (es. manda un messaggio), il sistema genera una Trace (traccia).

Se apri la dashboard di Jaeger (sulla porta 16686 del tuo stack Docker), vedrai un grafico a cascata (waterfall) per quella singola richiesta. Jaeger ti dirà esattamente:

Tempo totale: 120ms

↳ Controllo firma DPoP: 5ms

↳ Lettura JTI da Redis: 2ms

↳ Query PostgreSQL per policy: 45ms

↳ Chiamata al Webhook PDP dell'altra org: 65ms

Se c'è un collo di bottiglia, lo vedi all'istante: la "barra" di quell'operazione in Jaeger sarà lunghissima e rossa.

2. Dove sono i veri colli di bottiglia architetturali? 🚦
Se portassimo il sistema sotto stress estremo, ecco i 3 punti dove Cullis farebbe da imbuto (ed è stato progettato sapendo di questi compromessi):

A. L'Audit Ledger Crittografico (Il vero limite by-design)
Ricordi che l'audit log usa una Hash Chain (ogni riga contiene l'hash crittografico della riga precedente per impedire manomissioni)?.
Questo è il collo di bottiglia computazionale numero uno. Per calcolare l'hash in sequenza esatta, gli inserimenti nel database devono essere serializzati. In Cullis c'è un lock asincrono (_audit_chain_lock). Se 5.000 agenti fanno operazioni contemporaneamente, le loro scritture di audit dovranno mettersi in fila indiana.

B. Saturazione del Connection Pool del Database
FastAPI può accettare 10.000 richieste concorrenti perché è asincrono. Ma se il connection pool di PostgreSQL (gestito da SQLAlchemy) è impostato a 20 connessioni massime, la 21esima richiesta dovrà aspettare che una delle prime 20 finisca di usare il database.

C. Il carico sulla CPU per la crittografia
La matematica asimmetrica è "pesante". Per risolvere questo, Cullis usa un trucco elegante:

Se il Broker dovesse verificare enormi firme RSA per ogni singola API call, la CPU andrebbe al 100% quasi subito.

Ecco perché Cullis usa Curve Ellittiche (EC P-256) per il token binding (DPoP). Le firme sono leggerissime da generare e velocissime da verificare, riducendo drasticamente il collo di bottiglia sulla CPU.

D. Il limite sulle connessioni WebSocket
Mantenere connessioni sempre aperte occupa memoria. Per evitare che un'organizzazione monopolizzi il broker (Resource Exhaustion), c'è un rate limit architetturale rigido: massimo 100 connessioni WebSocket attive per ogni organizzazione.

Come scalare quando serve?
Quando un solo server non basta più, avvii 5 copie (worker) del Broker dietro a Nginx. Non si pesteranno i piedi perché usano Redis come memoria condivisa per mettersi d'accordo su chi sta esaurendo il rate limit e per passarsi i messaggi WebSocket tra un worker e l'altro (Redis Pub/Sub).

Sei pronto a disegnare l'ultimo grande pezzo dell'infrastruttura (magari proprio la messaggistica asincrona o il proxy aziendale), o vuoi approfondire come OpenTelemetry raccoglie queste metriche?

Quindi dovrei deployare piu broker o redis gia lo fa?

Devi deployare tu più istanze del Broker. Redis non esegue il codice o "clona" il broker, ma è il componente magico che permette a più broker di lavorare insieme come se fossero uno solo.

Usiamo un'analogia: immagina il Broker come i cassieri di un supermercato. Se c'è troppa fila (cioè troppi agenti che fanno richieste), tu proprietario devi aprire più casse (aggiungere copie del Broker).
Redis è l'interfono e il gestionale centrale che tutti i cassieri condividono.

Ecco esattamente come funziona il deployment su larga scala in Cullis:

1. Come fai a deployare più Broker? (Horizontal Scaling)
In produzione, invece di lanciare un solo container Docker del broker, usi un orchestratore (come Kubernetes o Docker Swarm/Compose) per lanciare, ad esempio, 5 copie identiche del container del broker.

Davanti a questi 5 container c'è il Load Balancer (Nginx). Quando un agente fa una richiesta HTTP, Nginx fa "testa o croce" e la manda al Worker 1, la richiesta successiva al Worker 2, e così via.

2. Perché ti serve Redis in questo scenario?
Visto che ora hai 5 server broker separati, ognuno ha la sua memoria RAM isolata. Senza Redis, il sistema andrebbe in pezzi. Ecco i 3 poteri di Redis in un setup multi-broker:

A. Consegnare i messaggi tra server diversi (Pub/Sub per WebSocket):
Mettiamo che l'Agente Alice sia connessa via WebSocket al Broker 1, e l'Agente Bob sia connesso al Broker 2.
Se Alice manda un messaggio a Bob, il Broker 1 non sa come raggiungere Bob (non è nella sua RAM). Quindi il Broker 1 "urla" il messaggio su un canale Redis. Il Broker 2, che è in ascolto su Redis, lo sente e lo inoltra a Bob.

B. Rate Limiting Globale:
Se il limite è "10 richieste al minuto", e l'attaccante manda 5 richieste al Broker 1 e 5 al Broker 2, come fanno a sapere che il limite è stato raggiunto? Salvano il contatore su Redis. Così il limite è globale, non per singolo server.

C. Protezione Anti-Replay (JTI Blacklist):
Se un attaccante ruba un token DPoP e prova a usarlo contemporaneamente sul Broker 1 e sul Broker 2, entrambi vanno a scrivere il seriale (JTI) su Redis. Redis è "atomico", quindi bloccherà il secondo tentativo istantaneamente.

In sintesi per il tuo diagramma:
Disegna un blocco centrale chiamato "Nginx/Load Balancer" che divide il traffico verso tre scatolette identiche chiamate "Broker Worker". Poi, disegna una linea che collega tutti e tre i worker a una singola scatola "Redis" in basso (la loro memoria condivisa), e un'altra linea che li collega al "Database PostgreSQL" (il loro archivio permanente a lungo termine).

Ottimo pero se stanno tutti insieme dietro a nginx, se invece volessi collegare due broker che si trovano uno a milano e l'altro a new york? Basta il trust tra i due che si fidano?

Hai appena toccato il Santo Graal dell'architettura di rete: il passaggio dallo scaling orizzontale (stesso datacenter) alla distribuzione geografica multi-regionale.

La risposta breve è: no, non basta solo dirsi "ci fidiamo". In un'architettura Zero Trust basata su PKI, la fiducia deve essere espressa matematicamente e l'instradamento dei messaggi deve essere fisicamente possibile.

Se vuoi espandere il tuo diagramma per includere Milano e New York, devi decidere quale di questi due modelli architetturali vuoi usare per Cullis. Sono molto diversi:

Modello A: Unico Trust Domain (Geo-distribuito) 🌍
In questo scenario, hai un solo "network Cullis" globale, ma i server fisici sono sparsi.

La Fiducia: Esiste una sola Broker CA (Livello 0). Sia i worker di Milano che quelli di New York usano esattamente le stesse chiavi per verificare i token DPoP e i certificati degli agenti.

Il Problema (Latenza e Stato): Se un agente a Milano manda un messaggio a un agente a New York, i due worker del broker devono potersi parlare. Questo significa che devono condividere lo stesso database PostgreSQL e lo stesso cluster Redis (magari usando versioni Enterprise geo-replicate). Se la connessione transoceanica cade, i worker perdono la sincronia.

Modello B: Federazione Multi-Broker (Cross-Domain) 🤝
Questo è lo scenario più avanzato e resiliente. Milano ha il suo sistema completo (Broker CA "Europa", suo DB, suo Redis). New York ha il suo (Broker CA "America", suo DB, suo Redis). Sono due Trust Domain completamente indipendenti.

La Fiducia (Cross-Certification): Per farli parlare, non basta una stretta di mano. Serve la Cross-Certification PKI. La CA di Milano firma il certificato della CA di New York, e la CA di New York firma quello di Milano. In questo modo, un agente di Milano riconosce matematicamente come validi i certificati emessi a New York, unendo di fatto le due catene di fiducia.

Il Routing: I broker devono implementare un protocollo di Server-to-Server federation (come fa l'email con SMTP o Mastodon con ActivityPub). Se il Broker di Milano riceve un messaggio per spiffe://ny.local/sony/agent, sa che non deve cercarlo nel suo database locale, ma deve inoltrare il pacchetto cifrato al Broker di New York.

Allo stato attuale del design che abbiamo discusso, Cullis usa un modello a Singolo Broker Centrale (Control Plane Neutrale) con le Organizzazioni che si federano attorno ad esso. Le singole organizzazioni gestiscono il loro "data plane" (le loro chiavi e le loro policy tramite il PDP).

Per i tuoi disegni, vuoi mappare l'architettura mantenendo un singolo Broker neutrale (magari scalato dietro Nginx come visto prima), oppure vuoi progettare il sistema per supportare fin dall'inizio il Modello B con routing tra Broker diversi?

Eh si quindi in pratica potrei avere 5 broker dietro nginx a milano e 5 broker dietro ngnix a newyork con certificati firmati

Esattamente! Hai centrato il bersaglio al 100%. 🎯

Questo è lo scenario enterprise per eccellenza (il Modello B: Federazione Multi-Broker). Hai due ecosistemi completamente autonomi che decidono di "stringersi la mano" crittograficamente, creando un ponte tra l'Europa e l'America senza condividere i database.

Se dovessi disegnare questo schema sulla lavagna, avresti due grandi "isole" identiche collegate da un singolo ponte. Ecco come funzionano le isole e il ponte:

1. L'Isola di Milano 🇮🇹
Ingresso: 1 Load Balancer (Nginx)

Motore: 5 copie del Broker (Worker)

Stato: 1 Cluster Redis (per il rate limit locale e i WebSocket di Milano) + 1 Database PostgreSQL (per le sessioni e l'audit degli agenti europei).

Identità: La sua Broker CA (Milano).

2. L'Isola di New York 🇺🇸
Ha la sua copia esatta di tutto: Nginx, 5 Worker, il suo Redis, il suo PostgreSQL.

Identità: La sua Broker CA (New York).

Se la connessione internet tra i due continenti cade, gli agenti di Milano continuano a parlarsi tra loro senza problemi, e lo stesso fanno quelli di New York. Questa è la vera resilienza.

3. Il Ponte: Cross-Certification e Routing 🌉
Come fanno a parlarsi un agente di Milano e uno di New York se i database sono separati? Qui entra in gioco il protocollo.

A. La Fiducia (Cross-Certification):
Gli amministratori dei due sistemi si scambiano i certificati CA di "Livello 0".
La CA di Milano appone la sua firma digitale sul certificato della CA di New York, e viceversa. È come se l'Italia e gli Stati Uniti firmassero un trattato per riconoscere reciprocamente i passaporti.

B. Il Routing (SPIFFE è il CAP digitale):
Ricordi lo SPIFFE ID di cui parlavamo? Funziona esattamente come un indirizzo email o postale.
Se un agente invia un messaggio a spiffe://ny.cullis/sony/supplier:

Il worker di Milano legge l'indirizzo. Vede che il dominio è ny.cullis.

Sa che non deve cercare questo agente nel suo database PostgreSQL di Milano.

Prende il pacchetto (che è già cifrato End-to-End) e lo instrada al Load Balancer di New York tramite una connessione TLS server-to-server.

New York riceve il pacchetto, verifica la firma (perché si fida della CA di Milano), e lo consegna all'agente supplier usando il suo Redis locale.

A questo punto, hai un'ottima mappa mentale di tutta l'infrastruttura di rete, di come si scala e di come si fida crittograficamente.

Per completare i tuoi disegni architetturali, ci mancano i dettagli "interni" di come i dati viaggiano o vengono salvati. Quale di questi tre flussi logici vuoi mappare ora?

L'End-to-End Encryption (E2E): Disegnare come un messaggio viene "impacchettato" con doppia firma e cifratura AES-GCM + RSA prima di lasciare l'agente.

L'Audit Ledger Crittografico: Disegnare come il database PostgreSQL concatena gli hash (la Hash Chain) per rendere le operazioni a prova di manomissione.

L'MCP Proxy: Mappare come un'azienda installa questo componente interno per nascondere tutta questa complessità ai suoi poveri agenti AI.

Quindi quanto carico sopporta un broker e quanto 5 broker?

Per darti dei numeri concreti (basati sui benchmark tipici di uno stack FastAPI + PostgreSQL + Redis), dobbiamo dividere il "carico" in due categorie: le connessioni passive (agenti collegati in attesa) e le operazioni attive (agenti che inviano messaggi o fanno login e scrivono sul database).

Ecco come si comportano 1 singolo Broker rispetto a 5 Broker.

1. Un Singolo Broker (1 Worker)
Un singolo container Python/FastAPI è un eccellente "vigile urbano" grazie all'architettura asincrona (ASGI), ma ha limiti fisici di CPU e connessioni al database.

Connessioni WebSocket (Passive): Regge tranquillamente 10.000+ connessioni simultanee. Tuttavia, ricorda che Cullis impone un limite architetturale di massima sicurezza di 100 connessioni per organizzazione per evitare monopoli. Quindi, se hai 100 organizzazioni diverse, 1 broker le gestisce senza sudare.

Crittografia e Letture (Attive): Grazie all'uso delle curve ellittiche (EC P-256) per il DPoP, un singolo worker può validare token e firme a un ritmo di 500 - 1.000 RPS (Richieste Per Secondo).

Scritture (Il limite): Se le operazioni richiedono di scrivere su PostgreSQL (es. registrare una nuova sessione o l'audit di un messaggio), il limite scende. Con un tipico pool di 20 connessioni al DB, il broker gestirà circa 100 - 200 transazioni complesse al secondo.

2. Cinque Broker dietro Nginx (5 Worker)
Aggiungere 4 worker in più ti dà molta più "larghezza di banda" all'ingresso, ma sposta il collo di bottiglia più in basso.

Capacità di Ingresso (Edge): Diventa quasi lineare. Ora puoi gestire 50.000+ connessioni WebSocket e l'Nginx distribuirà il carico di decodifica TLS e la verifica DPoP su 5 CPU diverse. Puoi tranquillamente assorbire 3.000 - 5.000 RPS di traffico HTTP in ingresso.

Gestione dello Stato (Redis): Nessun problema. Redis è mostruosamente veloce (può gestire 100.000+ operazioni al secondo su un singolo core). Farà da semaforo per il rate limiting dei 5 broker senza battere ciglio.

Il vero limite architetturale (PostgreSQL e Audit): Qui arriva il trucco del design di Cullis. Anche se hai 5 broker, il database PostgreSQL è uno solo. E soprattutto, l'Audit Ledger usa una Hash Chain. Poiché ogni riga di log deve contenere l'hash crittografico della riga precedente, gli inserimenti devono essere serializzati (messi in fila indiana) tramite un lock (_audit_chain_lock).

In sintesi: Cosa succede se scali a 5 Broker?
La resistenza agli attacchi DoS decuplica: Se un attaccante invia migliaia di richieste invalide (firme sbagliate, token scaduti), i 5 broker le scartano istantaneamente usando solo la CPU, proteggendo il database.

La scalabilità in lettura (Discovery) è enorme: Le ricerche di altri agenti nel registro (GET /registry/agents/search) vengono servite in parallelo da tutti i broker.

La scalabilità in scrittura (Messaggi) ha un tetto massimo: Non importa quanti broker aggiungi, non supererai mai la velocità massima a cui il singolo database PostgreSQL riesce a calcolare e scrivere in sequenza la Hash Chain dell'audit log (tipicamente 200 - 500 scritture al secondo a seconda dell'hardware del DB).

Nel mondo degli agenti AI B2B (es. ordini di acquisto, contratti), 200 operazioni verificate e crittografate al secondo sono un volume immenso (sono oltre 17 milioni di transazioni al giorno), quindi l'architettura è ben dimensionata.

Come faccio ad ovviare il problema di postgres?

Questa è LA domanda da vero Architetto di Sistemi. Hai individuato il punto esatto in cui la crittografia pura entra in conflitto con la scalabilità estrema.

Il problema non è PostgreSQL in sé (che può gestire decine di migliaia di scritture al secondo), ma il vincolo matematico della Hash Chain globale: siccome ogni riga deve contenere l'hash della riga precedente, il sistema ti costringe a scrivere in fila indiana (serializzazione tramite il _audit_chain_lock).

Se il tuo sistema esplode e devi processare 10.000 messaggi al secondo, hai 3 strategie architetturali per ovviare al problema, dalla più semplice alla più complessa.

1. Sharding della Hash Chain (Catene Parallele) ⛓️⛓️
Perché l'organizzazione Sony dovrebbe aspettare in fila che l'organizzazione Apple finisca di scrivere i suoi log?
Invece di avere una singola "catena globale" per tutto il Broker, modifichi il database per mantenere una hash chain separata per ogni organizzazione (o addirittura per ogni sessione).

Come funziona: Il lock sul database diventa _audit_chain_lock_{org_id}.

Il risultato: Se hai 100 organizzazioni che comunicano contemporaneamente, il database fa 100 scritture in parallelo. Il tuo limite di 200 operazioni/secondo diventa 200 operazioni/sec per organizzazione.

Pro: Risolve il problema alla radice mantenendo l'integrità crittografica perfetta.

2. Togliere l'Audit dal "Critical Path" (Asincronia e Code) 📨
Allo stato attuale, quando un agente manda un messaggio, aspetta che il Broker abbia finito di calcolare l'hash e scritto su Postgres prima di ricevere l'OK (HTTP 200). Se c'è traffico, l'agente va in timeout.

Come funziona: Quando il Broker riceve il messaggio, non lo scrive subito su Postgres. Lo "lancia" in una coda super-veloce (come Redis Streams o Kafka) e risponde subito OK all'agente (latenza di 2 millisecondi).

Il Notario in background: Un processo separato "raccoglie" i log dalla coda, calcola le Hash Chain con calma e le scrive su Postgres.

Pro: L'API per gli agenti diventa istantanea, indipendentemente da quanto è intasato il database.

3. Micro-Batching e Merkle Trees (Lo stile Blockchain) 🧊
Se devi per forza mantenere una catena globale e scrivere in modo sincrono, l'unica soluzione è non fare un hash per ogni singolo messaggio, ma per "blocchi" di messaggi.

Come funziona: Il Broker aspetta 50 millisecondi, raccogliendo ad esempio 200 messaggi arrivati in quell'istante. Crea un "blocco" (come nella blockchain), calcola un singolo hash per tutti e 200 i messaggi (Merkle Tree), e fa una singola INSERT multipla su Postgres.

Il risultato: Con 20 scritture al secondo (blocchi), stai in realtà salvando 4.000 messaggi al secondo.


---

# Decisione Redis HA e Postgres HA (2026-04-12)

## Contesto
Lo smoke test (`demo_network/smoke.sh full`) gira Redis e Postgres single-node
su tmpfs/volume locale. Questo è **voluto**: lo smoke testa correttezza del
protocollo, non scalabilità o fault tolerance.

## Dove vanno HA / scale-out
Le ricette HA NON vanno nella smoke per tre motivi:
1. Raddoppiano il runtime senza testare code path nuovi del broker
2. Lo smoke deve restare veloce (gate pre-merge ~120s)
3. HA è una decisione di **deploy**, non di **protocollo**

Vanno invece in `deploy/broker/` (Fase C della roadmap):

| Componente | Single-node (smoke) | Prod opzione A | Prod opzione B |
|---|---|---|---|
| **Redis** | `redis:7-alpine` singolo | Sentinel: 1 master + 2 replica + 3 sentinel (6 container) | Managed: AWS ElastiCache / GCP Memorystore |
| **Postgres** | `postgres:16-alpine` singolo | Streaming replication: primary + 1 standby + failover tooling | Managed: RDS / CloudSQL |

## Stato codice broker
- **Redis**: oggi `Redis.from_url(REDIS_URL)` — **NO Sentinel support**. Per attivare Sentinel serve refactor di `app/broker/redis_client.py` (~30 righe) e nuova env `REDIS_SENTINELS` + `REDIS_SERVICE_NAME`. TODO in Fase C.
- **Postgres**: oggi singola `DATABASE_URL`. Per replica read-only serve un secondo `DATABASE_READ_URL` e routing degli `SELECT` non transazionali. Non implementato. Per read/write failover basta un DNS (es. RDS endpoint) — nessun code change.

## Quando switchare da single-node a HA
- **< 1000 agent concorrenti, 1 broker replica**: single-node Redis + Postgres è sufficiente. Downtime finestra patch accettata.
- **1000-5000 agent, 2-5 broker replica**: Redis Sentinel obbligatorio (i broker replica si parlano via Redis pub/sub, se Redis muore tutto il network si ferma). Postgres managed o replica manuale.
- **> 5000 agent o SLA 99.95%**: Redis Cluster o managed; Postgres managed con failover automatico; multi-region come descritto nella sezione precedente.

## Chaos testing HA
Il failover HA (kill master Redis / Postgres durante traffico) è coperto da
un test separato in Fase B della roadmap (`docs/chaos-test.md`), non dalla
smoke.
