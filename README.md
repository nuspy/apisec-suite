# apisec-suite

Tre scanner di sicurezza per API, orchestrati insieme, con un solo report.

Nessuno dei tre, da solo, copre l'OWASP API Security Top 10. Presi insieme si
completano — ed e' l'unica ragione per cui esiste questo progetto.

| Engine | Cosa copre | Cosa NON copre | Licenza |
|---|---|---|---|
| **VulnAPI** | header e cookie di sicurezza, batteria JWT, authentication bypass, fingerprinting, TRACE/TRACK, method override, GraphQL introspection | BOLA, BFLA, mass assignment, business logic, SSRF, injection: e' *context-free*, testa ogni operazione isolatamente | MIT |
| **APISCAN** | l'intera OWASP API Top 10, con BOLA, BFLA multi-ruolo, mass assignment, business logic, SSRF, injection | conformita' al contratto; nessuna suite di test automatica a monte | AGPL-3.0 |
| **42Crunch** *(freemium)* | **contract conformance**: valida le risposte reali contro l'OpenAPI — l'unico dei tre a farlo | non eseguibile in locale, quota di 25 scansioni/repo/mese | proprietaria |

VulnAPI e APISCAN girano in locale. 42Crunch no: la sua logica sta in
un'immagine Docker proprietaria che pretende il contesto di un runner, quindi
la suite **ne genera il workflow di CI** invece di eseguirlo.

## Cosa fa concretamente

1. Configuri il bersaglio e le credenziali **una volta sola**.
2. Gli engine girano in sequenza, ognuno tradotto nel proprio dialetto.
3. I risultati vengono **fusi**: lo stesso difetto trovato da due engine con
   nomi diversi diventa un finding solo, marcato come *confermato da piu'
   engine*.
4. Esce un report unico in **SARIF, JSON e HTML**.
5. Se configurato, un **LLM** analizza i finding gia' uniti — quindi vede cose
   che nessun engine da solo puo' vedere.

Esempio reale, sul target di test incluso:

```
68 finding grezzi (vulnapi: 57, apiscan: 11) -> 54 dopo la fusione,
7 confermati da piu' engine

  API5:2023   {'apiscan': 3}                    <- solo APISCAN
  API8:2023   {'vulnapi': 50, 'apiscan': 8}     <- entrambi, 7 corroborati
```

Il CORS wildcard che VulnAPI chiama *"CORS Allow-Origin Header is set to
wildcard (*)"* e APISCAN chiama *"ACAO=\*, ACAC=true, Wildcard with
credentials"* diventa un finding solo, con due conferme indipendenti.

## Installazione

Serve **Python 3.10 o successivo**. Gli script creano un ambiente virtuale
dentro la cartella del progetto: non toccano il Python di sistema, e si
disinstallano cancellando `.venv`, `bin` e `vendor`.

### Windows

```powershell
git clone <questo-repo> apisec-suite
cd apisec-suite
.\install.ps1
```

Se PowerShell rifiuta di eseguire lo script, la policy di esecuzione e'
ristretta. Per la sola sessione corrente:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Linux e macOS

```bash
git clone <questo-repo> apisec-suite
cd apisec-suite
./install.sh
```

Il bit di esecuzione e' registrato nel repository, quindi `chmod` non serve. Se
hai copiato i file senza git (zip, chiavetta, condivisione di rete) il
permesso puo' essersi perso: `chmod +x install.sh run-*.sh run-gui.command`.

Tkinter non si installa da pip — e' un binding a Tcl/Tk di sistema. Se manca,
l'installer lo rileva e dice cosa fare:

| Sistema | Comando |
|---|---|
| macOS (Homebrew) | `brew install python-tk` |
| macOS (python.org) | gia' incluso |
| Debian / Ubuntu | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Arch | `sudo pacman -S tk` |

Senza Tkinter la GUI non parte, ma la riga di comando funziona lo stesso.

### Opzioni dell'installer

| Opzione | Effetto |
|---|---|
| `--force` / `-Force` | ricrea il venv da zero |
| `--skip-engines` / `-SkipEngines` | non scarica VulnAPI ne' clona APISCAN |
| `--python` / `-Python` | usa un interprete specifico |

Gli engine non sono ridistribuiti qui: `bootstrap.py` li prende dalle fonti
ufficiali. E' igiene sulle licenze e sugli aggiornamenti.

## Uso

| | Windows | Linux / macOS |
|---|---|---|
| Interfaccia grafica | `.\run-gui.ps1` | `./run-gui.sh` |
| Scansione | `.\run-scan.ps1 ...` | `./run-scan.sh ...` |
| Target di test | `.\run-testtarget.ps1` | `./run-testtarget.sh` |
| Verifica installazione | `.\install.ps1` | `./install.sh` |

Su **macOS** c'e' anche `run-gui.command`: doppio click dal Finder, senza
passare dal Terminale. Al primo avvio macOS puo' chiedere conferma se il file
risulta scaricato da internet.

Gli script trovano il venv da soli: non serve attivarlo a mano.

### Interfaccia grafica

```bash
./run-gui.sh          # oppure  .\run-gui.ps1  su Windows
python apisec_gui.py  # se preferisci gestire l'ambiente da te
```

Non e' un'applicazione web: si apre una finestra, non c'e' nessun indirizzo a
cui collegarsi.

E' la GUI di APISCAN **estesa**, non riscritta. I tab `Target`,
`Authentication`, `Form Login`, `OWASP Scans` e `Advanced` sono quelli
originali e continuano a comandare APISCAN; `Engine`, `LLM` e `CI/CD` sono
della suite. La configurazione dell'autenticazione compilata li' — otto flow,
mTLS, form-login con auto-detect — alimenta **tutti** gli engine.

### Non hai il documento OpenAPI?

Entrambi gli engine ne vogliono uno. Se non ce l'hai, la suite lo cerca sul
bersaglio:

```bash
# cerca il documento e poi scansiona
./run-scan.sh --url https://api.example.test --discover

# solo ricerca, nessun payload di attacco: guarda cosa c'è e basta
./run-scan.sh --url https://api.example.test --discover-only
```

Prima cerca il **documento** vero, in ordine di costo:

1. **Header `Link`** con `rel=describedby` o `service-desc`.
2. **Pagine di documentazione** — Swagger-UI e ReDoc dichiarano l'URL dello
   spec nel proprio HTML. Trova documenti a path che nessuna wordlist
   indovinerebbe, tipo `/static/contract/v2/service-description.json`.
3. **Wordlist** di ~100 percorsi convenzionali (framework Spring, ASP.NET,
   WordPress, UI moderne come RapiDoc/Scalar), sondati in parallelo.

Con un URL che ha un path (`https://host/api/v1`) **risale i livelli**: il
documento sta quasi sempre più in alto, su `https://host/openapi.json`.

**Un 200 non basta.** Molti server rispondono 200 con la propria SPA a
qualunque path. Ogni candidato viene scaricato, interpretato come JSON o YAML,
e accettato solo se contiene operazioni vere.

### Ricostruzione della superficie

Se il documento non c'è, la superficie dell'API **non è invisibile: è sparsa**.
La suite la ricompone da:

| Fonte | Cosa legge | Contatta |
|---|---|---|
| **Analisi JavaScript** | i path che la SPA chiama, nei suoi bundle (fetch/axios/URL, chunk webpack) | solo il bersaglio |
| **robots.txt / sitemap.xml** | path dichiarati ed esclusi | solo il bersaglio |
| **OSINT** (`--osint`) | URL storiche da Wayback Machine e Common Crawl | ⚠️ servizi terzi |

L'analisi JavaScript è la risposta esatta al caso "server che risponde 200 con
la SPA a tutto": quella SPA *è* la mappa. Su un target che espone solo una SPA
la suite ha ricostruito **13 endpoint** — inclusi `/api/v2/users/{id}` con il
parametro di path riconosciuto, la base dei test BOLA.

**L'OSINT è opt-in** (`--osint`, default off) perché invia il nome del dominio
a `web.archive.org` e `commoncrawl.org`, che lo registrano. Nella GUI chiede
conferma prima di partire.

### Sintesi dell'OpenAPI

Dagli endpoint ricostruiti, la suite **sintetizza un OpenAPI 3.1** che entrambi
gli engine consumano. I segmenti `{id}` diventano parametri di path, così gli
scanner li riconoscono come punti di manipolazione. Non è un contratto — mancano
tipi, schemi e risposte — ma è più preciso di un crawl alla cieca, perché
include path che il crawler non raggiunge (quelli visti solo nel JavaScript o
negli archivi).

### La catena di ripiego

Quando manca il documento, in ordine:

1. **cerca** il documento vero (header, HTML, wordlist);
2. **ricostruisce** la superficie (JS, robots, sitemap, OSINT);
3. **sintetizza** un OpenAPI dagli endpoint — `--no-synthesize` per disattivare;
4. **crawl** di APISCAN come ultimo ripiego — `--no-crawl-fallback` per
   disattivare; VulnAPI passa a `curl`.

Ogni fonte è attivabile singolarmente. Da CLI:

```bash
./run-scan.sh --url https://api.example.test --discover              # tutto tranne OSINT
./run-scan.sh --url https://api.example.test --discover --osint      # anche archivi
./run-scan.sh --url https://api.example.test --discover --no-js       # senza analisi JS
./run-scan.sh --url https://api.example.test --discover-only          # solo ricerca
```

Nella GUI, tab `Engine` → card "Scoperta del contratto": una casella per ogni
fonte, più il pulsante **Cerca ora** che ricostruisce, sintetizza, e compila il
campo Swagger del tab `Target`.

Un avvertimento che il report ripete: la copertura della scansione è quella del
documento **usato** — trovato o sintetizzato — che può essere più stretta della
superficie reale dell'API.

### Riga di comando

```bash
# scansione base
./run-scan.sh --url https://api.example.test --openapi openapi.json

# con autenticazione e soglia di fallimento
./run-scan.sh --url https://api.example.test --openapi openapi.json \
    --flow token --token "$API_TOKEN" --fail-on high --sarif out.sarif

# solo un engine, con analisi LLM
./run-scan.sh --url ... --engines vulnapi --llm

# quali provider LLM sono disponibili?
./run-scan.sh --llm-list
```

Su Windows lo stesso con `.\run-scan.ps1`. Le liste accettano sia la virgola
sia lo spazio (`--engines vulnapi,apiscan` oppure `--engines "vulnapi apiscan"`),
perche' in PowerShell la virgola costruisce un array e altrimenti la lista
arriverebbe deformata.

Codici di uscita: `0` pulito · `1` finding sopra soglia · `2` configurazione
non valida · `3` nessun engine ha potuto girare.

### CI/CD

Dal tab `CI/CD` della GUI si genera un workflow GitHub Actions che mette in
pipeline 42Crunch (audit + scan), la suite, e unisce tutti i SARIF in un solo
caricamento verso Code Scanning. I job 42Crunch sono separati e
`continue-on-error`, cosi' la quota esaurita non ferma il resto.

## LLM

Il layer LLM passa da [llmswitch](https://github.com/nuspy/llmswitch), che
tiene un registry di provider e sa risolvere `(base_url, api_key, modello)`.
Sono disponibili tutti i suoi tipi: **LM Studio, vLLM, llama.cpp**, OpenAI,
Claude, Gemini, Grok, Qwen, DeepSeek, Kimi, Z.AI, NVIDIA NIM, Nebius, Unsloth,
generico OpenAI-compatibile, i quattro abbonamenti OAuth e i tre CLI-agenti.

Tre consumatori, una sola configurazione:

- **la suite** usa il provider direttamente per il triage e la sintesi;
- **APISCAN** riceve `LLM_PROVIDER`, `LLM_API_BASE`, `LLM_MODEL` e
  `LLM_API_KEY` iniettate nell'ambiente del suo processo. Ha gia' un provider
  `openai_compat`, quindi parla con l'intero registry **senza che una riga del
  suo codice cambi**;
- **i CLI-agenti** (Claude Code, Codex, Antigravity), che non hanno endpoint
  HTTP, vengono esposti da uno shim locale OpenAI-compatibile e diventano
  utilizzabili anche da APISCAN.

Sui provider locali vale la regola VRAM di llmswitch: di default la suite usa
**solo un modello gia' in memoria** e non ne carica di propria iniziativa —
prendersi la GPU e' una decisione dell'utente, non di uno scanner in
background.

Una regola sta sopra tutto: **l'LLM annota, non cancella.** Un verdetto di
"falso positivo" diventa un campo del finding e lo degrada a informativo, mai
la sua rimozione. Un modello che sbaglia deve costare una riga di rumore, non
una vulnerabilita' vera che sparisce prima di essere letta.

## Target di test

```bash
./run-testtarget.sh          # http://127.0.0.1:8000
./run-testtarget.sh --port 9000
```

Un'API FastAPI deliberatamente insicura, con OpenAPI auto-generato e difetti
scelti perche' entrambi gli engine trovino qualcosa: BOLA, BFLA, mass
assignment, SSRF, header assenti, CORS wildcard, cookie insicuri, JWT con
segreto debole, `/.env` esposto.

Esiste per una ragione precisa: gli engine inviano payload di attacco, e
provarli su sistemi di terzi non e' accettabile. Bind su `127.0.0.1`.

## Architettura

```
install.ps1  install.sh          creano il venv e scaricano gli engine
run-gui.ps1  run-gui.sh  run-gui.command
run-scan.ps1 run-scan.sh
run-testtarget.ps1 run-testtarget.sh

apisec/
├── config.py          ScanConfig, AuthConfig, LLMSettings — configurazione condivisa
├── findings.py        Finding unificato, severita', classi di difetto per la dedup
├── runner.py          orchestrazione: esegui -> fondi -> analizza -> scrivi
├── engines/
│   ├── base.py        Engine ABC + runner di processi con streaming e timeout
│   ├── vulnapi_engine.py
│   └── apiscan_engine.py
├── report/
│   ├── merge.py       fusione cross-engine, corroborazione, matrice di copertura
│   ├── sarif.py       SARIF 2.1.0
│   └── html.py        report unificato, responsive
├── llm/
│   ├── bridge.py      ponte a llmswitch + iniezione env verso APISCAN
│   ├── shim.py        shim OpenAI-compatibile per i CLI-agenti
│   ├── client.py      client OpenAI / Anthropic
│   └── analyst.py     triage e sintesi sui finding uniti
├── cicd/workflow.py   generatore GitHub Actions
└── gui/app.py         ApiSecSuiteApp(APISCANApp)
```

Due decisioni portano il peso dell'architettura:

**Gli engine sono processi, non import.** Non e' pigrizia: APISCAN e' AGPL e
VulnAPI e' MIT, e l'esecuzione come processi separati e' aggregazione, non
derivazione — nessuno contamina l'altro. In piu' un engine che va in crash non
porta giu' la GUI, e VulnAPI e' un binario Go che non c'e' niente da importare.

**La deduplica usa classi di difetto, non categorie OWASP.** Su dati reali la
categoria e' troppo grossolana: HSTS assente, CSP assente, CORS wildcard,
X-Frame-Options assente e nosniff assente sono *tutti* `API8:2023` sullo stesso
endpoint. Una chiave basata sulla categoria li fondeva in un finding solo,
perdendone quattro veri. La tabella delle classi in `findings.py` e' esplicita
di proposito: dedurre l'equivalenza dalla somiglianza dei testi produrrebbe
fusioni casuali.

**Gli engine girano in sequenza.** Due scanner che martellano insieme la stessa
API falsano le misure di rate limiting, si sporcano a vicenda i test di stato,
e su un bersaglio fragile ne raddoppiano le probabilita' di crash.

## Licenza

**AGPL-3.0.** La GUI estende per sottoclasse quella di APISCAN, quindi tutto il
progetto e' un'opera derivata AGPL. Conseguenza concreta: offrendo questa suite
come servizio accessibile in rete va pubblicato il sorgente completo.

VulnAPI resta MIT: e' un processo separato, non lo si tocca. Vedi `NOTICE`.

## Avvertenza

Gli engine eseguono test attivi: inviano payload di attacco, tentano bypass di
autenticazione, provano accessi non autorizzati.

**Usali solo su API di cui sei proprietario o per cui hai autorizzazione
scritta.** Non puntarli sulla produzione: un'implementazione poco resiliente
puo' andare in crash sotto i test.
