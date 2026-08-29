"""GUI della suite: estende quella di APISCAN invece di riscriverla.

`apiscan_gui.APISCANApp` era gia' un orchestratore di processi esterni - non
importa `apiscan.py`, lo lancia con `subprocess.Popen` e ne segue lo stdout -
e ha gia' cablati i tab piu' laboriosi da rifare: otto flow di autenticazione,
mTLS, form-login con auto-detect, crawling, tuning.

Estenderla per classe, senza toccare il suo sorgente, ha tre conseguenze utili:

* `git pull` sul progetto originale continua a funzionare senza conflitti;
* la configurazione dell'autenticazione, compilata una volta, alimenta *tutti*
  gli engine, non solo APISCAN;
* per APISCAN si riusa la sua stessa `_build_args()`, quindi ogni opzione dei
  suoi widget arriva a destinazione anche quando la suite non la modella.

Quello che questa sottoclasse aggiunge: tre tab (Engine, LLM, CI/CD) e la
sostituzione di `_start_scan`, che da lanciatore di un processo diventa
orchestratore di piu' engine con fusione dei risultati.
"""
from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path
from tkinter import (
    BooleanVar, Canvas, DISABLED, END, NORMAL, StringVar, Tk, W,
    filedialog, messagebox, ttk,
)

from ..config import AuthConfig, ConfigError, LLMSettings, ScanConfig
from ..engines import ENGINE_ORDER, engine_status
from ..runner import ScanRunner

# --- innesto su APISCAN ------------------------------------------------ #
# Il pacchetto upstream non e' installabile: si aggiunge la sua cartella a
# sys.path prima di importarlo. Il percorso e' quello in cui bootstrap.py lo
# clona; `APISCAN_HOME` lo sovrascrive.

def _apiscan_home() -> Path | None:
    import os
    candidates = []
    env = os.getenv("APISCAN_HOME", "").strip()
    if env:
        candidates.append(Path(env))
    root = Path(__file__).resolve().parents[2]
    candidates += [root / "vendor" / "apiscanner", root / "apiscanner", root]
    for candidate in candidates:
        if (candidate / "apiscan_gui.py").is_file():
            return candidate
    return None


_HOME = _apiscan_home()
if _HOME is not None and str(_HOME) not in sys.path:
    sys.path.insert(0, str(_HOME))

try:
    from apiscan_gui import CLR, APISCANApp, _init_styles, _make_card
except ImportError as exc:  # pragma: no cover - dipende dall'ambiente
    raise ImportError(
        "apiscan_gui non importabile: la GUI della suite estende quella di "
        "APISCAN. Eseguire `python bootstrap.py --apiscan`, oppure impostare "
        f"APISCAN_HOME. Dettaglio: {exc}"
    ) from exc


APP_TITLE = "apisec-suite — VulnAPI + APISCAN + 42Crunch"


class ApiSecSuiteApp(APISCANApp):
    """La GUI di APISCAN, piu' gli altri engine e il layer LLM."""

    def __init__(self, root: Tk) -> None:
        # Le variabili vanno create prima di `super().__init__`, che costruisce
        # la UI e quindi chiama `_build_ui` (sovrascritto qui sotto).
        self._suite_init_vars()
        self._runner: ScanRunner | None = None
        self._outcome = None
        super().__init__(root)
        root.title(APP_TITLE)
        self._log("", "white")
        self._log("  apisec-suite attiva: engine multipli, fusione dei "
                  "risultati, SARIF unificato.", "info")

    # ------------------------------------------------------------------ #
    # Variabili
    # ------------------------------------------------------------------ #

    def _suite_init_vars(self) -> None:
        status = engine_status()

        self.engine_vars: dict[str, BooleanVar] = {
            name: BooleanVar(value=status[name].ok) for name in ENGINE_ORDER
        }
        self.engine_status = status
        self.engine_timeout_var = StringVar(value="3600")
        self.vulnapi_mode_var = StringVar(value="openapi")
        self.vulnapi_scans_var = StringVar()
        self.vulnapi_exclude_var = StringVar()
        self.suite_output_var = StringVar(value=str(Path.cwd() / "apisec_out"))
        self.fail_on_var = StringVar(value="high")

        # --- LLM ---
        self.llm_enabled_var = BooleanVar(value=False)
        self.llm_registry_var = StringVar(value="llmswitch")
        self.llm_provider_var = StringVar(value="(assegnato nel registry)")
        self.llm_model_var = StringVar()
        self.llm_consumer_var = StringVar(value="chat")
        self.llm_may_load_var = BooleanVar(value=False)
        self.llm_drive_apiscan_var = BooleanVar(value=True)
        self.llm_analyze_var = BooleanVar(value=True)
        self.llm_status_var = StringVar(value="non verificato")
        self._llm_provider_ids: list[str] = []

        # --- CI/CD ---
        self.ci_name_var = StringVar(value="API Security")
        self.ci_api_def_var = StringVar(value="openapi.json")
        self.ci_target_var = StringVar(value="${{ vars.API_TARGET_URL }}")
        self.ci_secret_var = StringVar(value="API_TOKEN")
        self.ci_python_var = StringVar(value="3.12")
        self.ci_audit_var = BooleanVar(value=True)
        self.ci_scan_var = BooleanVar(value=True)
        self.ci_suite_var = BooleanVar(value=True)
        self.ci_ondemand_var = BooleanVar(value=True)
        self.ci_upload_var = BooleanVar(value=True)
        self.ci_cron_var = StringVar(value="0 3 * * 1")

    # ------------------------------------------------------------------ #
    # Costruzione UI
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        super()._build_ui()
        self._suite_add_tabs()

    def _suite_add_tabs(self) -> None:
        notebook = getattr(self, "_notebook", None)
        if notebook is None:  # pragma: no cover - cambio di struttura upstream
            self._log("[!] Notebook non trovato: i tab della suite non sono "
                      "stati aggiunti.", "red")
            return

        for label, builder in (
            ("  Engine  ", self._build_tab_engines),
            ("  LLM  ", self._build_tab_llm),
            ("  CI/CD  ", self._build_tab_cicd),
        ):
            frame = ttk.Frame(notebook, style="Root.TFrame")
            notebook.add(frame, text=label)
            builder(frame)

    # ---------------------------- tab Engine --------------------------- #

    def _build_tab_engines(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        card = _make_card(parent, "Engine da eseguire")
        card.pack(fill="x", padx=10, pady=(10, 6))
        inner = card.content
        inner.columnconfigure(0, weight=1)

        ttk.Label(
            inner,
            text="Gli engine girano in sequenza, non in parallelo: due scanner "
                 "insieme falsano le misure di rate limiting e raddoppiano il "
                 "carico sul bersaglio.",
            style="Muted.TLabel", wraplength=780, justify="left",
        ).grid(row=0, column=0, sticky=W, padx=14, pady=(6, 8))

        row = 1
        for name in ENGINE_ORDER:
            availability = self.engine_status[name]
            frame = ttk.Frame(inner, style="Card.TFrame")
            frame.grid(row=row, column=0, sticky="ew", padx=14, pady=3)

            label = {"vulnapi": "VulnAPI (Go, MIT)",
                     "apiscan": "APISCAN (Python, AGPL-3.0)"}[name]
            check = ttk.Checkbutton(frame, text=label,
                                    variable=self.engine_vars[name],
                                    style="Card.TCheckbutton")
            check.pack(side="left")
            if not availability.ok:
                check.configure(state=DISABLED)

            color = CLR["success"] if availability.ok else CLR["danger"]
            detail = availability.detail
            if not availability.ok and availability.hint:
                detail = f"{detail} — {availability.hint}"
            ttk.Label(frame, text=detail, style="Muted.TLabel",
                      foreground=color, wraplength=520,
                      justify="left").pack(side="left", padx=(12, 0))
            row += 1

        coverage = ttk.Label(
            inner,
            text="Copertura complementare — VulnAPI: header, cookie, JWT, "
                 "auth bypass, fingerprinting (API2, API8). APISCAN: BOLA, "
                 "BFLA, mass assignment, business logic, SSRF, injection "
                 "(API1, API3-API7, API9, API10). Nessuno dei due valida la "
                 "conformita' al contratto: quella la fa 42Crunch, dal tab CI/CD.",
            style="Muted.TLabel", wraplength=780, justify="left")
        coverage.grid(row=row, column=0, sticky=W, padx=14, pady=(10, 8))

        # --- opzioni ---
        card2 = _make_card(parent, "Opzioni")
        card2.pack(fill="x", padx=10, pady=6)
        opts = card2.content
        opts.columnconfigure(1, weight=1)

        def field(row_index: int, label: str, widget: ttk.Widget,
                  hint: str = "") -> None:
            ttk.Label(opts, text=label).grid(row=row_index, column=0, sticky=W,
                                             padx=(14, 8), pady=4)
            widget.grid(row=row_index, column=1, sticky="ew", padx=(0, 14), pady=4)
            if hint:
                ttk.Label(opts, text=hint, style="Muted.TLabel").grid(
                    row=row_index, column=2, sticky=W, padx=(0, 14))

        field(0, "Cartella di output",
              ttk.Entry(opts, textvariable=self.suite_output_var))
        ttk.Button(opts, text="Sfoglia", style="Small.TButton",
                   command=self._browse_output).grid(row=0, column=3, padx=(0, 14))

        field(1, "Timeout per engine (s)",
              ttk.Entry(opts, textvariable=self.engine_timeout_var, width=10),
              "0 = nessun limite")
        field(2, "VulnAPI: modalita'",
              ttk.Combobox(opts, textvariable=self.vulnapi_mode_var,
                           values=["openapi", "curl"], state="readonly", width=12),
              "curl = una sola URL")
        field(3, "VulnAPI: solo questi check",
              ttk.Entry(opts, textvariable=self.vulnapi_scans_var),
              "separati da virgola")
        field(4, "VulnAPI: escludi check",
              ttk.Entry(opts, textvariable=self.vulnapi_exclude_var))
        field(5, "Soglia di fallimento",
              ttk.Combobox(opts, textvariable=self.fail_on_var,
                           values=["critical", "high", "medium", "low", "never"],
                           state="readonly", width=12),
              "usata dal riepilogo e dalla CLI")

        note = ttk.Label(
            parent,
            text="Nota: su un OpenAPI ampio VulnAPI e' lento — applica un rate "
                 "limit interno e moltiplica una trentina di check per ogni "
                 "operazione. E' normale che impieghi piu' di APISCAN.",
            style="Muted.TLabel", wraplength=780, justify="left")
        note.pack(anchor=W, padx=24, pady=(4, 10))

    def _browse_output(self) -> None:
        chosen = filedialog.askdirectory(title="Cartella di output")
        if chosen:
            self.suite_output_var.set(chosen)

    # ------------------------------ tab LLM ---------------------------- #

    def _build_tab_llm(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        card = _make_card(parent, "Provider LLM (llmswitch)")
        card.pack(fill="x", padx=10, pady=(10, 6))
        inner = card.content
        inner.columnconfigure(1, weight=1)

        from ..llm import (
            available, list_consumers, list_providers, list_registries,
            unavailable_reason,
        )

        if not available():
            ttk.Label(inner, text=unavailable_reason(), style="Muted.TLabel",
                      foreground=CLR["warning"], wraplength=780,
                      justify="left").grid(row=0, column=0, columnspan=3,
                                           sticky=W, padx=14, pady=10)
            ttk.Label(inner,
                      text="Le scansioni funzionano comunque: senza LLM manca "
                           "solo il triage e la sintesi.",
                      style="Muted.TLabel", wraplength=780,
                      justify="left").grid(row=1, column=0, columnspan=3,
                                           sticky=W, padx=14, pady=(0, 10))
            return

        # llmswitch tiene un registry per applicazione: si sceglie quale
        # aprire, cosi' i provider gia' configurati per altri progetti sono
        # subito riutilizzabili invece di dover essere reinseriti.
        registries = list_registries()
        if registries:
            populated = next((name for name, count in registries if count), "")
            self.llm_registry_var.set(populated or registries[0][0])
        registry_labels = [f"{name} ({count} provider)"
                           for name, count in registries] or ["llmswitch (0)"]
        self._llm_registry_names = [name for name, _ in registries] or ["llmswitch"]

        ttk.Checkbutton(inner, text="Abilita l'analisi LLM",
                        variable=self.llm_enabled_var,
                        style="Card.TCheckbutton").grid(
            row=0, column=0, columnspan=3, sticky=W, padx=14, pady=(8, 4))

        def field(row: int, label: str, widget: ttk.Widget, hint: str = "") -> None:
            ttk.Label(inner, text=label).grid(row=row, column=0, sticky=W,
                                              padx=(14, 8), pady=4)
            widget.grid(row=row, column=1, sticky="ew", pady=4)
            if hint:
                ttk.Label(inner, text=hint, style="Muted.TLabel").grid(
                    row=row, column=2, sticky=W, padx=(8, 14))

        self._llm_registry_labels = registry_labels
        registry_box = ttk.Combobox(inner, values=registry_labels,
                                    state="readonly")
        current = self.llm_registry_var.get()
        if current in self._llm_registry_names:
            registry_box.current(self._llm_registry_names.index(current))
        registry_box.bind("<<ComboboxSelected>>",
                          lambda _e: self._on_registry_changed(registry_box))
        field(1, "Registry", registry_box, "file di provider di llmswitch")
        self._llm_registry_box = registry_box

        providers = list_providers(self.llm_registry_var.get())
        labels = ["(assegnato al consumer)"]
        self._llm_provider_ids = [""]
        for prov in providers:
            where = "locale" if prov.local else "remoto"
            labels.append(f"{prov.label} · {where}"
                          + (f" · {prov.model}" if prov.model else ""))
            self._llm_provider_ids.append(prov.pid)
        # Le etichette servono a `_llm_settings` per risalire dall'etichetta
        # scelta all'id del provider: la combobox espone il testo, non l'indice.
        self._llm_labels = labels

        provider_box = ttk.Combobox(inner, textvariable=self.llm_provider_var,
                                    values=labels, state="readonly")
        field(2, "Provider", provider_box, f"{len(providers)} configurati")
        self._llm_provider_box = provider_box

        consumers = list_consumers(self.llm_registry_var.get()) or ["chat"]
        if self.llm_consumer_var.get() not in consumers:
            self.llm_consumer_var.set(consumers[0])
        consumer_box = ttk.Combobox(inner, textvariable=self.llm_consumer_var,
                                    values=consumers)
        field(3, "Consumer", consumer_box, "a quale uso e' assegnato")
        self._llm_consumer_box = consumer_box

        field(4, "Modello",
              ttk.Entry(inner, textvariable=self.llm_model_var),
              "vuoto = quello del provider")

        ttk.Checkbutton(
            inner,
            text="Consenti di caricare un modello locale se la VRAM e' libera",
            variable=self.llm_may_load_var, style="Card.TCheckbutton").grid(
            row=5, column=0, columnspan=3, sticky=W, padx=14, pady=2)
        ttk.Label(inner,
                  text="Disattivo, usa solo cio' che e' gia' in memoria: "
                       "prendersi la GPU e' una decisione dell'utente, non di "
                       "uno scanner che gira in background.",
                  style="Muted.TLabel", wraplength=760, justify="left").grid(
            row=6, column=0, columnspan=3, sticky=W, padx=(34, 14), pady=(0, 6))

        ttk.Checkbutton(
            inner, text="Passa la configurazione LLM anche ad APISCAN (--api11)",
            variable=self.llm_drive_apiscan_var,
            style="Card.TCheckbutton").grid(row=7, column=0, columnspan=3,
                                            sticky=W, padx=14, pady=2)
        ttk.Checkbutton(
            inner, text="Analizza i finding uniti di tutti gli engine",
            variable=self.llm_analyze_var,
            style="Card.TCheckbutton").grid(row=8, column=0, columnspan=3,
                                            sticky=W, padx=14, pady=2)

        actions = ttk.Frame(inner, style="Card.TFrame")
        actions.grid(row=9, column=0, columnspan=3, sticky="ew", padx=14,
                     pady=(10, 8))
        ttk.Button(actions, text="Verifica connessione", style="Small.TButton",
                   command=self._test_llm).pack(side="left")
        ttk.Label(actions, textvariable=self.llm_status_var,
                  style="Muted.TLabel").pack(side="left", padx=12)

        info = _make_card(parent, "Come funziona")
        info.pack(fill="x", padx=10, pady=6)
        ttk.Label(
            info.content,
            text="Il provider scelto qui serve tutti i consumatori. La suite lo "
                 "usa direttamente per il triage dei finding. Ad APISCAN "
                 "vengono iniettate LLM_PROVIDER, LLM_API_BASE, LLM_MODEL e "
                 "LLM_API_KEY nell'ambiente del suo processo: usa il proprio "
                 "client, senza modifiche al suo codice. Gli agenti CLI "
                 "(Claude Code, Codex, Antigravity), che non hanno un endpoint "
                 "HTTP, vengono esposti da uno shim locale OpenAI-compatibile e "
                 "diventano utilizzabili anche da APISCAN.",
            style="Muted.TLabel", wraplength=780, justify="left").pack(
            anchor=W, padx=14, pady=10)

    def _on_registry_changed(self, box: ttk.Combobox) -> None:
        """Ricarica provider e consumer quando si cambia registry."""
        from ..llm import list_consumers, list_providers

        try:
            name = self._llm_registry_names[box.current()]
        except (IndexError, TypeError):
            return
        self.llm_registry_var.set(name)

        providers = list_providers(name)
        labels = ["(assegnato al consumer)"]
        self._llm_provider_ids = [""]
        for prov in providers:
            where = "locale" if prov.local else "remoto"
            labels.append(f"{prov.label} · {where}"
                          + (f" · {prov.model}" if prov.model else ""))
            self._llm_provider_ids.append(prov.pid)
        self._llm_labels = labels
        self._llm_provider_box.configure(values=labels)
        self.llm_provider_var.set(labels[0])

        consumers = list_consumers(name) or ["chat"]
        self._llm_consumer_box.configure(values=consumers)
        if self.llm_consumer_var.get() not in consumers:
            self.llm_consumer_var.set(consumers[0])

        self.llm_status_var.set(
            f"registry «{name}»: {len(providers)} provider, "
            f"{len(consumers)} consumer")

    def _test_llm(self) -> None:
        self.llm_status_var.set("verifica in corso...")

        def work() -> None:
            from ..llm import LLMClient
            try:
                ok, message = LLMClient(self._llm_settings()).test()
            except Exception as exc:
                ok, message = False, str(exc)
            self.root.after(0, lambda: self.llm_status_var.set(
                ("OK — " if ok else "errore — ") + message[:160]))

        threading.Thread(target=work, daemon=True).start()

    # ----------------------------- tab CI/CD --------------------------- #

    def _build_tab_cicd(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        card = _make_card(parent, "Workflow GitHub Actions")
        card.pack(fill="x", padx=10, pady=(10, 6))
        inner = card.content
        inner.columnconfigure(1, weight=1)

        ttk.Label(
            inner,
            text="42Crunch e' l'unico dei tre a validare le risposte contro il "
                 "contratto OpenAPI, ma non e' eseguibile in locale: la logica "
                 "sta in un'immagine proprietaria che si aspetta il contesto di "
                 "un runner, e ogni esecuzione consuma la quota freemium "
                 "(25 scansioni per repository al mese, 3 repository per "
                 "organizzazione). Qui se ne genera il workflow.",
            style="Muted.TLabel", wraplength=780, justify="left").grid(
            row=0, column=0, columnspan=3, sticky=W, padx=14, pady=(8, 10))

        def field(row: int, label: str, var: StringVar, hint: str = "") -> None:
            ttk.Label(inner, text=label).grid(row=row, column=0, sticky=W,
                                              padx=(14, 8), pady=4)
            ttk.Entry(inner, textvariable=var).grid(row=row, column=1,
                                                    sticky="ew", pady=4)
            if hint:
                ttk.Label(inner, text=hint, style="Muted.TLabel").grid(
                    row=row, column=2, sticky=W, padx=(8, 14))

        field(1, "Nome del workflow", self.ci_name_var)
        field(2, "File OpenAPI nel repo", self.ci_api_def_var,
              "relativo alla radice")
        field(3, "URL bersaglio", self.ci_target_var, "variabile o URL")
        field(4, "Secret con il token", self.ci_secret_var)
        field(5, "Versione Python", self.ci_python_var)
        field(6, "Cron", self.ci_cron_var, "vuoto = nessuna schedulazione")

        for row, (text, var) in enumerate((
            ("Includi 42Crunch audit (statico, non tocca l'API)", self.ci_audit_var),
            ("Includi 42Crunch scan (conformance dinamica)", self.ci_scan_var),
            ("Includi apisec-suite (VulnAPI + APISCAN)", self.ci_suite_var),
            ("42Crunch solo su richiesta o schedulato (risparmia quota)",
             self.ci_ondemand_var),
            ("Unisci i SARIF e carica su Code Scanning", self.ci_upload_var),
        ), start=7):
            ttk.Checkbutton(inner, text=text, variable=var,
                            style="Card.TCheckbutton").grid(
                row=row, column=0, columnspan=3, sticky=W, padx=14, pady=2)

        actions = ttk.Frame(inner, style="Card.TFrame")
        actions.grid(row=12, column=0, columnspan=3, sticky="ew", padx=14,
                     pady=(12, 10))
        ttk.Button(actions, text="Anteprima", style="Small.TButton",
                   command=self._preview_workflow).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Salva come...", style="Primary.TButton",
                   command=self._save_workflow).pack(side="left")

    def _workflow_options(self):
        from ..cicd import WorkflowOptions
        return WorkflowOptions(
            name=self.ci_name_var.get().strip() or "API Security",
            api_definition=self.ci_api_def_var.get().strip() or "openapi.json",
            target_url=self.ci_target_var.get().strip(),
            credential_secret=self.ci_secret_var.get().strip() or "API_TOKEN",
            python_version=self.ci_python_var.get().strip() or "3.12",
            include_42crunch_audit=self.ci_audit_var.get(),
            include_42crunch_scan=self.ci_scan_var.get(),
            include_suite=self.ci_suite_var.get(),
            crunch_on_demand_only=self.ci_ondemand_var.get(),
            upload_to_code_scanning=self.ci_upload_var.get(),
            fail_on=self.fail_on_var.get(),
            schedule_cron=self.ci_cron_var.get().strip(),
        )

    def _preview_workflow(self) -> None:
        from ..cicd import generate_workflow
        self._clear_output()
        self._hide_banner()
        self._log("=" * 62, "header")
        self._log("  Anteprima del workflow", "header")
        self._log("=" * 62, "header")
        for line in generate_workflow(self._workflow_options()).splitlines():
            self._log(line, "white")
        self._notebook.select(0)  # il pannello di output e' sul tab Target

    def _save_workflow(self) -> None:
        from ..cicd import write_workflow
        path = filedialog.asksaveasfilename(
            title="Salva il workflow",
            defaultextension=".yml",
            initialfile="api-security.yml",
            filetypes=[("YAML", "*.yml *.yaml"), ("Tutti i file", "*.*")],
        )
        if not path:
            return
        try:
            written = write_workflow(self._workflow_options(), Path(path))
        except OSError as exc:
            messagebox.showerror("Salvataggio fallito", str(exc))
            return
        self._log(f"[+] Workflow salvato in {written}", "green")
        messagebox.showinfo(
            "Workflow salvato",
            f"Salvato in:\n{written}\n\nVa messo in .github/workflows/ del "
            f"repository. Prima di usarlo, configurare la variabile "
            f"API_TARGET_URL e il secret {self.ci_secret_var.get()}.")

    # ------------------------------------------------------------------ #
    # Configurazione
    # ------------------------------------------------------------------ #

    def _llm_settings(self) -> LLMSettings:
        # La combobox espone il testo scelto, non il suo indice: l'id del
        # provider si recupera dalla posizione dell'etichetta nella lista.
        provider_id = ""
        labels = getattr(self, "_llm_labels", None)
        if labels:
            try:
                provider_id = self._llm_provider_ids[
                    labels.index(self.llm_provider_var.get())]
            except (ValueError, IndexError):
                provider_id = ""

        return LLMSettings(
            enabled=self.llm_enabled_var.get(),
            registry_app=self.llm_registry_var.get().strip() or "llmswitch",
            consumer=self.llm_consumer_var.get().strip() or "chat",
            provider_id=provider_id,
            model=self.llm_model_var.get().strip(),
            may_load_model=self.llm_may_load_var.get(),
            drive_apiscan=self.llm_drive_apiscan_var.get(),
            analyze_findings=self.llm_analyze_var.get(),
        )

    def _suite_config(self) -> ScanConfig:
        """Costruisce la configurazione dai widget, base e nuovi."""
        auth = AuthConfig(
            flow=self.flow_var.get(),
            token=self.token_var.get().strip(),
            basic_auth=self.basic_auth_var.get().strip(),
            ntlm=self.ntlm_var.get().strip(),
            api_key=self.apikey_var.get().strip(),
            api_key_header=self.apikey_header_var.get().strip() or "X-API-Key",
            client_id=self.client_id_var.get().strip(),
            client_secret=self.client_secret_var.get().strip(),
            token_url=self.token_url_var.get().strip(),
            auth_url=self.auth_url_var.get().strip(),
            redirect_uri=self.redirect_uri_var.get().strip(),
            scope=self.scope_var.get().strip(),
            client_cert=self.client_cert_var.get().strip(),
            client_key=self.client_key_var.get().strip(),
            cert_password=self.cert_password_var.get().strip(),
            login_url=self.form_login_url_var.get().strip(),
            login_username=self.form_login_user_var.get().strip(),
            login_password=self.form_login_pass_var.get().strip(),
            token_path=self.form_login_token_path_var.get().strip(),
        )

        engines = [name for name in ENGINE_ORDER if self.engine_vars[name].get()]

        cfg = ScanConfig(
            target_url=self.url_var.get().strip(),
            openapi=self.swagger_var.get().strip(),
            output_dir=Path(self.suite_output_var.get().strip() or "apisec_out"),
            engines=engines,
            auth=auth,
            llm=self._llm_settings(),
            threads=_as_int(self.threads_var.get(), 16),
            timeout=_as_float(self.timeout_var.get(), 5.0),
            proxy=self.proxy_var.get().strip(),
            insecure=self.insecure_var.get(),
            debug=self.debug_var.get(),
            crawl=self.crawl_var.get(),
            apiscan_checks=[k for k, v in self.api_vars.items() if v.get()],
            vulnapi_mode=self.vulnapi_mode_var.get(),
            vulnapi_scans=_split(self.vulnapi_scans_var.get()),
            vulnapi_exclude=_split(self.vulnapi_exclude_var.get()),
        )

        # Per APISCAN si riusa la traduzione della GUI upstream: conosce ogni
        # suo widget, comprese le opzioni che la suite non modella.
        if "apiscan" in engines:
            try:
                cfg.apiscan_argv_override = list(self._build_args())
            except Exception as exc:
                self._log(f"[!] Traduzione argomenti APISCAN fallita ({exc}): "
                          f"uso la mappatura della suite.", "yellow")

        # Le variabili d'ambiente che la GUI upstream passava al processo
        # figlio restano valide: qui vengono raccolte per l'engine.
        cfg.apiscan_env = {
            "APISCAN_DEEP_SCAN": "1" if self.deep_scan_var.get() else "0",
            "APISCAN_FAST": "1" if self.fast_mode_var.get() else "0",
            "APISCAN_INTENSITY": self.intensity_var.get().strip() or "medium",
        }
        return cfg

    # ------------------------------------------------------------------ #
    # Esecuzione
    # ------------------------------------------------------------------ #

    def _start_scan(self) -> None:
        """Sostituisce il lancio del singolo processo con l'orchestrazione."""
        try:
            cfg = self._suite_config()
        except Exception as exc:
            messagebox.showerror("Configurazione", str(exc))
            return

        errors = cfg.validate()
        if errors:
            messagebox.showerror("Configurazione non valida", "\n".join(errors))
            return

        if not cfg.engines:
            messagebox.showwarning("Nessun engine",
                                   "Selezionare almeno un engine nel tab Engine.")
            return

        if "apiscan" in cfg.engines and not any(v.get() for v in self.api_vars.values()):
            if not messagebox.askyesno(
                "Nessuna categoria selezionata",
                "APISCAN e' attivo ma nessuna categoria OWASP e' selezionata.\n"
                "Le eseguira' tutte. Continuare?",
            ):
                return

        self.running = True
        self._hide_banner()
        self._clear_output()
        self.scan_btn.configure(state=DISABLED)
        self.stop_btn.configure(state=NORMAL)
        self.header_scan_btn.configure(state=DISABLED)
        self.header_stop_btn.configure(state=NORMAL)
        self.progress_bar.start(10)
        self._update_header_status("Scansione...", CLR["warning"])
        self._update_status("Scansione multi-engine in corso...")

        self._log("=" * 62, "header")
        self._log("  apisec-suite — scansione avviata", "header")
        self._log(f"  Bersaglio: {cfg.target_url}", "header")
        self._log(f"  Engine: {', '.join(cfg.engines)}", "header")
        self._log("=" * 62, "header")

        self._runner = ScanRunner(cfg)
        self._outcome = None
        self.scan_thread = threading.Thread(
            target=self._run_suite, args=(self._runner,), daemon=True)
        self.scan_thread.start()

    def _run_suite(self, runner: ScanRunner) -> None:
        """Gira nel thread di lavoro: comunica solo attraverso la queue."""
        def progress(line: str) -> None:
            self.text_queue.put(line)

        def sink(engine: str, line: str) -> None:
            self.text_queue.put(f"{engine} | {line}")

        try:
            self._outcome = runner.run(progress=progress, line_sink=sink)
        except ConfigError as exc:
            self.text_queue.put(f"[!] Configurazione non valida: {exc}")
        except Exception as exc:
            self.text_queue.put(f"[ERROR] Scansione fallita: {exc}")
            if runner.cfg.debug:
                import traceback
                for line in traceback.format_exc().splitlines():
                    self.text_queue.put(line)

    def _stop_scan(self) -> None:
        if self._runner is not None:
            self.text_queue.put("[!] Interruzione richiesta: termino gli engine...")
            self._runner.cancel()
        self.running = False
        # Il thread di lavoro chiude da solo appena l'engine termina; il
        # polling della classe base se ne accorge e chiama `_on_scan_complete`.

    def _finish_ui(self) -> None:
        self.progress_bar.stop()
        self.scan_btn.configure(state=NORMAL)
        self.stop_btn.configure(state=DISABLED)
        self.header_scan_btn.configure(state=NORMAL)
        self.header_stop_btn.configure(state=DISABLED)

        outcome = self._outcome
        if outcome is None:
            self._update_header_status("Pronto", CLR["text_muted"])
            self._update_status("Scansione terminata senza risultati")
            return

        counts = outcome.counts
        severe = counts["critical"] + counts["high"]
        color = CLR["danger"] if severe else CLR["success"]
        self._update_header_status("Pronto", color)
        self._update_status(
            f"{len(outcome.findings)} finding · rischio {outcome.score:g}/100")

        self._log("")
        self._log("=" * 62, "header")
        self._log("  Riepilogo", "header")
        self._log("=" * 62, "header")
        for line in outcome.summary_lines():
            self._log(line, "red" if severe and "Finding:" in line else "white")

        analysis = outcome.analysis
        if analysis is not None and getattr(analysis, "executive_summary", ""):
            self._log("")
            self._log("--- Analisi LLM ---", "info")
            for line in analysis.executive_summary.splitlines():
                self._log(line, "info")
            for item in getattr(analysis, "priorities", []):
                self._log(f"  • {item}", "yellow")

        self._log("")
        for name, path in outcome.artifacts.items():
            self._log(f"[+] {name}: {path}", "green")

        report = outcome.artifacts.get("html")
        if report is not None:
            self.root.after(200, lambda: self._offer_report(report, severe))

    def _offer_report(self, report: Path, severe: int) -> None:
        message = (f"Scansione completata.\n\n"
                   f"{len(self._outcome.findings)} finding, "
                   f"{severe} di gravita' alta o critica.\n\n"
                   f"Aprire il report unificato?")
        if messagebox.askyesno("Scansione completata", message):
            import webbrowser
            webbrowser.open(report.as_uri())

    def _open_output_folder(self) -> None:
        """Apre la cartella della suite, non quella di APISCAN."""
        import os
        import subprocess
        base = Path(self.suite_output_var.get().strip() or "apisec_out")
        try:
            runs = sorted(base.glob("scan_*"), key=os.path.getmtime, reverse=True)
            target = runs[0] if runs else base
        except OSError:
            target = base
        if not target.exists():
            self._log(f"[!] Cartella non ancora creata: {target}", "yellow")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(target))  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(target)])
            else:
                subprocess.Popen(["xdg-open", str(target)])
        except OSError as exc:
            self._log(f"[!] Apertura fallita: {exc}", "red")

    def _on_close(self) -> None:
        if self.running:
            if not messagebox.askyesno(
                "Scansione in corso",
                "Una scansione e' in corso.\nInterromperla e uscire?",
            ):
                return
            self._stop_scan()
        try:
            from ..llm import shutdown_all
            shutdown_all()
        except Exception:
            pass
        self.root.destroy()


# ---------------------------------------------------------------------- #

def _as_int(value: str, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _as_float(value: str, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _split(value: str) -> list[str]:
    return [item.strip() for item in str(value).split(",") if item.strip()]


def main() -> None:
    root = Tk()
    _init_styles(root)
    root.option_add("*insertWidth", 2)
    ApiSecSuiteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
