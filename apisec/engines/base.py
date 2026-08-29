"""Contratto comune degli engine e runner dei processi.

Un engine e' un programma esterno che sa scansionare un'API e lasciare i
risultati da qualche parte. La suite non lo importa e non lo linka: lo lancia,
ne segue l'output riga per riga, e alla fine legge cio' che ha prodotto.

Questa separazione non e' pigrizia architetturale, e' voluta:

* **licenze** — APISCAN e' AGPL-3.0, vulnapi e' MIT. Eseguirli come processi
  separati e' aggregazione, non derivazione: nessuno dei due contamina l'altro.
* **robustezza** — uno scanner che va in crash a meta' non porta giu' la GUI.
* **linguaggi** — vulnapi e' un binario Go. Non c'e' niente da importare.

E' anche il modello che la GUI di APISCAN gia' usava per se stessa, il che
rende l'estensione naturale invece che forzata.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..config import ScanConfig
from ..findings import Finding

#: Callback per lo streaming: riceve (nome_engine, riga).
LineSink = Callable[[str, str], None]


@dataclass
class Availability:
    """Se e come l'engine si puo' eseguire su questa macchina."""

    ok: bool
    detail: str = ""
    #: Percorso dell'eseguibile o dello script, quando trovato.
    path: str = ""
    #: Cosa fare per renderlo disponibile, se non lo e'.
    hint: str = ""


@dataclass
class EngineResult:
    """Esito di una singola esecuzione."""

    engine: str
    returncode: int | None = None
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    #: Errore di orchestrazione (non trovato, timeout, crash del wrapper).
    error: str = ""
    #: File prodotti dall'engine, per gli artifact.
    artifacts: list[Path] = field(default_factory=list)
    skipped: bool = False

    @property
    def ok(self) -> bool:
        # Molti scanner escono con codice != 0 proprio *perche'* hanno trovato
        # qualcosa: il returncode da solo non dice se l'esecuzione e' riuscita.
        return not self.error and not self.skipped


class Engine(ABC):
    """Un tool di scansione, visto dalla suite."""

    #: Identificativo interno, usato nei path e nei finding.
    name: str = ""
    #: Nome mostrato all'utente.
    label: str = ""
    #: Licenza dell'engine, mostrata nella GUI: l'utente deve sapere cosa esegue.
    license: str = ""
    #: Timeout predefinito. vulnapi su un'API media supera abbondantemente i
    #: cinque minuti, quindi il default e' generoso.
    default_timeout_s: float = 3600.0

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._cancelled = False

    # ------------------------------------------------------------------ #
    # Da implementare
    # ------------------------------------------------------------------ #

    @abstractmethod
    def check(self) -> Availability:
        """L'engine e' installato e utilizzabile?"""

    @abstractmethod
    def build_command(self, cfg: ScanConfig) -> list[str]:
        """Riga di comando completa, gia' tradotta nel dialetto dell'engine."""

    @abstractmethod
    def collect(self, cfg: ScanConfig) -> list[Finding]:
        """Legge cio' che l'engine ha prodotto e lo normalizza."""

    # ------------------------------------------------------------------ #
    # Con default ragionevoli
    # ------------------------------------------------------------------ #

    def build_env(self, cfg: ScanConfig) -> dict[str, str]:
        """Ambiente del processo figlio.

        Il default forza UTF-8 e output non bufferizzato: senza, su Windows
        l'output arriva a blocchi da 8 KB e la GUI sembra bloccata, e i
        caratteri non-ASCII fanno esplodere cp1252.
        """
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
        env["NO_COLOR"] = "1"
        env["CLICOLOR"] = "0"
        return env

    def prepare(self, cfg: ScanConfig) -> None:
        """Predisposizione prima dell'esecuzione. Puo' sollevare eccezioni."""

    def working_dir(self, cfg: ScanConfig) -> Path | None:
        return None

    def limitations(self) -> list[str]:
        """Cosa questo engine NON copre, in chiaro.

        Serve alla GUI e al report: un report combinato che tace le lacune di
        ogni engine racconta una copertura che non c'e'.
        """
        return []

    # ------------------------------------------------------------------ #
    # Esecuzione
    # ------------------------------------------------------------------ #

    def cancel(self) -> None:
        """Interrompe l'esecuzione in corso, se ce n'e' una."""
        self._cancelled = True
        proc = self._process
        if proc is not None and proc.poll() is None:
            _terminate_tree(proc)

    def run(self, cfg: ScanConfig, sink: LineSink | None = None,
            timeout_s: float | None = None) -> EngineResult:
        """Esegue l'engine e raccoglie i finding.

        Non solleva eccezioni per i fallimenti dell'engine: le riporta in
        `EngineResult.error`, perche' un engine che fallisce non deve impedire
        agli altri di girare.
        """
        import time

        result = EngineResult(engine=self.name)
        started = time.monotonic()
        self._cancelled = False

        def emit(line: str) -> None:
            if sink is not None:
                sink(self.name, line)

        availability = self.check()
        if not availability.ok:
            result.skipped = True
            result.error = availability.detail or f"{self.label} non disponibile"
            if availability.hint:
                result.error += f" - {availability.hint}"
            emit(f"[!] {result.error}")
            return result

        try:
            self.prepare(cfg)
        except Exception as exc:  # la preparazione tocca il filesystem e la rete
            result.error = f"preparazione fallita: {exc}"
            emit(f"[!] {result.error}")
            return result

        try:
            cmd = self.build_command(cfg)
        except Exception as exc:
            result.error = f"comando non costruibile: {exc}"
            emit(f"[!] {result.error}")
            return result

        emit(f"[*] {self.label}: {_display_cmd(cmd)}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                env=self.build_env(cfg),
                cwd=str(self.working_dir(cfg) or Path.cwd()),
                creationflags=_no_window_flag(),
            )
        except FileNotFoundError:
            result.error = f"eseguibile non trovato: {cmd[0]}"
            emit(f"[!] {result.error}")
            return result
        except Exception as exc:
            result.error = f"avvio fallito: {exc}"
            emit(f"[!] {result.error}")
            return result

        limit = timeout_s if timeout_s is not None else self.default_timeout_s
        killer: threading.Timer | None = None
        timed_out = threading.Event()

        if limit and limit > 0:
            def _on_timeout() -> None:
                timed_out.set()
                proc = self._process
                if proc is not None and proc.poll() is None:
                    _terminate_tree(proc)

            killer = threading.Timer(limit, _on_timeout)
            killer.daemon = True
            killer.start()

        try:
            assert self._process.stdout is not None
            for raw in iter(self._process.stdout.readline, b""):
                line = raw.decode("utf-8", errors="replace")
                # Alcuni tool usano \r per le progress bar: senza questo split
                # la riga non arriva mai a schermo.
                for segment in line.replace("\r\n", "\n").split("\r"):
                    text = segment.rstrip("\n")
                    if text.strip():
                        emit(text)
            self._process.stdout.close()
            result.returncode = self._process.wait()
        except Exception as exc:
            result.error = f"lettura output fallita: {exc}"
        finally:
            if killer is not None:
                killer.cancel()
            self._process = None
            result.duration_s = time.monotonic() - started

        if timed_out.is_set():
            result.error = f"timeout dopo {limit:.0f}s"
            emit(f"[!] {self.label}: {result.error}")
        elif self._cancelled:
            result.error = "interrotto dall'utente"
            emit(f"[!] {self.label}: {result.error}")

        # I finding si raccolgono comunque: un engine interrotto a meta' ha
        # spesso gia' scritto qualcosa, e buttarlo via non aiuta nessuno.
        try:
            result.findings = self.collect(cfg)
            emit(f"[+] {self.label}: {len(result.findings)} finding raccolti "
                 f"in {result.duration_s:.1f}s")
        except Exception as exc:
            if not result.error:
                result.error = f"raccolta finding fallita: {exc}"
            emit(f"[!] {self.label}: raccolta finding fallita: {exc}")

        return result


# ---------------------------------------------------------------------- #
# Utilita'
# ---------------------------------------------------------------------- #

def _no_window_flag() -> int:
    """Evita che ogni engine apra una finestra di console su Windows."""
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Termina il processo e i suoi figli.

    `Popen.terminate()` da solo lascia orfani i figli, e uno scanner che ha
    generato worker continuerebbe a bombardare il bersaglio dopo lo STOP.
    """
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15,
                           creationflags=_no_window_flag())
        else:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        # Ultima spiaggia: se anche taskkill fallisce non c'e' altro da fare
        # qui, e sollevare bloccherebbe lo shutdown della GUI.
        try:
            proc.kill()
        except Exception:
            pass


def _display_cmd(cmd: Iterable[str]) -> str:
    """Comando in forma leggibile, con i segreti oscurati.

    L'output finisce nei log della GUI e negli artifact di CI: un token in
    chiaro li' dentro e' un token pubblicato.
    """
    out: list[str] = []
    redact_next = False
    for part in cmd:
        if redact_next:
            out.append("***")
            redact_next = False
            continue
        lowered = part.lower()
        if any(k in lowered for k in _SECRET_FLAGS):
            out.append(part)
            redact_next = True
            continue
        if " " in part:
            out.append(f'"{part}"')
        else:
            out.append(part)
    return " ".join(out)


_SECRET_FLAGS = (
    "--token", "--secret", "--password", "--apikey", "--api-key",
    "--basic-auth", "--ntlm", "--client-secret", "--cert-password",
    "--login-password", "--oauth2-bearer",
)


def resolve_executable(*candidates: str) -> str:
    """Primo candidato risolvibile: percorso esistente o comando nel PATH."""
    for cand in candidates:
        if not cand:
            continue
        p = Path(cand)
        if p.exists() and p.is_file():
            return str(p.resolve())
        found = shutil.which(cand)
        if found:
            return found
    return ""


def python_executable() -> str:
    """Interprete da usare per gli engine Python.

    `sys.executable` e non "python": la suite puo' girare in un venv, e
    lanciare il "python" del PATH prenderebbe l'interprete sbagliato con le
    dipendenze mancanti.
    """
    return sys.executable or "python"
