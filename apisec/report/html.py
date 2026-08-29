"""Report HTML unificato.

Un solo file autocontenuto, senza risorse esterne: finisce negli artifact di CI,
negli allegati e nelle cartelle condivise, dove un CDN non e' raggiungibile.

E' un'interfaccia a tutti gli effetti, quindi vale la regola di progetto: deve
funzionare anche sul telefono. Concretamente significa niente tabelle a
scorrimento orizzontale (le righe diventano schede sotto i 720 px), corpo del
testo a 16 px, bersagli tattili da 48 px, contrasto sopra 4.5:1 e rispetto di
`prefers-color-scheme` e `prefers-reduced-motion`.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from ..config import ScanConfig
from ..findings import Finding, OWASP_API_2023, Severity, count_by_severity
from .merge import MergeStats, coverage_matrix, risk_score

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                   Severity.LOW, Severity.INFO]

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critico",
    Severity.HIGH: "Alto",
    Severity.MEDIUM: "Medio",
    Severity.LOW: "Basso",
    Severity.INFO: "Informativo",
}


def write_html(findings: Sequence[Finding], dest: Path, *,
               cfg: ScanConfig | None = None,
               stats: MergeStats | None = None,
               analysis: Any = None,
               engine_results: Sequence[Any] = (),
               limitations: dict[str, list[str]] | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        render_html(findings, cfg=cfg, stats=stats, analysis=analysis,
                    engine_results=engine_results, limitations=limitations),
        encoding="utf-8",
    )
    return dest


def render_html(findings: Sequence[Finding], *,
                cfg: ScanConfig | None = None,
                stats: MergeStats | None = None,
                analysis: Any = None,
                engine_results: Sequence[Any] = (),
                limitations: dict[str, list[str]] | None = None) -> str:
    counts = count_by_severity(findings)
    score = risk_score(findings)
    generated = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    target = html.escape(cfg.target_url if cfg else "")

    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Report sicurezza API — {target or 'apisec-suite'}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="hdr">
  <div class="wrap">
    <p class="eyebrow">apisec-suite · report unificato</p>
    <h1>{target or "Scansione API"}</h1>
    <p class="meta">Generato il {generated}{_engines_line(engine_results)}</p>
  </div>
</header>

<main class="wrap">
  {_score_section(score, counts, len(findings))}
  {_analysis_section(analysis)}
  {_stats_section(stats)}
  {_coverage_section(findings)}
  {_findings_section(findings)}
  {_engines_section(engine_results, limitations)}
  {_config_section(cfg)}
</main>

<footer class="wrap ftr">
  <p>Prodotto da <strong>apisec-suite</strong>, che orchestra VulnAPI (MIT) e
  APISCAN (AGPL-3.0). I risultati sono indicazioni da verificare, non una
  prova di sfruttabilita'.</p>
</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------- #
# Sezioni
# ---------------------------------------------------------------------- #

def _score_section(score: float, counts: dict[str, int], total: int) -> str:
    tiles = "".join(
        f'<div class="tile s-{sev.value}">'
        f'<span class="tile-n">{counts[sev.value]}</span>'
        f'<span class="tile-l">{_SEVERITY_LABEL[sev]}</span></div>'
        for sev in _SEVERITY_ORDER
    )
    band = ("critical" if score >= 70 else "high" if score >= 40
            else "medium" if score >= 15 else "low")
    return f"""
<section aria-labelledby="h-sintesi">
  <h2 id="h-sintesi">Quadro generale</h2>
  <div class="score-row">
    <div class="score sc-{band}">
      <span class="score-n">{score:g}</span>
      <span class="score-l">rischio / 100</span>
    </div>
    <div class="tiles">{tiles}</div>
  </div>
  <p class="muted">{total} finding dopo la fusione dei duplicati.</p>
</section>"""


def _analysis_section(analysis: Any) -> str:
    if analysis is None:
        return ""
    summary = getattr(analysis, "executive_summary", "") or ""
    paths = list(getattr(analysis, "attack_paths", []) or [])
    priorities = list(getattr(analysis, "priorities", []) or [])
    errors = list(getattr(analysis, "errors", []) or [])
    if not (summary or paths or priorities or errors):
        return ""

    provider = html.escape(str(getattr(analysis, "provider", "") or ""))
    model = html.escape(str(getattr(analysis, "model", "") or ""))
    badge = " · ".join(p for p in (provider, model) if p)

    blocks = []
    if summary:
        blocks.append(f"<p>{html.escape(summary)}</p>")
    if priorities:
        blocks.append("<h3>Priorita'</h3><ol>" + "".join(
            f"<li>{html.escape(p)}</li>" for p in priorities) + "</ol>")
    if paths:
        blocks.append("<h3>Percorsi di attacco</h3><ul>" + "".join(
            f"<li>{html.escape(p)}</li>" for p in paths) + "</ul>")
    if errors:
        blocks.append('<p class="warn">Analisi parziale: ' + html.escape(
            "; ".join(errors)) + "</p>")

    return f"""
<section class="card ai" aria-labelledby="h-ai">
  <h2 id="h-ai">Analisi LLM {f'<span class="badge">{badge}</span>' if badge else ''}</h2>
  {''.join(blocks)}
  <p class="muted small">Il verdetto del modello annota i finding, non li
  rimuove: un'indicazione di falso positivo va verificata, non creduta.</p>
</section>"""


def _stats_section(stats: MergeStats | None) -> str:
    if stats is None:
        return ""
    return f"""
<section aria-labelledby="h-fusione">
  <h2 id="h-fusione">Fusione</h2>
  <p>{html.escape(stats.summary())}</p>
</section>"""


def _coverage_section(findings: Sequence[Finding]) -> str:
    matrix = coverage_matrix(findings)
    engines = sorted({e for row in matrix.values() for e in row})
    if not engines:
        return ""

    head = "".join(f"<th scope='col'>{html.escape(e)}</th>" for e in engines)
    rows = []
    for key, label in OWASP_API_2023.items():
        row = matrix.get(key, {})
        cells = "".join(
            f"<td data-l='{html.escape(e)}'>"
            f"{'<span class=hit>' + str(row[e]) + '</span>' if row.get(e) else '<span class=dash>—</span>'}"
            f"</td>"
            for e in engines
        )
        rows.append(
            f"<tr><th scope='row'><span class='api'>{key}</span> "
            f"<span class='apil'>{html.escape(label)}</span></th>{cells}</tr>")

    unclassified = matrix.get("(non classificato)", {})
    if any(unclassified.values()):
        cells = "".join(
            f"<td data-l='{html.escape(e)}'>"
            f"{'<span class=hit>' + str(unclassified[e]) + '</span>' if unclassified.get(e) else '<span class=dash>—</span>'}"
            f"</td>" for e in engines)
        rows.append(f"<tr><th scope='row'><span class='apil'>Non classificato"
                    f"</span></th>{cells}</tr>")

    return f"""
<section aria-labelledby="h-cov">
  <h2 id="h-cov">Copertura per categoria OWASP</h2>
  <p class="muted">Le celle vuote di un engine sono le lacune che l'altro copre.
  E' il motivo per cui vengono eseguiti insieme.</p>
  <div class="tablewrap">
    <table class="cov">
      <thead><tr><th scope="col">Categoria</th>{head}</tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>"""


def _findings_section(findings: Sequence[Finding]) -> str:
    if not findings:
        return ('<section><h2>Finding</h2><p class="ok">Nessun finding '
                'registrato.</p></section>')

    items = []
    for index, finding in enumerate(findings, start=1):
        items.append(_finding_card(index, finding))

    return f"""
<section aria-labelledby="h-find">
  <h2 id="h-find">Finding ({len(findings)})</h2>
  <div class="findings">{''.join(items)}</div>
</section>"""


def _finding_card(index: int, f: Finding) -> str:
    sev = f.severity
    chips = [f'<span class="chip s-{sev.value}">{_SEVERITY_LABEL[sev]}</span>']
    if f.cvss:
        estimate = " (stima)" if f.cvss_estimated else ""
        chips.append(f'<span class="chip">CVSS {f.cvss:g}{html.escape(estimate)}</span>')
    for owasp in f.owasp:
        chips.append(f'<span class="chip owasp">{html.escape(owasp)}</span>')
    for cwe in f.cwe:
        chips.append(f'<span class="chip">{html.escape(cwe)}</span>')
    for engine in (f.corroborated_by or [f.engine]):
        chips.append(f'<span class="chip eng">{html.escape(engine)}</span>')
    if len(f.corroborated_by) > 1:
        chips.append('<span class="chip corr">confermato da piu\' engine</span>')
    if f.llm_verdict:
        chips.append(f'<span class="chip llm v-{html.escape(f.llm_verdict)}">'
                     f'LLM: {html.escape(f.llm_verdict)}</span>')

    endpoint = f"{f.method} {f.normalized_path}".strip()
    body = []
    if f.description:
        body.append(f"<p>{html.escape(f.description)}</p>")
    if f.llm_rationale:
        body.append(f'<p class="rationale">{html.escape(f.llm_rationale)}</p>')
    if f.remediation:
        body.append(f'<p class="fix"><strong>Rimedio.</strong> '
                    f'{html.escape(f.remediation)}</p>')

    evidence = f.evidence.summary()
    if evidence:
        body.append(
            "<details><summary>Prova</summary>"
            f"<pre>{html.escape(evidence[:4000])}</pre></details>")

    return f"""
<article class="finding b-{sev.value}" id="f{index}">
  <h3><span class="num">{index}</span> {html.escape(f.title)}</h3>
  {f'<p class="ep"><code>{html.escape(endpoint)}</code></p>' if endpoint else ''}
  <div class="chips">{''.join(chips)}</div>
  {''.join(body)}
  <p class="muted small">Regola: <code>{html.escape(f.rule_id)}</code></p>
</article>"""


def _engines_section(engine_results: Sequence[Any],
                     limitations: dict[str, list[str]] | None) -> str:
    if not engine_results and not limitations:
        return ""

    rows = []
    for result in engine_results:
        name = html.escape(str(getattr(result, "engine", "")))
        count = len(getattr(result, "findings", []) or [])
        duration = getattr(result, "duration_s", 0.0)
        error = str(getattr(result, "error", "") or "")
        skipped = bool(getattr(result, "skipped", False))
        state = ("saltato" if skipped else "errore" if error else "completato")
        cls = "err" if (error or skipped) else "ok"
        detail = html.escape(error) if error else f"{count} finding"
        rows.append(f"<tr><th scope='row'>{name}</th>"
                    f"<td data-l='Esito'><span class='{cls}'>{state}</span></td>"
                    f"<td data-l='Dettaglio'>{detail}</td>"
                    f"<td data-l='Durata'>{duration:.1f}s</td></tr>")

    table = ""
    if rows:
        table = f"""
  <div class="tablewrap">
    <table>
      <thead><tr><th scope="col">Engine</th><th scope="col">Esito</th>
      <th scope="col">Dettaglio</th><th scope="col">Durata</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>"""

    limits = ""
    if limitations:
        blocks = []
        for engine, items in limitations.items():
            if not items:
                continue
            lis = "".join(f"<li>{html.escape(i)}</li>" for i in items)
            blocks.append(f"<h3>{html.escape(engine)}</h3><ul>{lis}</ul>")
        if blocks:
            limits = ('<div class="limits"><h3 class="lh">Cosa questa scansione '
                      'NON copre</h3>' + "".join(blocks) + "</div>")

    return f"""
<section aria-labelledby="h-eng">
  <h2 id="h-eng">Engine eseguiti</h2>{table}{limits}
</section>"""


def _config_section(cfg: ScanConfig | None) -> str:
    if cfg is None:
        return ""
    payload = json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2, default=str)
    return f"""
<section aria-labelledby="h-cfg">
  <h2 id="h-cfg">Configurazione</h2>
  <details>
    <summary>Parametri della scansione (credenziali oscurate)</summary>
    <pre>{html.escape(payload)}</pre>
  </details>
</section>"""


def _engines_line(engine_results: Sequence[Any]) -> str:
    names = [str(getattr(r, "engine", "")) for r in engine_results
             if not getattr(r, "skipped", False)]
    return f" · engine: {html.escape(', '.join(names))}" if names else ""


# ---------------------------------------------------------------------- #

_CSS = """
:root{
  --bg:#ffffff; --fg:#16181d; --muted:#5c6370; --card:#f6f7f9; --line:#dfe3e8;
  --accent:#1f6feb; --crit:#a4133c; --high:#c2410c; --med:#8a6d00;
  --low:#1f6feb; --info:#5c6370; --ok:#166534;
  --radius:12px;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0d1117; --fg:#e6edf3; --muted:#9aa4b2; --card:#161b22; --line:#30363d;
    --accent:#58a6ff; --crit:#ff7b8a; --high:#f0883e; --med:#d9a441;
    --low:#58a6ff; --info:#9aa4b2; --ok:#3fb950;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0; background:var(--bg); color:var(--fg);
  font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  padding-bottom:env(safe-area-inset-bottom);
}
.wrap{max-width:64rem;margin:0 auto;padding:0 1rem}
.hdr{
  background:var(--card); border-bottom:1px solid var(--line);
  padding:1.5rem 0 1.25rem; padding-top:calc(1.5rem + env(safe-area-inset-top));
  margin-bottom:1.5rem;
}
.eyebrow{margin:0 0 .25rem;font-size:.8125rem;color:var(--muted);
  text-transform:uppercase;letter-spacing:.08em}
h1{margin:0;font-size:clamp(1.35rem,4vw,2rem);line-height:1.25;word-break:break-word}
h2{font-size:clamp(1.1rem,3vw,1.4rem);margin:2.25rem 0 .75rem;
  padding-bottom:.4rem;border-bottom:1px solid var(--line)}
h3{font-size:1.0625rem;margin:1.1rem 0 .4rem}
.meta{margin:.4rem 0 0;color:var(--muted);font-size:.9375rem}
.muted{color:var(--muted)} .small{font-size:.875rem}
code{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.9em;
  background:var(--card);padding:.1em .35em;border-radius:4px;word-break:break-all}
pre{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:.9rem;overflow-x:auto;font-size:.8125rem;line-height:1.5;
  white-space:pre-wrap;word-break:break-word}

.score-row{display:flex;flex-wrap:wrap;gap:1rem;align-items:stretch}
.score{flex:0 0 auto;min-width:8.5rem;padding:1rem 1.25rem;border-radius:var(--radius);
  border:2px solid var(--line);display:flex;flex-direction:column;justify-content:center}
.score-n{font-size:2.5rem;font-weight:700;line-height:1}
.score-l{font-size:.8125rem;color:var(--muted)}
.sc-critical{border-color:var(--crit)} .sc-critical .score-n{color:var(--crit)}
.sc-high{border-color:var(--high)} .sc-high .score-n{color:var(--high)}
.sc-medium{border-color:var(--med)} .sc-medium .score-n{color:var(--med)}
.sc-low{border-color:var(--ok)} .sc-low .score-n{color:var(--ok)}

.tiles{flex:1 1 20rem;display:grid;gap:.5rem;
  grid-template-columns:repeat(auto-fit,minmax(5.5rem,1fr))}
.tile{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:.6rem .5rem;text-align:center;min-height:3.5rem;
  display:flex;flex-direction:column;justify-content:center}
.tile-n{font-size:1.5rem;font-weight:700;line-height:1.1}
.tile-l{font-size:.75rem;color:var(--muted)}
.tile.s-critical .tile-n{color:var(--crit)} .tile.s-high .tile-n{color:var(--high)}
.tile.s-medium .tile-n{color:var(--med)} .tile.s-low .tile-n{color:var(--low)}

.card{background:var(--card);border:1px solid var(--line);
  border-radius:var(--radius);padding:1rem 1.1rem;margin-top:1.25rem}
.card h2{margin-top:0;border:none;padding:0}
.badge{font-size:.75rem;font-weight:400;color:var(--muted);
  border:1px solid var(--line);border-radius:999px;padding:.15rem .55rem;
  vertical-align:middle;margin-left:.4rem}
.rationale{color:var(--muted);border-left:3px solid var(--line);
  padding-left:.75rem;margin-left:0}
.fix{background:var(--card);border-left:3px solid var(--ok);padding:.6rem .75rem;
  border-radius:0 6px 6px 0}
.warn{color:var(--high)} .ok{color:var(--ok)} .err{color:var(--crit)}

.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.9375rem}
th,td{text-align:left;padding:.55rem .6rem;border-bottom:1px solid var(--line);
  vertical-align:top}
thead th{font-size:.8125rem;text-transform:uppercase;letter-spacing:.04em;
  color:var(--muted);white-space:nowrap}
.api{font-weight:600} .apil{color:var(--muted);font-size:.875rem}
.hit{font-weight:700;color:var(--accent)} .dash{color:var(--muted)}

.findings{display:flex;flex-direction:column;gap:.85rem}
.finding{background:var(--card);border:1px solid var(--line);
  border-left-width:4px;border-radius:var(--radius);padding:.9rem 1rem}
.finding h3{margin:0 0 .35rem;display:flex;gap:.5rem;align-items:baseline;
  word-break:break-word}
.num{color:var(--muted);font-weight:400;font-size:.875rem;flex:0 0 auto}
.b-critical{border-left-color:var(--crit)} .b-high{border-left-color:var(--high)}
.b-medium{border-left-color:var(--med)} .b-low{border-left-color:var(--low)}
.b-info{border-left-color:var(--info)}
.ep{margin:.25rem 0 .5rem}
.chips{display:flex;flex-wrap:wrap;gap:.35rem;margin:.5rem 0}
.chip{font-size:.75rem;padding:.2rem .55rem;border-radius:999px;
  border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.chip.s-critical{color:var(--crit);border-color:var(--crit)}
.chip.s-high{color:var(--high);border-color:var(--high)}
.chip.s-medium{color:var(--med);border-color:var(--med)}
.chip.owasp{color:var(--accent);border-color:var(--accent)}
.chip.corr{color:var(--ok);border-color:var(--ok)}
.chip.v-falso-positivo{color:var(--muted)}
.chip.v-confermato{color:var(--crit);border-color:var(--crit)}

details{margin:.6rem 0 0}
summary{cursor:pointer;color:var(--accent);font-size:.9375rem;
  min-height:48px;display:flex;align-items:center;padding:.25rem 0}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.limits{margin-top:1.25rem;border:1px solid var(--line);border-radius:var(--radius);
  padding:.9rem 1rem;background:var(--card)}
.limits .lh{margin-top:0} .limits ul{margin:.3rem 0 .8rem;padding-left:1.2rem}
.ftr{margin:2.5rem 0 2rem;color:var(--muted);font-size:.875rem;
  border-top:1px solid var(--line);padding-top:1rem}

@media (max-width:720px){
  /* Le tabelle diventano schede: nessuno scorrimento orizzontale sul telefono. */
  table,thead,tbody,tr,th,td{display:block}
  thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
  tr{border:1px solid var(--line);border-radius:var(--radius);
    margin-bottom:.6rem;padding:.5rem .7rem}
  th,td{border:none;padding:.3rem 0}
  tr>th[scope=row]{font-weight:700;border-bottom:1px solid var(--line);
    margin-bottom:.3rem;padding-bottom:.4rem}
  td::before{content:attr(data-l) " · ";color:var(--muted);font-size:.8125rem}
}
@media (prefers-reduced-motion:reduce){
  *{animation:none!important;transition:none!important}
}
"""
