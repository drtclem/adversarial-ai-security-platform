"""Live dashboard (D8/D9) — PLATFORM ZONE.

A FastAPI app that tails the SQLite event substrate and tells the STORY of a run:
one card per attack case (Orchestrator picked it → Red Team sent it → Target
replied → Judge ruled → Documentation drafted a candidate), plus an at-a-glance analytics headline
(a FAIL verdict is a flagged candidate; only the D4 human gate publishes a finding) and
plain-language legends for categories and verdicts. Read-only over the event store;
payloads are PHI-redacted at emit time (R4), so nothing raw reaches the browser.

Run:  ./.venv/bin/python -m uvicorn adv_platform.dashboard.app:app --port 8799
Local-only, $0.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from adv_platform.config import Config
from adv_platform.models import EventType
from adv_platform.observability.event_store import SqliteEventSink

# Plain-language names so a first-time viewer understands the taxonomy.
CATEGORY_NAMES: dict[str, str] = {
    "A": "Indirect prompt injection",
    "B": "Cross-patient PHI / authorization bypass",
    "C": "Verification bypass (ungrounded claim)",
    "D": "Multi-turn safeguard erosion",
    "E": "System-prompt / config leakage",
    "F": "Unbounded consumption / denial-of-wallet",
    "G": "Insecure output handling",
}
VERDICT_MEANINGS: dict[str, str] = {
    "pass": "target defended — no weakness",
    "fail": "weakness found → becomes a finding",
    "partial": "partial success — mutation candidate",
    "error": "couldn't complete (never counted as a pass)",
}


def _approved_findings(db_path: str) -> list[tuple[str, str]]:
    """(vuln_id, severity) of human-approved findings, read-only. A missing DB is
    empty — never created (a fresh clone has no platform_data/)."""
    if not Path(db_path).exists():
        return []
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT vuln_id, severity FROM findings WHERE human_approved = 1 ORDER BY vuln_id"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        con.close()
    return [(str(v), str(s)) for v, s in rows]


def _finding_status_counts(db_path: str) -> dict[str, int]:
    """Findings by lifecycle status (open / in_progress / resolved / regressed /
    published), read-only. A missing DB is empty — never created.

    `resolved` is split: a finding the human gate REJECTED (never approved: a Judge
    over-call, not a vulnerability) is `rejected_at_gate`, so "resolved" only ever
    means a real vulnerability that was fixed."""
    if not Path(db_path).exists():
        return {}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT CASE WHEN status = 'resolved' AND human_approved = 0 "
            "THEN 'rejected_at_gate' ELSE status END, COUNT(*) FROM findings GROUP BY 1"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        con.close()
    return {str(s): int(n) for s, n in rows}


def _trend(series: list[dict[str, Any]], key: str, higher_is_better: bool) -> str:
    if len(series) >= 2:
        d = series[-1][key] - series[-2][key]
        if not higher_is_better:
            d = -d
        return "improving" if d > 0.02 else "declining" if d < -0.02 else "flat"
    return "single-version" if len(series) == 1 else "no-data"


def _version_series(ledger_path: str) -> dict[str, Any]:
    """Resilience over time, from the version ledger (`platform_data/target_versions.json`).

    Two series per operator-stamped TARGET_VERSION marker, each only where the ledger
    has that data (never inferred):
      * `versions` — campaign pass rate (`campaign` per-category counts);
      * `replay`   — the version-triggered live replay of PUBLISHED findings
                     (`regression.live_replay`): leaks / attempts, plus inconclusive.
                     This re-tests known vulns only; it is not a pass rate over the
                     attack suite, and the two series are never merged.
    Empty/absent ledger, or neither kind of data → trend "no-data"."""
    empty = {"versions": [], "trend": "no-data", "replay": [], "replay_trend": "no-data"}
    p = Path(ledger_path)
    if not p.exists():
        return empty
    try:
        rows = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return empty
    series: list[dict[str, Any]] = []
    replay: list[dict[str, Any]] = []
    for r in rows:
        agg: Counter[str] = Counter()
        for counts in (r.get("campaign") or {}).values():
            for k, n in counts.items():
                agg[k] += n
        total = sum(agg.values())
        if total:
            series.append({
                "marker": r.get("marker"),
                "first_seen": r.get("first_seen"),
                "cases": total,
                "pass": agg.get("pass", 0),
                "fail": agg.get("fail", 0) + agg.get("partial", 0),
                "pass_rate": round(agg.get("pass", 0) / total, 3),
                "regressed": (r.get("regression") or {}).get("regressed", []),
            })
        live = (r.get("regression") or {}).get("live_replay") or {}
        attempts = sum(int(x.get("repeats", 0)) for x in live.values())
        if attempts:
            leaked = sum(int(x.get("leaked", 0)) for x in live.values())
            replay.append({
                "marker": r.get("marker"),
                "first_seen": r.get("first_seen"),
                "vulns": len(live),
                "attempts": attempts,
                "leaked": leaked,
                "held": sum(int(x.get("held", 0)) for x in live.values()),
                "inconclusive": sum(int(x.get("inconclusive", 0)) for x in live.values()),
                "leak_rate": round(leaked / attempts, 3),
                "regressed": sorted(v for v, x in live.items() if x.get("verdict") == "REGRESSED"),
                "by_vuln": {v: {k: x.get(k) for k in ("verdict", "status", "leaked", "held",
                                                     "inconclusive", "repeats")}
                            for v, x in sorted(live.items())},
            })
    return {"versions": series, "trend": _trend(series, "pass_rate", True),
            "replay": replay, "replay_trend": _trend(replay, "leak_rate", False)}


def _human_labels(path: str) -> dict[str, str]:
    """case_id -> human label ('pass'/'fail') for real campaign cases in the judge
    ground-truth set (ids `LIVE-<case_id>`). Missing file → no labels."""
    p = Path(path)
    if not p.exists():
        return {}
    labels: dict[str, str] = {}
    for line in p.read_text().splitlines():
        if not line.strip():
            continue
        c = json.loads(line)
        if str(c.get("id", "")).startswith("LIVE-") and not c.get("synthetic"):
            labels[c["id"][len("LIVE-"):]] = c["label"]
    return labels


def _gate_summary(events: list, paths: dict[str, str]) -> dict[str, Any]:
    """What happened to the local judge's FAIL verdicts at the human gate.
    A FAIL is a flagged CANDIDATE, not a finding: only the D4 gate publishes."""
    flagged = sorted({str(e.payload.get("case_id")) for e in events
                      if e.type is EventType.VERDICT and e.payload.get("result") == "fail"})
    labels = _human_labels(paths["ground_truth"])
    published = _approved_findings(paths["exploit_db"])
    return {
        "flagged": len(flagged),
        "flagged_published": len(_approved_findings(paths["run_exploit_db"])),
        "flagged_labeled_overcalls": sum(1 for c in flagged if labels.get(c) == "pass"),
        "flagged_labeled_real": sum(1 for c in flagged if labels.get(c) == "fail"),
        "published": [{"vuln_id": v, "severity": s} for v, s in published],
    }


# Target-induced unit cost: the Co-Pilot's own model bill per chat turn, Week-2 measured
# range (AI_COST_ANALYSIS.md). An estimate on the TARGET's account, never platform spend.
TARGET_USD_PER_TURN = (0.01, 0.10)
_SPEND_KEYS = ("spend_usd", "cost_usd", "spend")


def _validation_spend(results_dir: str) -> dict[str, Any]:
    """One-time frontier validation spend to date: the top-level spend field of each
    evals/judge/results/*.json (Judge eval, consistency, labeler check). Read-only;
    a file without a spend field contributes nothing. Never inferred."""
    files: list[dict[str, Any]] = []
    for f in sorted(Path(results_dir).glob("*.json")):
        try:
            d = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(d, dict):
            continue
        usd = next((d[k] for k in _SPEND_KEYS if isinstance(d.get(k), (int, float))), None)
        if usd:
            files.append({"file": f.name, "usd": round(float(usd), 6)})
    return {"total_usd": round(sum(x["usd"] for x in files), 6), "files": files,
            "source": "evals/judge/results/*.json"}


def _analytics(sink: SqliteEventSink, paths: dict[str, str]) -> dict[str, Any]:
    events = sink.all()
    by_type: Counter[str] = Counter(e.type.value for e in events)
    verdicts: Counter[str] = Counter(
        str(e.payload.get("result", "?")) for e in events if e.type is EventType.VERDICT
    )
    coverage: Counter[str] = Counter(
        str(e.payload.get("category")) for e in events
        if e.type is EventType.MESSAGE_SENT and e.payload.get("category")
    )

    # Per-category coverage + pass/fail rate, from the verdicts themselves (every judged
    # case has a category), so "cases per category" is accurate even when message_sent
    # events are sparse. (Q1 categories tested + count; Q2 pass/fail rate per category.)
    cat_verdicts: dict[str, Counter[str]] = {}
    for e in events:
        if e.type is EventType.VERDICT:
            cat = str(e.payload.get("category") or "?")
            cat_verdicts.setdefault(cat, Counter())[str(e.payload.get("result", "?"))] += 1
    by_category: dict[str, Any] = {}
    for cat in CATEGORY_NAMES:
        c = cat_verdicts.get(cat, Counter())
        total = sum(c.values())
        by_category[cat] = {
            "name": CATEGORY_NAMES[cat],
            "cases": total,
            "pass": c.get("pass", 0),
            "fail": c.get("fail", 0),
            "partial": c.get("partial", 0),
            "error": c.get("error", 0),
            "pass_rate": round(c.get("pass", 0) / total, 3) if total else None,
            "tested": total > 0,
        }

    # Cost + rate of scaling (Q5): total, per-attack, and cumulative spend sampled at
    # each judged attack in emission order. In local-only mode this is all $0 by design.
    judged = by_type.get(EventType.VERDICT.value, 0)
    total_cost = round(sink.total_cost_usd(), 6)
    cost_series: list[dict[str, Any]] = []
    cum, idx = 0.0, 0
    for e in events:
        if e.cost_usd:
            cum += e.cost_usd
        if e.type is EventType.VERDICT:
            idx += 1
            cost_series.append({"n": idx, "cum_usd": round(cum, 6)})

    return {
        "total_events": len(events),
        "attacks_judged": judged,
        "by_type": dict(by_type),
        "verdicts": dict(verdicts),
        "findings": by_type.get(EventType.FINDING_CREATED.value, 0),
        "coverage": dict(coverage),
        "by_category": by_category,
        "finding_status": _finding_status_counts(paths["exploit_db"]),
        "resilience": _version_series(paths["version_ledger"]),
        "total_cost_usd": total_cost,
        "cost": {
            # platform API spend, this run (the only cost the platform itself pays)
            "total_usd": total_cost,
            "usd_per_attack": round(total_cost / judged, 6) if judged else 0.0,
            "series": cost_series,
            # estimate of what this run's attacks cost the TARGET's model account
            "target_est": {
                "attacks": judged,
                "usd_per_turn_low": TARGET_USD_PER_TURN[0],
                "usd_per_turn_high": TARGET_USD_PER_TURN[1],
                "low_usd": round(judged * TARGET_USD_PER_TURN[0], 2),
                "high_usd": round(judged * TARGET_USD_PER_TURN[1], 2),
            },
            # one-time frontier Judge validation, to date (not per run)
            "validation": _validation_spend(paths["judge_results"]),
        },
        "gate": _gate_summary(events, paths),
    }


def _event_dict(seq: int, e) -> dict[str, Any]:
    return {"seq": seq, "type": e.type.value, "agent": e.agent.value if e.agent else None,
            "zone": e.zone.value, "correlation_id": e.correlation_id,
            "payload": e.payload, "cost_usd": e.cost_usd,
            "created_at": e.created_at.isoformat()}


def create_app(db_path: str | None = None, *, exploit_db_path: str | None = None,
               run_exploit_db_path: str | None = None,
               ground_truth_path: str | None = None,
               version_ledger_path: str | None = None,
               judge_results_dir: str | None = None) -> FastAPI:
    cfg = Config.load()
    path = db_path or cfg.event_store_path
    sink = SqliteEventSink(path)
    # Read-only lookups for the gate summary (curated published findings, this run's
    # flagged candidates, the human labels on real campaign cases) and the version
    # ledger (per-version resilience over time).
    gate_paths = {
        "exploit_db": exploit_db_path or cfg.exploit_db_path,
        "run_exploit_db": run_exploit_db_path
        or os.environ.get("RUN_EXPLOIT_DB_PATH", "./platform_data/exploits_run.db"),
        "ground_truth": ground_truth_path
        or str(Path(__file__).resolve().parents[2] / "evals/judge/ground_truth/cases.jsonl"),
        "version_ledger": version_ledger_path or cfg.version_ledger_path,
        "judge_results": judge_results_dir
        or str(Path(__file__).resolve().parents[2] / "evals/judge/results"),
    }
    app = FastAPI(title="Adversarial AI Security Platform — Live Console")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _INDEX_HTML

    @app.get("/api/catalog")
    def catalog() -> JSONResponse:
        return JSONResponse({"categories": CATEGORY_NAMES, "verdict_meanings": VERDICT_MEANINGS})

    @app.get("/api/events")
    def events(after: int = 0) -> JSONResponse:
        return JSONResponse([_event_dict(seq, e) for seq, e in sink.tail(after)])

    @app.get("/api/analytics")
    def analytics() -> JSONResponse:
        return JSONResponse(_analytics(sink, gate_paths))

    @app.get("/stream")
    async def stream(after: int = 0):
        async def gen():
            cursor = after
            while True:
                for seq, e in sink.tail(cursor):
                    cursor = seq
                    yield {"data": json.dumps(_event_dict(seq, e))}
                await asyncio.sleep(1.0)
        return EventSourceResponse(gen())

    return app


app = create_app()


_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Adversarial AI Security — Live Console</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#c9d1d9; --muted:#8b949e;
          --pass:#3fb950; --fail:#f85149; --partial:#d29922; --error:#a371f7; --accent:#58a6ff; }
  * { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
      font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; }
  header { padding:12px 16px; border-bottom:1px solid var(--border); display:flex;
           align-items:center; gap:12px; position:sticky; top:0; background:var(--bg); z-index:2; }
  h1 { font-size:15px; margin:0; font-weight:600; } h2 { font-size:12px; color:var(--muted);
       margin:18px 0 8px; text-transform:uppercase; letter-spacing:.05em; }
  .dot { width:9px;height:9px;border-radius:50%; background:var(--pass); box-shadow:0 0 8px var(--pass); }
  .grow { flex:1; } .cost { color:var(--muted); }
  .wrap { max-width:1000px; margin:0 auto; padding:16px; }
  .headline { background:var(--panel); border:1px solid var(--border); border-radius:8px;
              padding:14px 16px; font-size:16px; line-height:1.6; }
  .headline b.fail{color:var(--fail);} .headline b.pass{color:var(--pass);} .headline b.find{color:var(--partial);}
  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:12px; }
  .tile { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
  .tile .k{color:var(--muted);font-size:11px;} .tile .v{font-size:20px;font-weight:600;margin-top:3px;}
  .legends { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  @media(max-width:720px){ .legends{grid-template-columns:1fr;} }
  .legend { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
  .legend .li { display:flex; gap:8px; padding:2px 0; font-size:12.5px; }
  .legend .tag { flex:none; min-width:60px; font-weight:600; }
  .badge { font-size:11px; font-weight:700; padding:1px 7px; border-radius:10px; border:1px solid; }
  .b-pass{color:var(--pass);border-color:var(--pass);} .b-fail{color:var(--fail);border-color:var(--fail);}
  .b-partial{color:var(--partial);border-color:var(--partial);} .b-error{color:var(--error);border-color:var(--error);}
  .cat-A .tag{color:#ff7b72;} .cat-B .tag{color:#f85149;} .cat-C .tag{color:#d29922;}
  .case { background:var(--panel); border:1px solid var(--border); border-radius:8px; margin-bottom:8px; overflow:hidden; }
  .case-h { display:flex; align-items:center; gap:10px; padding:10px 12px; cursor:pointer; }
  .case-h:hover { background:#1c2230; } .case-h .cid{font-weight:600;} .case-h .cat{color:var(--muted);}
  .case-h .find{color:var(--partial);margin-left:auto;font-weight:600;} .chev{color:var(--muted);transition:transform .15s;}
  .open .chev{transform:rotate(90deg);}
  .steps { display:none; padding:4px 12px 12px 12px; border-top:1px solid var(--border); }
  .open .steps { display:block; }
  .step { display:flex; gap:10px; padding:3px 0; font-size:12.5px; }
  .step .n{color:var(--accent);flex:none;} .step .who{color:var(--muted);flex:none;min-width:96px;}
  .step .ev{color:var(--fail);} .step .pv{color:var(--pass);}
  details.tx{margin:6px 0 2px 106px;} details.tx summary{cursor:pointer;color:var(--accent);font-size:12px;}
  .turn{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #11161d;font-size:12.5px;}
  .turn .who2{flex:none;min-width:64px;font-weight:600;} .turn.attacker .who2{color:var(--fail);}
  .turn.target .who2{color:var(--accent);} .turn .msg{white-space:pre-wrap;word-break:break-word;color:var(--fg);}
  .li .mk{margin-left:auto;font-size:11px;} .li .mk.yes{color:var(--pass);} .li .mk.no{color:var(--muted);} .li .mk.deferred{color:var(--muted);font-style:italic;}
  .empty{color:var(--muted);padding:20px;text-align:center;}
  .ctable{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden;font-size:12.5px;}
  .ctable th,.ctable td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);}
  .ctable th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;}
  .ctable tr:last-child td{border-bottom:none;} .ctable td.num{text-align:right;font-variant-numeric:tabular-nums;}
  .bar{position:relative;height:8px;border-radius:4px;background:#21262d;overflow:hidden;min-width:70px;}
  .bar>span{position:absolute;left:0;top:0;bottom:0;background:var(--pass);}
  .muted2{color:var(--muted);}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:10px 12px;}
  .trend-improving{color:var(--pass);} .trend-declining{color:var(--fail);}
  .trend-flat,.trend-single-version,.trend-no-data,.trend-insufficient-data{color:var(--muted);}
  .spark{display:flex;align-items:flex-end;gap:3px;height:34px;margin-top:6px;}
  .spark .b{flex:1;background:var(--accent);border-radius:2px 2px 0 0;min-height:2px;}
  .stat-row{display:flex;gap:8px;padding:2px 0;font-size:12.5px;}
  .stat-row .tag{min-width:96px;color:var(--muted);flex:none;}
</style></head>
<body>
<header><span class="dot" id="dot"></span><h1>Adversarial AI Security — Live Console</h1>
  <span class="grow"></span><span class="cost" id="cost">$0.000000 platform</span></header>
<div class="wrap">
  <div class="headline" id="headline">Waiting for events…</div>
  <div class="tiles" id="tiles"></div>
  <h2>What the labels mean</h2>
  <div class="legends">
    <div class="legend" id="catLegend"></div>
    <div class="legend" id="verdictLegend"></div>
  </div>
  <h2>Coverage &amp; pass rate by attack category</h2>
  <div id="catTable"><div class="empty">No cases yet.</div></div>
  <h2>Resilience over versions — is the target getting harder to break?</h2>
  <div id="resilience"></div>
  <h2>Vulnerability lifecycle &amp; run cost</h2>
  <div class="legends">
    <div class="legend" id="findingStatus"></div>
    <div class="legend" id="costPanel"></div>
  </div>
  <h2>Attack cases — click any to expand the step-by-step</h2>
  <div id="cases"><div class="empty">No cases yet.</div></div>
</div>
<script>
const $=s=>document.querySelector(s);
let CATS={}, VMEAN={}, EVENTS=[], renderTimer=null;
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function loadCatalog(){
  try{ const c=await (await fetch('/api/catalog')).json(); CATS=c.categories; VMEAN=c.verdict_meanings; renderLegends(); }catch(e){}
}
function renderLegends(){
  $('#verdictLegend').innerHTML = '<div class="k" style="color:var(--muted);font-size:11px;margin-bottom:4px;">VERDICTS</div>'
    + Object.entries(VMEAN).map(([k,v])=>`<div class="li"><span class="badge b-${k} tag">${k}</span><span>${v}</span></div>`).join('');
}
function catLegend(seen){
  const rows = Object.keys(CATS).map(k=>{
    const t = seen.has(k);
    // F (unbounded consumption) is a deliberate scope decision, not an untested gap:
    // exercising it means driving up spend on a live target, so it was deferred by choice.
    const [cls, label] = t ? ['yes', '✓ tested'] : k === 'F' ? ['deferred', 'deferred'] : ['no', 'not yet'];
    return `<div class="li cat-${k}" style="opacity:${t?1:.55}"><span class="tag">${k}</span>`
      + `<span>${CATS[k]}</span><span class="mk ${cls}">${label}</span></div>`;
  }).join('');
  $('#catLegend').innerHTML = '<div class="k" style="color:var(--muted);font-size:11px;margin-bottom:4px;">CATEGORIES (A–G) — coverage</div>'+rows;
}
function badge(r){ return `<span class="badge b-${r}">${(r||'?').toUpperCase()}</span>`; }

function groupCases(){
  const g=new Map();
  for(const e of EVENTS){
    if(['target_response','verdict','finding_created'].includes(e.type)){
      if(!g.has(e.correlation_id)) g.set(e.correlation_id,{cid:e.correlation_id});
      const c=g.get(e.correlation_id);
      if(e.type==='target_response'){ c.case_id=e.payload.case_id; c.category=e.payload.category; c.turns=e.payload.turns; c.error=e.payload.error; c.dialog=e.payload.dialog||[]; }
      if(e.type==='verdict'){ c.result=e.payload.result; c.evidence=e.payload.evidence; c.det=e.payload.deterministic; c.case_id=c.case_id||e.payload.case_id; c.category=c.category||e.payload.category; }
      if(e.type==='finding_created'){ c.vuln=e.payload.vuln_id; c.sev=e.payload.severity; }
    }
  }
  return [...g.values()].filter(c=>c.case_id);
}
function renderCases(){
  const cases=groupCases();
  const seen=new Set(cases.map(c=>c.category));
  catLegend(seen);
  if(!cases.length){ $('#cases').innerHTML='<div class="empty">No cases yet.</div>'; return; }
  $('#cases').innerHTML = cases.map(c=>{
    const cat=CATS[c.category]||c.category;
    const findTxt = c.vuln? `→ ${c.vuln} (${c.sev})` : (c.result==='pass'?'defended':'');
    const how = c.det? 'deterministic pre-filter ($0)':'LLM judge';
    const step3 = c.error? `<span class="ev">tool/target error: ${c.error}</span>` : 'Target responded';
    const step5 = c.vuln
      ? `<span class="ev">Candidate drafted ${c.vuln} (${c.sev})</span> — flagged, awaits the human gate (D4); not a finding until approved`
      : (c.result==='pass' ? '<span class="pv">Nothing flagged — target defended</span>' : 'Nothing drafted');
    const dlg = c.dialog||[];
    const txHtml = dlg.length ? `<details class="tx"><summary>Show transcript — ${dlg.length} turn${dlg.length>1?'s':''} (redacted)</summary>`
      + dlg.map(t=>`<div class="turn ${t.speaker==='attacker'?'attacker':'target'}">`
        + `<span class="who2">${t.speaker==='attacker'?'Attacker':'Target'}</span>`
        + `<span class="msg">${esc(t.text)}</span></div>`).join('') + `</details>` : '';
    return `<div class="case" id="case-${c.cid}">
      <div class="case-h" onclick="document.getElementById('case-${c.cid}').classList.toggle('open')">
        <span class="chev">▶</span>${badge(c.result)}
        <span class="cid">${c.case_id}</span><span class="cat">${cat}</span>
        <span class="find">${findTxt}</span></div>
      <div class="steps">
        <div class="step"><span class="n">①</span><span class="who">Orchestrator</span><span>queued category ${c.category} — ${cat}</span></div>
        <div class="step"><span class="n">②</span><span class="who">Red Team</span><span>sent a ${c.turns||'?'}-turn attack to the target</span></div>
        <div class="step"><span class="n">③</span><span class="who">Target</span><span>${step3}</span></div>
        <div class="step"><span class="n">④</span><span class="who">Judge</span><span>ruled ${badge(c.result)} via ${how}${c.evidence?` · <span class="cat">${c.evidence}</span>`:''}</span></div>
        <div class="step"><span class="n">⑤</span><span class="who">Documentation</span><span>${step5}</span></div>
        ${txHtml}
      </div></div>`;
  }).join('');
}
async function renderAnalytics(){
  try{
    const a=await (await fetch('/api/analytics')).json();
    $('#cost').textContent='$'+Number(a.total_cost_usd).toFixed(6)+' platform';
    const v=a.verdicts||{}, judged=a.attacks_judged||0, failed=v.fail||0, passed=v.pass||0, finds=a.findings||0;
    const extra=[]; if(v.partial)extra.push(`${v.partial} partial`); if(v.error)extra.push(`${v.error} error`);
    // A FAIL verdict is a flagged CANDIDATE, not a finding: only the human gate publishes.
    const g=a.gate||{}, pub=g.published||[], flagged=g.flagged??failed, fpub=g.flagged_published||0;
    const oc=g.flagged_labeled_overcalls||0, real=g.flagged_labeled_real||0, unl=Math.max(0, flagged-oc-real);
    const why = flagged===0 ? '' : ' ('+[
      oc===flagged ? 'all over-calls' : (oc ? `${oc} over-call${oc>1?'s':''}` : ''),
      real ? `${real} labeled real` : '', unl ? `${unl} awaiting review` : ''
    ].filter(Boolean).join(', ')+')';
    const sev={}; pub.forEach(f=>{ const k=(f.severity||'?')[0].toUpperCase(); sev[k]=(sev[k]||0)+1; });
    const sevTxt=Object.entries(sev).map(([k,n])=>`${n} ${k}`).join(' · ');
    $('#headline').innerHTML =
      `<b>${judged}</b> attacks judged → <b class="pass">${passed} passed</b> · `
      + `<b class="fail">${flagged} flagged</b> by the local judge → human gate → `
      + `<b class="find">${fpub} of these published</b>${why}`
      + `${extra.length?` · ${extra.join(', ')}`:''}. `
      + `<span class="cost">${pub.length} finding${pub.length===1?'':'s'} published overall`
      + `${pub.length?` (${sevTxt}: ${pub.map(f=>f.vuln_id).join(', ')})`:''}.</span>`;
    $('#tiles').innerHTML =
      `<div class="tile"><div class="k">Attacks judged</div><div class="v">${judged}</div></div>`
     +`<div class="tile"><div class="k">Flagged (await gate)</div><div class="v">${finds}</div></div>`
     +`<div class="tile"><div class="k">Passed (defended)</div><div class="v">${passed}</div></div>`
     +`<div class="tile"><div class="k">Platform spend (USD)</div><div class="v">$${Number(a.total_cost_usd).toFixed(4)}</div></div>`;
    renderBreakdowns(a);
  }catch(e){ $('#dot').style.background='var(--error)'; }
}
function pct(x){ return x==null?'—':(Math.round(x*100)+'%'); }
function renderBreakdowns(a){
  // Coverage + pass rate per category (Q1 cases per category, Q2 rate per category).
  const bc=a.by_category||{};
  const rows=Object.entries(bc).map(([k,c])=>{
    const bar = c.cases? `<div class="bar"><span style="width:${Math.round((c.pass_rate||0)*100)}%"></span></div>` : '<span class="muted2">—</span>';
    const dim = c.tested? '' : ' class="muted2"';
    return `<tr${dim}><td><b>${k}</b> ${esc(c.name)}</td>`
      +`<td class="num">${c.cases||0}</td><td class="num">${c.pass||0}</td>`
      +`<td class="num">${c.fail||0}${c.partial?`+${c.partial}p`:''}${c.error?` ${c.error}e`:''}</td>`
      +`<td>${bar}</td><td class="num">${c.cases?pct(c.pass_rate):'not tested'}</td></tr>`;
  }).join('');
  $('#catTable').innerHTML = `<table class="ctable"><thead><tr>`
    +`<th>Category</th><th class="num">Cases</th><th class="num">Passed</th>`
    +`<th class="num">Flagged</th><th>Pass rate</th><th class="num"></th></tr></thead><tbody>${rows}</tbody></table>`;

  // Resilience over versions (Q3), from the version ledger. Two series, shown separately
  // and only where present: campaign pass rate, and the replay of published findings.
  const r=a.resilience||{versions:[],trend:'no-data',replay:[],replay_trend:'no-data'};
  const vs=r.versions||[], rp=r.replay||[];
  const trendTxt=t=>({improving:'▲ more resilient',declining:'▼ less resilient',flat:'▬ unchanged','single-version':'one version so far','no-data':'no data','insufficient-data':'need 2+ versions'}[t]||t);
  if(!vs.length && !rp.length){
    $('#resilience').innerHTML = `<div class="panel muted2">No versioned results yet. Stamp <code>TARGET_VERSION</code> when the target is redeployed and this fills in — campaign pass rate and a replay of published findings per version, so you can see whether it is becoming more or less resilient.</div>`;
  } else {
    let html='';
    if(vs.length){
      const bars = vs.map(v=>`<div class="b" title="${esc(v.marker||'?')}: ${pct(v.pass_rate)}" style="height:${Math.max(2,Math.round((v.pass_rate||0)*100))}%"></div>`).join('');
      const list = vs.map(v=>`<div class="stat-row"><span class="tag">${esc(v.marker||'?')}</span>`
        +`<span>${v.pass}/${v.cases} passed · <b>${pct(v.pass_rate)}</b>${(v.regressed&&v.regressed.length)?` · <span class="b-fail">${v.regressed.length} regressed</span>`:''}</span></div>`).join('');
      html += `<div class="panel"><div>Campaign pass rate per version — trend: <b class="trend-${r.trend}">${trendTxt(r.trend)}</b></div>`
        +`<div class="spark">${bars}</div>${list}</div>`;
    } else {
      html += `<div class="panel muted2">Campaign pass rate per version: no campaign has run against a stamped <code>TARGET_VERSION</code> yet.</div>`;
    }
    if(rp.length){
      const list = rp.map(v=>`<div class="stat-row"><span class="tag">${esc(v.marker||'?')}</span>`
        +`<span><b>${v.leaked}/${v.attempts}</b> leaked · ${v.held} held · ${v.inconclusive} inconclusive · ${v.vulns} published finding${v.vulns===1?'':'s'}`
        +`${(v.regressed&&v.regressed.length)?` · <span class="b-fail">${v.regressed.length} regressed</span>`:''}</span></div>`).join('');
      html += `<div class="panel"><div>Replay of published findings: leaks / attempts — trend: <b class="trend-${r.replay_trend}">${trendTxt(r.replay_trend)}</b></div>`
        +`<div class="muted2" style="font-size:11.5px;margin:2px 0 4px;">Re-tests known vulnerabilities only (deterministic leak markers); not a pass rate over the attack suite, and not finding closure. A finding can stay OPEN even at 0 leaks if a human read finds a residual (e.g. VULN-105, partially mitigated). A replay that holds is a fix candidate until a human reads it.</div>${list}</div>`;
    }
    $('#resilience').innerHTML = html;
  }

  // Vulnerability lifecycle: open / in progress / resolved / regressed / published (Q4).
  const fs=a.finding_status||{}, order=['open','in_progress','published','regressed','resolved','rejected_at_gate'];
  const labelmap={open:'Open (unreviewed)',in_progress:'In progress',published:'Open (confirmed)',regressed:'Regressed',resolved:'Resolved (fixed)',rejected_at_gate:'Rejected at gate (over-call)'};
  const keys=order.filter(k=>fs[k]!=null).concat(Object.keys(fs).filter(k=>!order.includes(k)));
  const fsRows = keys.length? keys.map(k=>`<div class="stat-row"><span class="tag">${labelmap[k]||k}</span><span><b>${fs[k]}</b></span></div>`).join('')
    : '<span class="muted2">No findings recorded yet.</span>';
  $('#findingStatus').innerHTML = '<div class="k" style="color:var(--muted);font-size:11px;margin-bottom:4px;">VULNERABILITY LIFECYCLE</div>'+fsRows;

  // Cost + rate of scaling (Q5).
  const cost=a.cost||{total_usd:a.total_cost_usd||0,usd_per_attack:0,series:[]}, cs=cost.series||[];
  const cmax=Math.max(1e-9,...cs.map(p=>p.cum_usd));
  const cbars=cs.length?`<div class="spark">`+cs.map(p=>`<div class="b" title="after ${p.n}: $${p.cum_usd.toFixed(6)}" style="height:${Math.max(2,Math.round(p.cum_usd/cmax*100))}%"></div>`).join('')+`</div>`:'';
  const rateNote = cost.total_usd>0? 'Cumulative curve shows the scaling rate as attacks accrue.' : 'In live mode this shows platform spend per attack and the cumulative curve.';
  const n=a.attacks_judged||0, money=x=>'$'+Number(x).toFixed(2);
  const te=cost.target_est||{attacks:n,usd_per_turn_low:0.01,usd_per_turn_high:0.10,low_usd:n*0.01,high_usd:n*0.10};
  const val=cost.validation||{total_usd:0,files:[]};
  const platLabel = cost.total_usd>0 ? '' : ' <span class="muted2">(local-only, asserted $0)</span>';
  const valTxt = val.files&&val.files.length
    ? `<b>${money(val.total_usd)}</b> <span class="muted2">across ${val.files.length} Judge-validation run${val.files.length===1?'':'s'} (one-time, 2026-09-30; see AI_COST_ANALYSIS.md)</span>`
    : '<span class="muted2">none recorded</span>';
  $('#costPanel').innerHTML = '<div class="k" style="color:var(--muted);font-size:11px;margin-bottom:4px;">COST &amp; SCALING RATE</div>'
    +`<div class="stat-row"><span class="tag">Platform API spend (this run)</span><span><b>$${Number(cost.total_usd).toFixed(6)}</b>${platLabel} over ${n} attacks · $${Number(cost.usd_per_attack).toFixed(6)}/attack</span></div>`
    +`<div class="stat-row"><span class="tag">Target-induced spend (est., this run)</span><span>${te.attacks} attacks × $${Number(te.usd_per_turn_low).toFixed(2)}–${Number(te.usd_per_turn_high).toFixed(2)} ≈ <b>${money(te.low_usd)}–${money(te.high_usd)}</b> <span class="muted2">on the target's account, not platform spend; per turn, so multi-turn attacks cost more</span></span></div>`
    +`<div class="stat-row"><span class="tag">Frontier validation (one-time, to date)</span><span>${valTxt}</span></div>`
    +`<div class="muted2" style="font-size:11.5px;margin-top:2px;">${rateNote}</div>${cbars}`;
}
function scheduleRender(){ if(renderTimer)return; renderTimer=setTimeout(()=>{renderTimer=null; renderCases(); renderAnalytics();},120); }

const es=new EventSource('/stream');
es.onmessage=e=>{ EVENTS.push(JSON.parse(e.data)); scheduleRender(); };
es.onerror=()=>{ $('#dot').style.background='var(--error)'; };
loadCatalog(); renderAnalytics();
</script></body></html>
"""
