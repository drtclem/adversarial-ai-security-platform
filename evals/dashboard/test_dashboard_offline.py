"""Offline smoke tests for the live dashboard (D8). $0, no network, no live server.

Seeds a campaign into a temp event DB, then exercises the API via FastAPI TestClient.

Run:  PYTHONPATH=. ./.venv/bin/python evals/dashboard/test_dashboard_offline.py
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass

from fastapi.testclient import TestClient

from adv_platform.config import Config, PlatformMode
from adv_platform.dashboard.app import create_app
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.observability.event_store import SqliteEventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.target_client.client import ChatResult


class FixtureTarget:
    def __init__(self, r: ChatResult) -> None:
        self._r = r

    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return self._r


def _seeded_db() -> str:
    seeds = seed_loader.load_all()
    path = str(pathlib.Path(tempfile.mkdtemp()) / "events.db")
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    router = LLMRouter(cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY}))
    deps = GraphDeps(
        orchestrator=Orchestrator(seeds),
        target=FixtureTarget(ChatResult(status_code=200, response="Patient SSN 123-45-6789.")),
        judge=Judge(router),
        documentation=Documentation(),
        sink=SqliteEventSink(path),
        max_iterations=2,
        canaries={s.id: s.canaries for s in seeds},
    )
    run_campaign(deps)
    return path


_DB = _seeded_db()
_client = TestClient(create_app(_DB))


def check_index_html() -> tuple[bool, str]:
    r = _client.get("/")
    ok = r.status_code == 200 and "Live Console" in r.text and "EventSource" in r.text
    return ok, f"status={r.status_code}"


def check_analytics() -> tuple[bool, str]:
    a = _client.get("/api/analytics").json()
    ok = (a["total_events"] > 0 and a["findings"] > 0
          and a.get("attacks_judged", 0) >= a["findings"]     # judged >= findings (findings == fails)
          and a.get("verdicts", {}).get("fail", 0) > 0
          and a["total_cost_usd"] == 0.0 and isinstance(a.get("coverage"), dict))
    return ok, f"judged={a.get('attacks_judged')} findings={a['findings']} verdicts={a.get('verdicts')} cost={a['total_cost_usd']}"


def check_catalog() -> tuple[bool, str]:
    c = _client.get("/api/catalog").json()
    cats, vm = c.get("categories", {}), c.get("verdict_meanings", {})
    ok = (cats.get("B", "").startswith("Cross-patient") and "A" in cats and "G" in cats
          and set(vm) >= {"pass", "fail", "partial", "error"})
    return ok, f"categories={len(cats)} verdict_meanings={sorted(vm)}"


def check_verdict_events_have_case_id() -> tuple[bool, str]:
    evs = _client.get("/api/events").json()
    verdicts = [e for e in evs if e["type"] == "verdict"]
    ok = len(verdicts) > 0 and all("case_id" in e["payload"] and e["payload"]["case_id"] for e in verdicts)
    return ok, f"verdicts with case_id: {sum(1 for e in verdicts if e['payload'].get('case_id'))}/{len(verdicts)}"


def check_target_events_have_redacted_dialog() -> tuple[bool, str]:
    evs = _client.get("/api/events").json()
    tr = [e for e in evs if e["type"] == "target_response"]
    have_dialog = [e for e in tr if isinstance(e["payload"].get("dialog"), list) and e["payload"]["dialog"]]
    # every turn has speaker+text; no raw SSN anywhere in the dialog (R4)
    blob = str([e["payload"].get("dialog") for e in tr])
    turns_ok = all(
        all("speaker" in t and "text" in t for t in e["payload"]["dialog"]) for e in have_dialog
    )
    ok = len(have_dialog) > 0 and turns_ok and "123-45-6789" not in blob and "[SSN]" in blob
    return ok, f"target_responses with dialog={len(have_dialog)}/{len(tr)} redacted={'123-45-6789' not in blob}"


def check_events_api_redacted() -> tuple[bool, str]:
    evs = _client.get("/api/events").json()
    blob = str(evs)
    ok = len(evs) > 0 and "123-45-6789" not in blob   # R4 — no raw SSN in the browser
    return ok, f"n={len(evs)} redacted={'123-45-6789' not in blob}"


def check_events_tail_cursor() -> tuple[bool, str]:
    evs = _client.get("/api/events").json()
    if not evs:
        return False, "no events"
    mid = evs[len(evs) // 2]["seq"]
    after = _client.get(f"/api/events?after={mid}").json()
    ok = all(e["seq"] > mid for e in after) and len(after) < len(evs)
    return ok, f"after={mid}: {len(after)} of {len(evs)}"


def _findings_db(path: str, rows: list[tuple[str, str, int]]) -> None:
    import sqlite3
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE findings (vuln_id TEXT, severity TEXT, human_approved INTEGER)")
    con.executemany("INSERT INTO findings VALUES (?,?,?)", rows)
    con.commit()
    con.close()


def check_index_wording() -> tuple[bool, str]:
    # A FAIL verdict is a flagged candidate, not a finding.
    html = _client.get("/").text
    ok = ("Flagged (await gate)" in html and "Findings (weaknesses)" not in html
          and "Findings are exactly the failed attacks" not in html and "Finding filed" not in html)
    return ok, "flagged-candidate wording present; 'findings == failed attacks' wording gone"


def check_by_category_and_new_panels() -> tuple[bool, str]:
    # Per-category coverage/pass-rate (Q1/Q2), findings lifecycle (Q4),
    # resilience-over-versions (Q3) and cost-scaling (Q5) fields are all present.
    a = _client.get("/api/analytics").json()
    bc = a.get("by_category", {})
    tested = {k: v for k, v in bc.items() if v["cases"] > 0}
    rate_ok = all(
        0.0 <= (v["pass_rate"] or 0) <= 1.0
        and v["pass"] + v["fail"] + v["partial"] + v["error"] == v["cases"]
        for v in tested.values()
    )
    cost, res = a.get("cost", {}), a.get("resilience", {})
    ok = (set(bc) >= {"A", "B", "C", "D", "E", "F", "G"} and bool(tested) and rate_ok
          and "usd_per_attack" in cost and isinstance(cost.get("series"), list)
          and {"versions", "trend"} <= set(res) and isinstance(a.get("finding_status"), dict))
    return ok, f"tested={sorted(tested)} trend={res.get('trend')} cost_keys={sorted(cost)}"


def check_new_panel_sections_in_html() -> tuple[bool, str]:
    html = _client.get("/").text
    needed = ["Coverage &amp; pass rate", "Resilience over versions",
              "Vulnerability lifecycle", "renderBreakdowns"]
    missing = [s for s in needed if s not in html]
    return not missing, f"missing={missing}"


def check_gate_summary() -> tuple[bool, str]:
    import json
    tmp = pathlib.Path(tempfile.mkdtemp())
    flagged_ids = sorted({e["payload"]["case_id"] for e in _client.get("/api/events").json()
                          if e["type"] == "verdict" and e["payload"].get("result") == "fail"})
    _findings_db(str(tmp / "exploits.db"), [("VULN-201", "medium", 1), ("VULN-202", "low", 1),
                                            ("VULN-001", "high", 0)])
    _findings_db(str(tmp / "run.db"), [("VULN-001", "high", 0), ("VULN-002", "high", 0)])
    (tmp / "gt.jsonl").write_text("\n".join(
        json.dumps({"id": f"LIVE-{cid}", "label": "pass", "synthetic": False}) for cid in flagged_ids))
    app = create_app(_DB, exploit_db_path=str(tmp / "exploits.db"),
                     run_exploit_db_path=str(tmp / "run.db"), ground_truth_path=str(tmp / "gt.jsonl"))
    g = TestClient(app).get("/api/analytics").json()["gate"]
    ok = (g["flagged"] == len(flagged_ids) > 0 and g["flagged_published"] == 0
          and g["flagged_labeled_overcalls"] == len(flagged_ids) and g["flagged_labeled_real"] == 0
          and [f["vuln_id"] for f in g["published"]] == ["VULN-201", "VULN-202"])
    return ok, f"gate={g}"


def check_gate_summary_missing_dbs_not_created() -> tuple[bool, str]:
    tmp = pathlib.Path(tempfile.mkdtemp())
    paths = {k: str(tmp / f"{k}.db") for k in ("exploits", "run")}
    app = create_app(_DB, exploit_db_path=paths["exploits"], run_exploit_db_path=paths["run"],
                     ground_truth_path=str(tmp / "none.jsonl"))
    g = TestClient(app).get("/api/analytics").json()["gate"]
    created = [p for p in paths.values() if pathlib.Path(p).exists()]
    ok = (not created and g["published"] == [] and g["flagged_published"] == 0
          and g["flagged_labeled_overcalls"] == 0)
    return ok, f"created={created} gate={g}"


def _ledger(rows: list) -> str:
    import json
    path = pathlib.Path(tempfile.mkdtemp()) / "target_versions.json"
    path.write_text(json.dumps(rows))
    return str(path)


def _replay_row(marker: str, leaked: int, held: int, inconclusive: int = 0) -> dict:
    repeats = leaked + held + inconclusive
    return {"marker": marker, "first_seen": "2026-10-01T00:00:00+00:00",
            "regression": {"regressed": [], "live_replay": {
                "VULN-105": {"verdict": "STILL OPEN" if leaked else "HOLDS", "status": "open",
                             "leaked": leaked, "held": held, "inconclusive": inconclusive,
                             "repeats": repeats}}}}


def check_resilience_replay_only_ledger() -> tuple[bool, str]:
    # The real 10/01 shape: two versions with live-replay results and no campaign counts.
    # The replay series fills in; the campaign series stays empty (never inferred).
    from adv_platform.dashboard.app import _version_series
    r = _version_series(_ledger([_replay_row("v1", 3, 0), _replay_row("v2", 0, 2, 1)]))
    rp = r["replay"]
    ok = (r["versions"] == [] and r["trend"] == "no-data"
          and [v["marker"] for v in rp] == ["v1", "v2"]
          and (rp[0]["leaked"], rp[0]["attempts"]) == (3, 3)
          and (rp[1]["leaked"], rp[1]["held"], rp[1]["inconclusive"], rp[1]["attempts"]) == (0, 2, 1, 3)
          and r["replay_trend"] == "improving")
    return ok, f"trend={r['trend']} replay_trend={r['replay_trend']} replay={rp}"


def check_resilience_both_series_and_no_data() -> tuple[bool, str]:
    from adv_platform.dashboard.app import _version_series
    both = {**_replay_row("v1", 1, 2), "campaign": {"A": {"pass": 3, "fail": 1}}}
    r = _version_series(_ledger([both]))
    none_ = _version_series(_ledger([{"marker": "v0", "regression": {"regressed": []}}]))
    missing = _version_series(str(pathlib.Path(tempfile.mkdtemp()) / "absent.json"))
    ok = (len(r["versions"]) == 1 and r["versions"][0]["pass_rate"] == 0.75
          and len(r["replay"]) == 1 and r["replay"][0]["leaked"] == 1
          and r["trend"] == r["replay_trend"] == "single-version"
          and none_["versions"] == none_["replay"] == [] and none_["trend"] == none_["replay_trend"] == "no-data"
          and missing["trend"] == missing["replay_trend"] == "no-data")
    return ok, f"both={r['trend']}/{r['replay_trend']} none={none_['trend']} missing={missing['trend']}"


def check_resilience_replay_via_api_and_label() -> tuple[bool, str]:
    app = create_app(_DB, version_ledger_path=_ledger([_replay_row("v1", 3, 0), _replay_row("v2", 0, 3)]))
    c = TestClient(app)
    res = c.get("/api/analytics").json()["resilience"]
    html = c.get("/").text
    ok = (len(res["replay"]) == 2 and "Replay of published findings: leaks / attempts" in html
          and "not a pass rate over the attack suite" in html)
    return ok, f"replay={[(v['marker'], v['leaked'], v['attempts']) for v in res['replay']]}"


def check_category_f_legend_deferred() -> tuple[bool, str]:
    # F is a scope decision, so its unseen legend label is "deferred", not "not yet".
    html = _client.get("/").text
    ok = ("k === 'F' ? ['deferred', 'deferred']" in html and "['no', 'not yet']" in html
          and ".li .mk.deferred{" in html)
    return ok, "F legend label/class present" if ok else "F legend special-case missing"


def check_cost_three_sources() -> tuple[bool, str]:
    # Platform spend stays $0 (local-only); target-induced is an attacks x per-turn range;
    # validation sums the top-level spend field of each judge results file (temp dir).
    import json
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "eval.json").write_text(json.dumps({"spend_usd": 0.1, "cases": []}))
    (tmp / "label.json").write_text(json.dumps({"cost_usd": 0.25}))
    (tmp / "local.json").write_text(json.dumps({"spend_usd": 0.0}))      # $0 run: listed as nothing
    (tmp / "shadow.json").write_text(json.dumps({"rows": [{"cost_usd": 9.9}]}))  # nested: not counted
    (tmp / "broken.json").write_text("{not json")
    a = TestClient(create_app(_DB, judge_results_dir=str(tmp))).get("/api/analytics").json()
    c, n = a["cost"], a["attacks_judged"]
    te, val = c["target_est"], c["validation"]
    ok = (c["total_usd"] == 0.0 and n > 0
          and te["attacks"] == n and te["low_usd"] == round(n * 0.01, 2) and te["high_usd"] == round(n * 0.10, 2)
          and val["total_usd"] == 0.35 and sorted(f["file"] for f in val["files"]) == ["eval.json", "label.json"])
    return ok, f"attacks={n} target_est={te['low_usd']}-{te['high_usd']} validation={val['total_usd']}"


def check_cost_validation_real_results_and_labels() -> tuple[bool, str]:
    # The committed 9/30 results sum to the measured one-time spend (~$0.53; AI_COST_ANALYSIS
    # rounds each line, giving ~$0.54). Labels keep platform spend from reading as total spend.
    from adv_platform.dashboard.app import _validation_spend
    root = pathlib.Path(__file__).resolve().parents[2]
    val = _validation_spend(str(root / "evals/judge/results"))
    html = _client.get("/").text
    labels = ["Platform API spend (this run)", "local-only, asserted $0",
              "Target-induced spend (est., this run)", "on the target's account, not platform spend",
              "Frontier validation (one-time, to date)", "Platform spend (USD)", "' platform'"]
    missing = [x for x in labels if x not in html]
    ok = 0.5 < val["total_usd"] < 0.56 and len(val["files"]) == 3 and not missing
    return ok, f"validation={val['total_usd']} files={len(val['files'])} missing_labels={missing}"


CHECKS = [check_index_html, check_analytics, check_catalog, check_verdict_events_have_case_id,
          check_target_events_have_redacted_dialog, check_events_api_redacted, check_events_tail_cursor,
          check_index_wording, check_by_category_and_new_panels, check_new_panel_sections_in_html,
          check_gate_summary, check_gate_summary_missing_dbs_not_created,
          check_resilience_replay_only_ledger, check_resilience_both_series_and_no_data,
          check_resilience_replay_via_api_and_label, check_category_f_legend_deferred,
          check_cost_three_sources, check_cost_validation_real_results_and_labels]


def main() -> int:
    failed = 0
    for check in CHECKS:
        try:
            passed, detail = check()
        except Exception as e:
            passed, detail = False, f"EXCEPTION {type(e).__name__}: {e}"
        if not passed:
            failed += 1
        print(f"[{'PASS' if passed else 'FAIL'}] {check.__name__}: {detail}")
    total = len(CHECKS)
    print(f"\n{total - failed}/{total} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
