"""First LIVE campaign against the real target — LOCAL-ONLY, $0.

Runs the full LangGraph loop (Orchestrator -> Red Team[LLM mutation + adaptive
escalation] -> Judge -> Documentation) against the real Co-Pilot over HTTP, with the
LOCAL judge + deterministic pre-filter, persisting to the SQLite event store (for the
dashboard) and the exploit DB (dedupe + findings), then renders the VULN report.

Guardrails enforced HERE, not trusted:
  * Forces PLATFORM_MODE=local-only and ASSERTS it — no frontier/paid path reachable.
  * Asserts every agent role routes to the LOCAL backend.
  * After the run, asserts total spend == $0 (sink + router). Any non-zero aborts loud.
  * The client's own host allow-list keeps every request on the target / its auth host.

Requires: VPN up (target localhost is only reachable over VPN) and
TARGET_USERNAME / TARGET_PASSWORD in .env.

Run:  PYTHONPATH=. ./.venv/bin/python scripts/run_live_campaign.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Force local-only BEFORE any config load — belt-and-suspenders ($0 guarantee).
os.environ["PLATFORM_MODE"] = "local-only"
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

from adv_platform.config import Config, PlatformMode
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.judge import Judge
from adv_platform.judge.shadow import build_shadow
from adv_platform.harness.version_trigger import VersionLedger, live_gate
from adv_platform.llm.router import LLMRouter
from adv_platform.models import AgentRole
from adv_platform.observability.event_store import SqliteEventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.storage.exploit_db import ExploitDB
from adv_platform.storage.report import render_markdown
from adv_platform.target_client.client import TargetClient

# Scope: all present categories. B is expected to ERROR (broken snapshot worker) —
# an error is a distinct state, never a pass (R11).
MUTATIONS_PER_SEED = 2
MAX_ESCALATIONS = 1
MAX_ATTACKS_PER_BRIEF = 8


def _abort(msg: str) -> None:
    print(f"\n!!! ABORT: {msg}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    cfg = Config.load()

    # ── hard guardrails ──────────────────────────────────────────────────────
    if cfg.platform_mode is not PlatformMode.LOCAL_ONLY:
        _abort(f"expected local-only, got {cfg.platform_mode}. Refusing (paid-call risk).")
    router = LLMRouter(cfg)
    for role in AgentRole:
        if router.backend_for(role) != "local":
            _abort(f"{role.value} routes to {router.backend_for(role)} — must be local in local-only.")
    print(f"mode={cfg.platform_mode.value}  target={cfg.target_base_url}  "
          f"local_model={cfg.local_model}")
    print("All roles route LOCAL. Judge/Docs are LOCAL here — $0.\n")

    if not (cfg.target_username and cfg.target_password):
        _abort("TARGET_USERNAME / TARGET_PASSWORD missing in .env.")

    # ── local completion for the Red Team (always local, $0) ─────────────────
    def redteam_complete(prompt, system=None, temperature=None, max_tokens=None) -> str:
        r = router.complete(AgentRole.REDTEAM, prompt, system=system,
                            temperature=temperature or 0.9, max_tokens=max_tokens or 400)
        if r.cost_usd != 0.0:
            _abort("Red Team incurred non-zero cost — local must be $0.")
        return r.text

    # ── build the target client + login ──────────────────────────────────────
    print("Connecting to target (VPN must be up) and authenticating...")
    client = TargetClient(
        base_url=cfg.target_base_url,
        username=cfg.target_username,
        password=cfg.target_password,
        auth_host=cfg.target_auth_host,
    )
    try:
        client.login()
    except Exception as e:
        _abort(f"login failed ({type(e).__name__}: {e}). Is the VPN up?")
    print("Authenticated OK.\n")

    # ── deps: persist events (dashboard) + findings (exploit DB) ─────────────
    seeds = seed_loader.load_all()
    present = Orchestrator(seeds).categories_with_seeds()
    sink = SqliteEventSink(cfg.event_store_path)
    # FRESH_RUN=1 → clean slate for a pristine demo run (removes prior + any
    # contaminated events before this campaign writes).
    if os.environ.get("FRESH_RUN") == "1":
        removed = sink.clear()
        print(f"FRESH_RUN: cleared {removed} prior event(s) from {cfg.event_store_path}\n")
    # Campaign auto-findings go to a RUN-SCOPED exploit DB so they never overwrite the
    # curated, human-approved VRs in the main store (reports/ + finalize_reports.py).
    run_exploit_db_path = os.environ.get("RUN_EXPLOIT_DB_PATH", "./platform_data/exploits_run.db")
    exploit_db = ExploitDB(run_exploit_db_path)
    findings_db = ExploitDB(cfg.exploit_db_path)
    print(f"Run-scoped exploit DB (auto-findings): {run_exploit_db_path}\n"
          f"Curated findings store (human-approved VRs) untouched: {cfg.exploit_db_path}\n")
    deps = GraphDeps(
        orchestrator=Orchestrator(seeds),
        target=client,
        # JUDGE_SHADOW=laya adds the calibrated-classifier tier in shadow mode (decides nothing)
        judge=Judge(router, shadow=build_shadow(cfg)),
        documentation=Documentation(),
        sink=sink,
        # Upper bound only: the finding-aware Orchestrator halts on its own (no new
        # signal / every category exhausted) and may revisit a category that keeps
        # producing new signal, up to max_visits_per_category.
        max_iterations=len(present) * Orchestrator(seeds).max_visits_per_category,
        max_attacks=MAX_ATTACKS_PER_BRIEF,
        canaries={s.id: s.canaries for s in seeds},
        redteam_complete=redteam_complete,
        mutations_per_seed=MUTATIONS_PER_SEED,
        max_escalations=MAX_ESCALATIONS,
        exploit_db=exploit_db,
        # Curated, human-gated findings (published/resolved) steer the Orchestrator.
        # READ-ONLY: the graph never writes this store.
        findings_db=findings_db,
        sentinel_check=True,        # re-score 5 known-answer cases before trusting the Judge
        # TARGET_VERSION (operator-stamped at deploy) -> a new version runs the full
        # regression suite before attacking; every transcript is stamped with it.
        target_version=cfg.target_version or None,
        version_ledger=VersionLedger(cfg.version_ledger_path),
        # A new version replays every published VULN against the live target (3x each)
        # on top of the stored-fixture check — the regression suite talks to the new build.
        regression_gate=live_gate(client.chat_sequence, marker=cfg.target_version or None),
    )
    print(f"Categories present: {[c.value for c in present]}  "
          f"(mutations/seed={MUTATIONS_PER_SEED}, max_escalations={MAX_ESCALATIONS})\n"
          f"Launching campaign...\n" + "=" * 78)

    try:
        state = run_campaign(deps)
    finally:
        client.close()

    # ── post-run guardrail: prove $0 ─────────────────────────────────────────
    sink_cost = sink.total_cost_usd()
    router_cost = router.spend.total_usd
    print("=" * 78)
    print(f"\nSpend — sink=${sink_cost:.4f}  router=${router_cost:.4f}")
    if sink_cost != 0.0 or router_cost != 0.0:
        _abort("NON-ZERO SPEND on a local-only run — investigate before trusting results.")

    # ── version trigger: did the target change, and did anything regress? ───
    vc = state.get("version_check") or {}
    if vc:
        if vc["action"] == "skipped-no-marker":
            print("\nTarget version: NOT SET (TARGET_VERSION empty) — regression trigger skipped.")
        elif vc["action"] == "unchanged":
            print(f"\nTarget version: {vc['marker']} (unchanged) — no regression run needed.")
        else:
            status = (f"REGRESSION DETECTED: {vc['regressed']}" if vc["blocked"]
                      else f"no fixed vuln reappeared ({vc['fixtures']} case(s) checked)")
            print(f"\nTarget version: {vc['previous'] or '(none)'} -> {vc['marker']} — "
                  f"regression suite ran: {status}")
            rows = VersionLedger(cfg.version_ledger_path).load()
            for vid, r in ((rows[-1].get("regression") or {}).get("live_replay") or {}).items():
                print(f"  live replay {vid} [{r['status']}]: {r['verdict']} "
                      f"(leaked {r['leaked']}/{r['repeats']}, inconclusive {r['inconclusive']})")

    for f in state.get("cross_category") or []:
        print(f"CROSS-CATEGORY REGRESSION: {f['note']} "
              f"({f['from_version']} -> {f['to_version']}; fail rate {f['improved']} "
              f"{f['improved_fail_rate']}, {f['worsened']} {f['worsened_fail_rate']})")

    # ── judge sentinels: was the Judge trustworthy for this run? ─────────────
    js = state.get("judge_sentinel") or {}
    if js:
        tag = "TRUSTED" if js.get("trusted") else "UNTRUSTED — review every verdict by hand"
        print(f"\nJudge sentinels: {tag}  ({js.get('reason')})")
        for r in js.get("results", []):
            print(f"  {r['id']:<28} expected={r['expected']:<4} got={r['got']}")

    # ── orchestrator decisions: why each category, and why it stopped ────────
    print("\nOrchestrator decisions:")
    for d in state.get("decisions", []):
        if d["category"]:
            top = sorted(d["scores"].items(), key=lambda kv: -kv[1]["total"])[:3]
            ranked = ", ".join(f"{k}={v['total']}" for k, v in top)
            print(f"  iter {d['iteration']}: -> {d['category']}  (top: {ranked})")
    print(f"  halt: {state.get('halt_reason') or 'max_iterations reached'}")

    # ── coverage + report ────────────────────────────────────────────────────
    cov = exploit_db.coverage()
    print(f"\nTranscripts: {len(state.get('transcripts', []))}  "
          f"Verdicts: {len(state.get('verdicts', []))}  "
          f"Findings: {len(state.get('findings', []))}")
    print(f"Categories tested: {cov['categories_tested']}  "
          f"OWASP covered: {cov['owasp_covered']}")
    print(f"Dedupe: {cov['dedupe']}")

    report_md = render_markdown(exploit_db, title="First LIVE Campaign — VULN Report")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path("platform_data") / f"vuln_report_{ts}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_md)
    print(f"\nVULN report written to: {out}\n")
    print("#" * 78)
    print(report_md)
    print("#" * 78)

    exploit_db.close()
    findings_db.close()
    print(f"\nEvent store: {cfg.event_store_path}  (dashboard: "
          f"./.venv/bin/python -m uvicorn adv_platform.dashboard.app:app --port 8799)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
