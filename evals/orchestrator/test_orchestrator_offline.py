"""Offline tests for the finding-aware Orchestrator — local-only, $0.

Covers the spec §8 policy: prioritize by coverage gaps + unresolved findings,
redirect away from categories that stop producing new signal, halt after N attacks
with no new signal, and stay deterministic (same state -> same brief). The last
checks run the full LangGraph loop with a curated findings store to prove the graph
actually feeds the policy real data (the old graph passed coverage={}).

Run:  PYTHONPATH=. ./.venv/bin/python evals/orchestrator/test_orchestrator_offline.py
"""

from __future__ import annotations

import sys
from typing import Optional

from adv_platform.config import Config, PlatformMode
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.models import (
    AttackCategory as C,
    EventType,
    Finding,
    FindingStatus,
    OwaspLLM,
    Severity,
)
from adv_platform.observability.events import EventSink
from adv_platform.orchestrator.orchestrator import CategoryStats, Orchestrator, findings_by_category
from adv_platform.redteam import seeds as seed_loader
from adv_platform.storage.exploit_db import ExploitDB
from adv_platform.target_client.client import ChatResult

SEEDS = seed_loader.load_all()
REFUSAL = "I'm sorry, but I can't help with that request."


def _finding(vid: str, cat: C, sev: Severity, status: FindingStatus) -> Finding:
    return Finding(
        vuln_id=vid, title=f"{cat.value}: synthetic", severity=sev,
        owasp=[OwaspLLM.LLM02_SENSITIVE_INFO_DISCLOSURE], attack_category=cat,
        clinical_impact="synthetic", repro_steps=["synthetic"], observed="synthetic",
        expected="refuse", remediation=["synthetic"], status=status,
    )


def _even(attacks: int = 10) -> dict[C, CategoryStats]:
    """Every seeded category equally covered, no findings, not yet visited."""
    return {c: CategoryStats(lifetime_attacks=attacks) for c in Orchestrator(SEEDS).categories_with_seeds()}


def _with_findings(stats: dict[C, CategoryStats], findings: list[Finding]) -> dict[C, CategoryStats]:
    for cat, (score, conf, unrev) in findings_by_category(findings).items():
        if cat in stats:
            stats[cat].findings_score, stats[cat].open_confirmed, stats[cat].open_unreviewed = score, conf, unrev
    return stats


# ── pure policy checks ────────────────────────────────────────────────────────
def check_coverage_gap_wins() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _even(30)
    stats[C.G_INSECURE_OUTPUT] = CategoryStats(lifetime_attacks=0)   # lowest risk, never attacked
    b = o.decide(stats).brief
    return b is not None and b.category is C.G_INSECURE_OUTPUT, f"picked {b.category.value if b else None}: {b.rationale if b else ''}"


def check_confirmed_open_finding_boosts() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _with_findings(_even(), [_finding("V1", C.E_SYSTEM_PROMPT_LEAK, Severity.MEDIUM, FindingStatus.PUBLISHED)])
    b = o.decide(stats).brief
    return b.category is C.E_SYSTEM_PROMPT_LEAK, f"picked {b.category.value}: {b.rationale}"


def check_resolved_findings_ignored() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _with_findings(_even(), [_finding(f"V{i}", C.G_INSECURE_OUTPUT, Severity.HIGH, FindingStatus.RESOLVED) for i in range(5)])
    b = o.decide(stats).brief
    ok = b.category is not C.G_INSECURE_OUTPUT and stats[C.G_INSECURE_OUTPUT].findings_score == 0.0
    return ok, f"5 resolved G findings -> picked {b.category.value} (G findings score {stats[C.G_INSECURE_OUTPUT].findings_score})"


def check_unreviewed_drafts_discounted() -> tuple[bool, str]:
    # One human-confirmed MEDIUM outranks one agent-drafted, unreviewed HIGH.
    o = Orchestrator(SEEDS)
    stats = _with_findings(_even(), [
        _finding("V1", C.E_SYSTEM_PROMPT_LEAK, Severity.MEDIUM, FindingStatus.PUBLISHED),
        _finding("V2", C.G_INSECURE_OUTPUT, Severity.HIGH, FindingStatus.OPEN),
    ])
    b = o.decide(stats).brief
    return b.category is C.E_SYSTEM_PROMPT_LEAK, f"confirmed-medium E vs unreviewed-high G -> {b.category.value}"


def check_regressed_outranks_published() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _with_findings(_even(), [
        _finding("V1", C.E_SYSTEM_PROMPT_LEAK, Severity.MEDIUM, FindingStatus.PUBLISHED),
        _finding("V2", C.G_INSECURE_OUTPUT, Severity.MEDIUM, FindingStatus.REGRESSED),
    ])
    b = o.decide(stats).brief
    return b.category is C.G_INSECURE_OUTPUT, f"regressed G vs published E -> {b.category.value}"


def check_no_signal_visit_redirects() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _even()
    first = o.decide(stats).brief.category
    stats[first].run_visits, stats[first].last_visit_signal = 1, False
    second = o.decide(stats).brief.category
    return second is not first, f"{first.value} (no new signal) -> redirected to {second.value}"


def check_signal_visit_revisits_until_cap() -> tuple[bool, str]:
    o = Orchestrator(SEEDS, max_visits_per_category=2)
    stats = _even()
    first = o.decide(stats).brief.category
    stats[first].run_visits, stats[first].last_visit_signal = 1, True
    again = o.decide(stats).brief.category
    stats[first].run_visits = 2
    after_cap = o.decide(stats).brief.category
    ok = again is first and after_cap is not first
    return ok, f"signal -> revisit {again.value}; at cap -> {after_cap.value}"


def check_no_signal_attack_limit_halts() -> tuple[bool, str]:
    o = Orchestrator(SEEDS, no_signal_attack_limit=24)
    d = o.decide(_even(), attacks_since_signal=24)
    return d.brief is None and "no new signal" in d.halt_reason, f"halt_reason={d.halt_reason!r}"


def check_all_exhausted_halts() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    stats = _even()
    for s in stats.values():
        s.run_visits, s.last_visit_signal = 1, False
    d = o.decide(stats)
    return d.brief is None and "exhausted" in d.halt_reason, f"halt_reason={d.halt_reason!r}"


def check_unseeded_gaps_reported() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    d = o.decide(_even())
    missing = {c.value for c in C} - {c.value for c in o.categories_with_seeds()}
    return set(d.unseeded_gaps) == missing and len(missing) > 0, f"unseeded gaps={d.unseeded_gaps}"


def check_deterministic() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    fs = [_finding("V1", C.B_CROSS_PATIENT_PHI, Severity.LOW, FindingStatus.PUBLISHED)]
    picks = {o.decide(_with_findings(_even(), fs)).brief.category for _ in range(5)}
    return len(picks) == 1, f"5 identical inputs -> {sorted(p.value for p in picks)}"


def check_back_compat_next_brief() -> tuple[bool, str]:
    o = Orchestrator(SEEDS)
    all_run = set(o.categories_with_seeds())
    ok = o.next_brief() is not None and o.next_brief(already_run=all_run) is None
    return ok, "next_brief(): first call briefs, all-run returns None"


# ── graph integration (real data flowing into the policy) ─────────────────────
class FixtureTarget:
    def __init__(self, text: str) -> None:
        self._r = ChatResult(status_code=200, response=text)

    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return self._r


def _router() -> LLMRouter:
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    return LLMRouter(cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY}))


def _graph_deps(text: str, curated: ExploitDB, sink: EventSink) -> GraphDeps:
    return GraphDeps(
        orchestrator=Orchestrator(SEEDS), target=FixtureTarget(text), judge=Judge(_router()),
        documentation=Documentation(), sink=sink, max_iterations=20,
        canaries={s.id: s.canaries for s in SEEDS},
        exploit_db=ExploitDB(":memory:"), findings_db=curated,
    )


def check_graph_prioritizes_curated_open_finding() -> tuple[bool, str]:
    curated = ExploitDB(":memory:")
    # Lowest-priority seeded category gets a confirmed open finding; a resolved HIGH
    # sits on another category and must NOT attract the Orchestrator.
    cats = Orchestrator(SEEDS).categories_with_seeds()
    target, other = cats[-1], cats[0]
    curated.upsert_finding(_finding("VULN-900", target, Severity.MEDIUM, FindingStatus.PUBLISHED))
    curated.upsert_finding(_finding("VULN-901", other, Severity.HIGH, FindingStatus.RESOLVED))
    st = run_campaign(_graph_deps(REFUSAL, curated, EventSink()))
    first = st["decisions"][0]["category"]
    return first == target.value, f"first brief -> {first} (expected {target.value}); order={st['already_run']}"


def check_graph_halts_with_reason_and_events() -> tuple[bool, str]:
    sink = EventSink()
    st = run_campaign(_graph_deps(REFUSAL, ExploitDB(":memory:"), sink))
    halts = [e for e in sink.all() if e.type is EventType.AGENT_THINKING and e.payload.get("halt")]
    briefs = [e for e in sink.all() if e.type is EventType.MESSAGE_SENT and "scores" in e.payload]
    ok = bool(st.get("halt_reason")) and len(halts) == 1 and len(briefs) == len(st["already_run"])
    return ok, f"halt_reason={st.get('halt_reason')!r}, briefs={len(briefs)}, halt events={len(halts)}"


def check_graph_never_writes_curated_store() -> tuple[bool, str]:
    curated = ExploitDB(":memory:")
    curated.upsert_finding(_finding("VULN-900", C.B_CROSS_PATIENT_PHI, Severity.MEDIUM, FindingStatus.PUBLISHED))
    before = [f.model_dump_json() for f in curated.all_findings()]
    run_campaign(_graph_deps("Patient SSN 123-45-6789.", curated, EventSink()))
    after = [f.model_dump_json() for f in curated.all_findings()]
    return before == after, f"curated findings unchanged ({len(after)} row) after a leaking run"


CHECKS = [
    check_coverage_gap_wins,
    check_confirmed_open_finding_boosts,
    check_resolved_findings_ignored,
    check_unreviewed_drafts_discounted,
    check_regressed_outranks_published,
    check_no_signal_visit_redirects,
    check_signal_visit_revisits_until_cap,
    check_no_signal_attack_limit_halts,
    check_all_exhausted_halts,
    check_unseeded_gaps_reported,
    check_deterministic,
    check_back_compat_next_brief,
    check_graph_prioritizes_curated_open_finding,
    check_graph_halts_with_reason_and_events,
    check_graph_never_writes_curated_store,
]


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
