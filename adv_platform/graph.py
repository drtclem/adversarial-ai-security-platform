"""LangGraph wiring of the 4 agents + the campaign loop — PLATFORM ZONE.

Orchestrator → Red Team → Judge → Documentation, looped until the finding-aware
Orchestrator halts (no new signal / every category exhausted) or max_iterations.
The Documentation node reports each batch's NEW signal back into state so the next
Orchestrator turn can drill down or redirect. Local-only: langgraph
only orchestrates the LOCAL models; no paid path is reachable here. Every node
emits correlation-threaded, PHI-redacted events (R4) to the event substrate.

The Red Team (attacker zone) is driven via a `ChatTarget` (the real `TargetClient`
live, or an offline fixture). The Judge is invoked independently of the Red Team
(R7). Documentation writes Findings but NEVER approves/publishes — the deterministic
human-approval gate (D4/R8) is separate and out of any LLM's control.

langsmith tracing is force-disabled here to protect the $0/offline guarantee.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional, TypedDict

# Belt-and-suspenders: never let langchain/langsmith phone home (no outbound traces).
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGCHAIN_TRACING", "false")

from langgraph.graph import END, StateGraph  # noqa: E402

from adv_platform.documentation.documentation import Documentation  # noqa: E402
from adv_platform.judge.deterministic import redact  # noqa: E402
from adv_platform.judge.judge import Judge  # noqa: E402
from adv_platform.models import (  # noqa: E402
    AgentRole,
    AttackCase,
    AttackCategory,
    EventType,
    VerdictResult,
    Zone,
)
from adv_platform.observability.events import EventSink  # noqa: E402
from adv_platform.orchestrator.orchestrator import (  # noqa: E402
    CategoryStats,
    Orchestrator,
    findings_by_category,
)
from adv_platform.redteam.mutator import Complete, Mutator  # noqa: E402
from adv_platform.redteam.redteam import ChatTarget, RedTeam  # noqa: E402
from adv_platform.storage.exploit_db import ExploitDB  # noqa: E402


@dataclass
class GraphDeps:
    orchestrator: Orchestrator
    target: ChatTarget          # attacker-zone target (real TargetClient or fixture)
    judge: Judge
    documentation: Documentation
    sink: EventSink
    max_iterations: int = 3
    max_attacks: int = 8
    # case_id -> canaries, so the Judge can hard-catch known non-authorized data
    canaries: dict[str, list[str]] = field(default_factory=dict)
    # ── real Red Team (task 3) — all LOCAL / $0 ──────────────────────────────
    # A local completion callable (graph binds router.complete@REDTEAM). When set
    # with mutations_per_seed>0, the Red Team LLM-mutates each seed before running;
    # max_escalations>0 turns on adaptive crescendo. Left None → scripted-only
    # behaviour (fully back-compatible with the Phase-3 skeleton).
    redteam_complete: Optional[Complete] = None
    mutations_per_seed: int = 0
    max_escalations: int = 0
    # ── exploit DB (task 8) — dedupe + persistence + coverage; platform zone ──
    # When set, transcripts are deduped by content_hash BEFORE the (possibly paid)
    # Judge runs (§0.7), and confirmed Findings persist. Left None → no dedupe/
    # persistence (back-compatible with the skeleton and offline graph tests).
    exploit_db: Optional[ExploitDB] = None
    # ── finding-aware Orchestrator — curated, human-gated findings store ─────
    # READ-ONLY here. The source of truth for review status (published/resolved).
    # When set, the Orchestrator weighs these + this run's fresh drafts; when None
    # it falls back to exploit_db's findings. Never written by the graph.
    findings_db: Optional[ExploitDB] = None
    # ── Judge sentinels (judge/sentinels.py): re-score 5 known-answer transcripts
    # before the campaign; an untrusted Judge is reported, never hidden.
    sentinel_check: bool = False
    # ── version trigger (harness/version_trigger.py): operator-stamped target
    # version; a new one runs the full regression suite before any attack, and
    # every transcript is stamped with the version it ran against.
    target_version: Optional[str] = None
    version_ledger: Optional[Any] = None       # VersionLedger; None = no version check
    regression_gate: Optional[Any] = None      # GateFn for a new version; None = stored fixtures only


class CampaignState(TypedDict, total=False):
    iteration: int
    already_run: list[str]              # category values covered this run
    coverage: dict[str, int]
    brief: Any                          # CampaignBrief | None
    seeds: list[AttackCase]             # seeds for the current brief
    batch_cases: list[AttackCase]       # actual cases run this batch (seeds + mutations)
    batch_transcripts: list[Any]
    batch_judged: list[Any]             # transcripts actually judged (post-dedupe)
    batch_verdicts: list[Any]
    transcripts: list[Any]
    verdicts: list[Any]
    findings: list[Any]
    done: bool
    # ── finding-aware Orchestrator bookkeeping (JSON-friendly) ───────────────
    baseline: dict[str, dict]           # lifetime coverage snapshot at run start
    run_stats: dict[str, dict]          # category -> visits/attacks/new signals
    seen_hashes: list[str]              # transcripts seen this run (for "new" signal)
    attacks_since_signal: int
    halt_reason: str
    decisions: list[dict]               # every brief/halt with its score table
    judge_sentinel: dict                # SentinelReport.to_dict() when sentinel_check is on
    version_check: dict                 # TriggerResult.to_dict() when a ledger is configured
    cross_category: list[dict]          # improved-vs-worsened category pairs across versions


def build_graph(deps: GraphDeps):
    def _baseline() -> dict[str, dict]:
        """Lifetime per-category coverage from the exploit DB, snapshotted ONCE at
        run start (the judge node writes to the same DB during the run, so reading
        it live would double-count this run's attacks)."""
        if deps.exploit_db is None:
            return {}
        by_cat = deps.exploit_db.coverage().get("by_category", {})
        return {c: {"attacks": int(v.get("unique", 0)), "fails": int(v.get("fail", 0))}
                for c, v in by_cat.items()}

    def _open_findings(state: CampaignState) -> list:
        # Curated store = review truth; plus this run's fresh (unreviewed) drafts.
        # Drafts from PREVIOUS runs in the run-scoped DB are ignored: their review
        # outcome lives in the curated store, not on the stale draft row.
        if deps.findings_db is not None:
            return deps.findings_db.all_findings() + list(state.get("findings", []))
        if deps.exploit_db is not None:
            return deps.exploit_db.all_findings()
        return list(state.get("findings", []))

    def orchestrator_node(state: CampaignState) -> dict:
        baseline = state.get("baseline") or _baseline()
        run_stats = state.get("run_stats", {})
        fscores = findings_by_category(_open_findings(state))
        stats: dict[AttackCategory, CategoryStats] = {}
        for cat in AttackCategory:
            b = baseline.get(cat.value, {})
            r = CategoryStats.from_dict(run_stats.get(cat.value, {}))
            fs = fscores.get(cat, (0.0, 0, 0))
            r.lifetime_attacks, r.lifetime_fails = b.get("attacks", 0), b.get("fails", 0)
            r.findings_score, r.open_confirmed, r.open_unreviewed = fs
            stats[cat] = r
        deps.sink.emit(EventType.AGENT_STARTED, correlation_id="orchestrator",
                       agent=AgentRole.ORCHESTRATOR,
                       payload={"iteration": state.get("iteration", 0)})
        decision = deps.orchestrator.decide(
            stats,
            attacks_since_signal=state.get("attacks_since_signal", 0),
            max_attacks=deps.max_attacks,
        )
        record = {"iteration": state.get("iteration", 0),
                  "category": decision.brief.category.value if decision.brief else None,
                  "halt_reason": decision.halt_reason, "scores": decision.scores,
                  "exhausted": decision.exhausted, "unseeded_gaps": decision.unseeded_gaps}
        decisions = list(state.get("decisions", [])) + [record]
        if decision.brief is None:
            deps.sink.emit(EventType.AGENT_THINKING, correlation_id="orchestrator",
                           agent=AgentRole.ORCHESTRATOR,
                           payload={"halt": True, "halt_reason": decision.halt_reason,
                                    "scores": decision.scores,
                                    "unseeded_gaps": decision.unseeded_gaps})
            return {"brief": None, "done": True, "baseline": baseline,
                    "halt_reason": decision.halt_reason, "decisions": decisions}
        brief = decision.brief
        seeds = [s for s in deps.orchestrator.seeds if s.category == brief.category]
        deps.sink.emit(EventType.MESSAGE_SENT, correlation_id=brief.correlation_id,
                       agent=AgentRole.ORCHESTRATOR,
                       payload={"category": brief.category.value, "seeds": len(seeds),
                                "rationale": brief.rationale, "scores": decision.scores,
                                "exhausted": decision.exhausted,
                                "unseeded_gaps": decision.unseeded_gaps})
        already = list(dict.fromkeys(state.get("already_run", []) + [brief.category.value]))
        return {"brief": brief, "seeds": seeds, "already_run": already,
                "baseline": baseline, "decisions": decisions}

    def _redacted_dialog(tx) -> list[dict]:
        """Turn-by-turn REDACTED transcript for the dashboard (R4): PHI patterns
        masked, plus the case's canaries masked to [CANARY]. Never raw content."""
        canaries = deps.canaries.get(tx.case_id or "", [])
        dialog = []
        for t in tx.turns:
            text = redact(t.content or "")
            for c in canaries:
                if c:
                    text = re.sub(re.escape(c), "[CANARY]", text, flags=re.IGNORECASE)
            dialog.append({"speaker": t.speaker, "text": text})
        return dialog

    def _select_cases(state: CampaignState) -> list[AttackCase]:
        """Cases for the current brief (mirrors RedTeam.run_campaign selection) so we
        can LLM-expand them before running."""
        brief, seeds = state.get("brief"), state.get("seeds", [])
        cases = seeds
        if brief.seed_ids:
            wanted = set(brief.seed_ids)
            cases = [c for c in cases if c.id in wanted]
        return [c for c in cases if c.category == brief.category]

    def redteam_node(state: CampaignState) -> dict:
        brief = state.get("brief")
        base_cases = _select_cases(state)

        # Real Red Team (task 3): LLM-mutate each seed locally ($0) before running.
        mutator = (
            Mutator(deps.redteam_complete)
            if deps.redteam_complete is not None and deps.mutations_per_seed > 0
            else None
        )
        run_cases: list[AttackCase] = []
        for base in base_cases:
            run_cases.append(base)
            if mutator is None:
                continue
            for child in mutator.generate_mutations(base, n=deps.mutations_per_seed):
                run_cases.append(child)
                # Register the child's canaries under its own id so the Judge and the
                # dashboard redaction catch known non-authorized data (R4/R7).
                if child.canaries:
                    deps.canaries.setdefault(child.id, list(child.canaries))
                deps.sink.emit(EventType.MUTATION_GENERATED, correlation_id=brief.correlation_id,
                               agent=AgentRole.REDTEAM, zone=Zone.ATTACKER,
                               payload={"case_id": child.id, "parent_id": base.id,
                                        "category": base.category.value,
                                        "origin": child.origin, "label": child.notes})
        run_cases = run_cases[: brief.max_attacks]

        rt = RedTeam(deps.target, mutator=mutator, max_escalations=deps.max_escalations)
        batch = [rt.run_case(c) for c in run_cases]
        for tx in batch:                        # which target version this ran against
            tx.target_version_marker = deps.target_version
        for tx in batch:
            deps.sink.emit(EventType.TARGET_RESPONSE, correlation_id=tx.correlation_id,
                           agent=AgentRole.REDTEAM, zone=Zone.ATTACKER,
                           payload={"case_id": tx.case_id, "category": tx.category.value,
                                    "turns": len(tx.turns),
                                    "target_correlation_id": tx.target_correlation_id or "",
                                    "error": tx.error.type.value if tx.error else "",
                                    "dialog": _redacted_dialog(tx)})
        return {"batch_transcripts": batch, "batch_cases": run_cases,
                "transcripts": state.get("transcripts", []) + batch}

    def judge_node(state: CampaignState) -> dict:
        batch = state.get("batch_transcripts", [])
        new_verdicts = []
        judged = []
        for tx in batch:
            h = tx.content_hash
            # Dedupe: never judge the same transcript twice (§0.7). In `live` this
            # also avoids a paid Judge call for a repeat.
            if deps.exploit_db is not None and deps.exploit_db.is_duplicate(h):
                deps.exploit_db.record_transcript(h, tx.case_id, tx.category,
                                                  VerdictResult.PASS)  # bumps count only
                deps.sink.emit(EventType.AGENT_THINKING, correlation_id=tx.correlation_id,
                               agent=AgentRole.JUDGE,
                               payload={"dedupe_skip": True, "case_id": tx.case_id or "",
                                        "category": tx.category.value,
                                        "content_hash": h[:12]})
                continue
            v = deps.judge.judge(tx, canaries=deps.canaries.get(tx.case_id or "", []))
            new_verdicts.append(v)
            judged.append(tx)
            if deps.exploit_db is not None:
                deps.exploit_db.record_transcript(h, tx.case_id, tx.category, v.result)
            deps.sink.emit(EventType.VERDICT, correlation_id=tx.correlation_id,
                           agent=AgentRole.JUDGE,
                           payload={"case_id": tx.case_id or "",
                                    "category": tx.category.value,
                                    "result": v.result.value,
                                    "invariant_violated": v.invariant_violated,
                                    "deterministic": v.deterministic,
                                    "confidence": v.confidence,
                                    "review_recommended": v.review_recommended,
                                    "evidence": v.evidence_pointer,
                                    # calibrated-classifier tier, shadow mode (decides nothing)
                                    "shadow": (v.shadow.model_dump(
                                        include={"classifier", "p_violation", "would_decide",
                                                 "would_result", "agrees", "error"})
                                               if v.shadow else None)},
                           cost_usd=0.0)
        return {"batch_verdicts": new_verdicts, "batch_judged": judged,
                "verdicts": state.get("verdicts", []) + new_verdicts}

    def documentation_node(state: CampaignState) -> dict:
        # Only the transcripts the Judge actually ruled on this batch (post-dedupe),
        # aligned 1:1 with the verdicts.
        batch_tx = state.get("batch_judged", state.get("batch_transcripts", []))
        batch_v = state.get("batch_verdicts", [])
        # Prefer the actual cases run this batch (seeds + LLM mutations), so findings
        # for generated cases resolve; fall back to the seed catalog.
        by_case = {s.id: s for s in deps.orchestrator.seeds}
        by_case.update({c.id: c for c in state.get("batch_cases", [])})
        findings = list(state.get("findings", []))
        for tx, v in zip(batch_tx, batch_v):
            if v.result is VerdictResult.FAIL and v.invariant_violated:
                case = by_case.get(tx.case_id)
                if case is None:
                    continue
                f = deps.documentation.write_finding(v, tx, case)
                findings.append(f)
                if deps.exploit_db is not None:
                    deps.exploit_db.upsert_finding(f, content_hash=tx.content_hash)
                deps.sink.emit(EventType.FINDING_CREATED, correlation_id=tx.correlation_id,
                               agent=AgentRole.DOCUMENTATION,
                               payload={"vuln_id": f.vuln_id, "severity": f.severity.value,
                                        "category": f.attack_category.value,
                                        "case_id": tx.case_id or "",
                                        "human_approved": f.human_approved,
                                        "judge_trusted": state.get("judge_sentinel", {}).get("trusted")})
        # ── feed the Orchestrator: did this visit produce NEW signal? ─────────
        brief = state.get("brief")
        seen = set(state.get("seen_hashes", []))
        new_signal = 0
        for tx, v in zip(batch_tx, batch_v):
            flagged = (v.result in (VerdictResult.FAIL, VerdictResult.PARTIAL)
                       or getattr(v, "review_recommended", False))
            if flagged and tx.content_hash not in seen:
                new_signal += 1
        batch_all = state.get("batch_transcripts", [])
        seen |= {tx.content_hash for tx in batch_all}
        run_stats = dict(state.get("run_stats", {}))
        if brief is not None:
            cs = CategoryStats.from_dict(run_stats.get(brief.category.value, {}))
            cs.run_visits += 1
            cs.run_attacks += len(batch_all)
            cs.run_new_signals += new_signal
            cs.last_visit_signal = new_signal > 0
            run_stats[brief.category.value] = cs.to_dict()
        since = 0 if new_signal else state.get("attacks_since_signal", 0) + len(batch_all)
        return {"findings": findings, "iteration": state.get("iteration", 0) + 1,
                "run_stats": run_stats, "seen_hashes": sorted(seen),
                "attacks_since_signal": since}

    def after_orchestrator(state: CampaignState) -> str:
        return END if state.get("done") or state.get("brief") is None else "redteam"

    def after_documentation(state: CampaignState) -> str:
        if state.get("done") or state.get("iteration", 0) >= deps.max_iterations:
            return END
        return "orchestrator"

    b = StateGraph(CampaignState)
    b.add_node("orchestrator", orchestrator_node)
    b.add_node("redteam", redteam_node)
    b.add_node("judge", judge_node)
    b.add_node("documentation", documentation_node)
    b.set_entry_point("orchestrator")
    b.add_conditional_edges("orchestrator", after_orchestrator, {"redteam": "redteam", END: END})
    b.add_edge("redteam", "judge")
    b.add_edge("judge", "documentation")
    b.add_conditional_edges("documentation", after_documentation,
                            {"orchestrator": "orchestrator", END: END})
    return b.compile()


def run_campaign(deps: GraphDeps) -> CampaignState:
    """Run the full campaign loop and return the final state."""
    graph = build_graph(deps)
    version_check: dict = {}
    if deps.version_ledger is not None:
        from adv_platform.harness.version_trigger import check_and_trigger
        from adv_platform.harness.version_trigger import default_gate
        version_check = check_and_trigger(deps.target_version, deps.version_ledger,
                                          gate=deps.regression_gate or default_gate,
                                          sink=deps.sink).to_dict()
    sentinel: dict = {}
    if deps.sentinel_check:
        from adv_platform.judge.sentinels import run_sentinels
        sentinel = run_sentinels(deps.judge.router).to_dict()
        deps.sink.emit(EventType.AGENT_THINKING, correlation_id="judge-sentinels",
                       agent=AgentRole.JUDGE,
                       payload={"sentinel": True, "trusted": sentinel["trusted"],
                                "reason": sentinel["reason"], "results": sentinel["results"]})
    initial: CampaignState = {"iteration": 0, "already_run": [], "coverage": {},
                              "transcripts": [], "verdicts": [], "findings": [],
                              "run_stats": {}, "seen_hashes": [],
                              "attacks_since_signal": 0, "halt_reason": "",
                              "decisions": [], "judge_sentinel": sentinel,
                              "version_check": version_check}
    # LangGraph counts every node execution against recursion_limit (default 25 in
    # the pinned 0.2.x). One iteration = 4 nodes, plus the final halting
    # Orchestrator turn, so size the limit from max_iterations; max_iterations stays
    # the real bound.
    limit = 4 * max(1, deps.max_iterations) + 5
    final = graph.invoke(initial, config={"recursion_limit": limit})

    # Per-category results against this target version -> ledger; then flag any
    # category that improved while another got worse versus the previous version.
    final["cross_category"] = []
    if deps.version_ledger is not None and deps.target_version:
        from adv_platform.harness.version_trigger import cross_category_flags
        by_cat: dict[str, dict[str, int]] = {}
        for tx, v in zip(final.get("transcripts", []), _aligned_verdicts(final)):
            if v is None:
                continue
            b = by_cat.setdefault(tx.category.value, {})
            b[v.result.value] = b.get(v.result.value, 0) + 1
        if by_cat:
            deps.version_ledger.record_campaign(deps.target_version, by_cat)
            flags = cross_category_flags(deps.version_ledger, deps.target_version)
            final["cross_category"] = flags
            if flags:
                deps.sink.emit(EventType.REGRESSION_DETECTED, correlation_id="cross-category",
                               agent=AgentRole.ORCHESTRATOR,
                               payload={"cross_category": True, "flags": flags})
    return final


def _aligned_verdicts(state: dict) -> list:
    """Verdicts aligned to state['transcripts'] by transcript id (dedupe-skipped -> None)."""
    by_tx = {v.transcript_id: v for v in state.get("verdicts", [])}
    return [by_tx.get(tx.id) for tx in state.get("transcripts", [])]
