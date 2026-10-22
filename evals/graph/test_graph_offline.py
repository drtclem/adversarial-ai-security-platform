"""End-to-end offline test of the LangGraph campaign — local-only, $0.

Runs the full Orchestrator -> Red Team -> Judge -> Documentation loop against an
offline fixture target (no live target, no model calls needed for the deterministic
cases). Asserts the loop produces transcripts/verdicts/findings, emits events, keeps
spend at $0, and NEVER auto-approves a finding (D4 gate is separate).

Run:  PYTHONPATH=. ./.venv/bin/python evals/graph/test_graph_offline.py
"""

from __future__ import annotations

import sys
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass

from adv_platform.config import Config, PlatformMode
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.models import EventType, VerdictResult
from adv_platform.observability.events import EventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.target_client.client import ChatResult


class FixtureTarget:
    def __init__(self, result: ChatResult) -> None:
        self._r = result

    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return self._r


def _router() -> LLMRouter:
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    return LLMRouter(cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY}))


def _deps(result: ChatResult, max_iterations: int = 3) -> GraphDeps:
    seeds = seed_loader.load_all()
    return GraphDeps(
        orchestrator=Orchestrator(seeds),
        target=FixtureTarget(result),
        judge=Judge(_router()),
        documentation=Documentation(),
        sink=EventSink(),
        max_iterations=max_iterations,
        canaries={s.id: s.canaries for s in seeds},
    )


def check_campaign_produces_findings() -> tuple[bool, str]:
    # SSN in every response -> deterministic FAIL for every transcript -> findings.
    deps = _deps(ChatResult(status_code=200, response="Patient SSN 123-45-6789."))
    st = run_campaign(deps)
    v = st.get("verdicts", [])
    f = st.get("findings", [])
    ok = (len(v) > 0 and all(x.result is VerdictResult.FAIL and x.deterministic for x in v)
          and len(f) > 0 and deps.sink.total_cost_usd() == 0.0)
    return ok, f"transcripts={len(st.get('transcripts',[]))} verdicts={len(v)} findings={len(f)} cost={deps.sink.total_cost_usd()}"


def check_findings_never_auto_approved() -> tuple[bool, str]:
    deps = _deps(ChatResult(status_code=200, response="SSN 123-45-6789"))
    st = run_campaign(deps)
    f = st.get("findings", [])
    ok = len(f) > 0 and all((not x.human_approved) and x.status.value == "open" for x in f)
    return ok, f"all findings human_approved=False & open: {ok} (n={len(f)})"


def check_clean_run_no_findings() -> tuple[bool, str]:
    # A hard refusal everywhere -> all PASS -> zero findings.
    deps = _deps(ChatResult(status_code=200,
                            response="I'm sorry, but I can't help with that request."))
    st = run_campaign(deps)
    v = st.get("verdicts", [])
    ok = (len(v) > 0 and all(x.result is VerdictResult.PASS for x in v)
          and len(st.get("findings", [])) == 0)
    return ok, f"verdicts={len(v)} all_pass={all(x.result is VerdictResult.PASS for x in v)} findings={len(st.get('findings',[]))}"


def check_events_emitted() -> tuple[bool, str]:
    deps = _deps(ChatResult(status_code=200, response="SSN 123-45-6789"))
    run_campaign(deps)
    kinds = {e.type for e in deps.sink.all()}
    need = {EventType.AGENT_STARTED, EventType.MESSAGE_SENT, EventType.TARGET_RESPONSE,
            EventType.VERDICT, EventType.FINDING_CREATED}
    ok = need.issubset(kinds)
    return ok, f"event kinds present: {sorted(k.value for k in kinds)}"


def check_events_redacted() -> tuple[bool, str]:
    # No raw SSN should appear in any emitted event payload (R4).
    deps = _deps(ChatResult(status_code=200, response="SSN 123-45-6789"))
    run_campaign(deps)
    blob = str([e.payload for e in deps.sink.all()])
    return "123-45-6789" not in blob, "no raw SSN in event payloads"


def check_orchestrator_covers_distinct_categories() -> tuple[bool, str]:
    deps = _deps(ChatResult(status_code=200, response="ok"), max_iterations=3)
    st = run_campaign(deps)
    already = st.get("already_run", [])
    ok = len(already) == len(set(already)) and len(already) >= 1
    return ok, f"already_run={already} (distinct)"


CHECKS = [
    check_campaign_produces_findings,
    check_findings_never_auto_approved,
    check_clean_run_no_findings,
    check_events_emitted,
    check_events_redacted,
    check_orchestrator_covers_distinct_categories,
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
