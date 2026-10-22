"""Offline tests for the Judge sentinels — local-only, $0, fake LLM.

Run:  PYTHONPATH=. ./.venv/bin/python evals/judge/test_sentinels.py
"""

from __future__ import annotations

import sys
from typing import Optional

from adv_platform.config import Config, PlatformMode
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.deterministic import redact
from adv_platform.judge.judge import Judge
from adv_platform.judge.sentinels import SENTINELS, load_sentinels, run_sentinels
from adv_platform.llm.base import LLMError, LLMResponse
from adv_platform.models import AgentRole, EventType
from adv_platform.observability.events import EventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.target_client.client import ChatResult

CASES = load_sentinels()


def _reply(result: str) -> LLMResponse:
    return LLMResponse(text='{"result": "%s", "invariant_violated": %s, "confidence": 0.9, '
                            '"evidence_pointer": "t", "rationale": "x"}'
                            % (result, "true" if result == "fail" else "false"),
                       role=AgentRole.JUDGE, model="fake", backend="local")


class Always:
    """A Judge LLM that gives the same answer to everything (the drift failure modes)."""

    def __init__(self, result: str) -> None:
        self.result = result

    def complete(self, role, prompt, **kw):
        return _reply(self.result)


class Correct:
    """Answers each sentinel correctly by recognising its (redacted) target text."""

    def __init__(self) -> None:
        self.keys = []
        for _, label, tx in CASES:
            target = [t.content for t in tx.turns if t.speaker == "target"][-1]
            self.keys.append((redact(target)[:60], label))

    def complete(self, role, prompt, **kw):
        for key, label in self.keys:
            if key in prompt:
                return _reply(label)
        return _reply("pass")


class Down:
    def complete(self, role, prompt, **kw):
        raise LLMError("ollama not reachable")


def check_sentinels_load() -> tuple[bool, str]:
    labels = sorted(l for _, l, _ in CASES)
    return len(CASES) == len(SENTINELS) == 5 and labels.count("fail") == 3, f"{len(CASES)} sentinels, labels={labels}"


def check_correct_judge_is_trusted() -> tuple[bool, str]:
    r = run_sentinels(Correct())
    return r.trusted and not r.missed, r.reason


def check_pass_everything_judge_is_untrusted() -> tuple[bool, str]:
    r = run_sentinels(Always("pass"))
    # the deterministic sentinel still catches its exploit; the two LLM-tier ones are missed
    return (not r.trusted) and len(r.missed) == 2, r.reason


def check_fail_everything_judge_is_untrusted() -> tuple[bool, str]:
    r = run_sentinels(Always("fail"))
    return (not r.trusted) and "agreeing-with-everything" in r.reason, r.reason


def check_unreachable_judge_is_unverified() -> tuple[bool, str]:
    r = run_sentinels(Down())
    return (not r.trusted) and r.errors and "could not verify" in r.reason, r.reason


def check_sentinels_never_pollute_campaign_cache() -> tuple[bool, str]:
    campaign_judge = Judge(Correct())
    run_sentinels(campaign_judge.router)
    return len(campaign_judge._cache) == 0, "sentinels use fresh Judges; campaign cache stays empty"


class Fixture:
    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return ChatResult(status_code=200, response="Patient SSN 123-45-6789.")


def _deps(router, on: bool) -> tuple[GraphDeps, EventSink]:
    seeds = seed_loader.load_all()
    sink = EventSink()
    return GraphDeps(orchestrator=Orchestrator(seeds), target=Fixture(), judge=Judge(router),
                     documentation=Documentation(), sink=sink, max_iterations=2,
                     canaries={s.id: s.canaries for s in seeds}, sentinel_check=on), sink


def check_graph_reports_untrusted_judge_on_findings() -> tuple[bool, str]:
    deps, sink = _deps(Always("pass"), True)
    st = run_campaign(deps)
    ev = [e for e in sink.all() if e.payload.get("sentinel")]
    fe = [e for e in sink.all() if e.type is EventType.FINDING_CREATED]
    ok = (st["judge_sentinel"]["trusted"] is False and len(ev) == 1 and fe
          and all(e.payload.get("judge_trusted") is False for e in fe))
    return ok, f"sentinel event={len(ev)}, findings flagged judge_trusted=False: {len(fe)}"


def check_graph_default_off() -> tuple[bool, str]:
    deps, sink = _deps(Always("pass"), False)
    st = run_campaign(deps)
    ok = st["judge_sentinel"] == {} and not [e for e in sink.all() if e.payload.get("sentinel")]
    return ok, "sentinel_check=False: no sentinel run, no event"


def check_consistency_summary_math() -> tuple[bool, str]:
    sys.path.insert(0, "evals/judge")
    from run_judge_consistency import summarize
    rows = [{"id": "a", "label": "fail", "deterministic": True, "preds": ["fail"] * 3},
            {"id": "b", "label": "fail", "deterministic": False, "preds": ["fail", "pass", "fail"]},
            {"id": "c", "label": "pass", "deterministic": False, "preds": ["pass"] * 3}]
    m = summarize(rows)
    ok = (m["stability"] == 0.667 and m["llm_tier_stability"] == 0.5 and m["majority_accuracy"] == 1.0
          and m["any_run_false_negatives"] == ["b"] and m["flip_cases"][0]["id"] == "b")
    return ok, f"stability={m['stability']} llm={m['llm_tier_stability']} any-run FN={m['any_run_false_negatives']}"


CHECKS = [
    check_consistency_summary_math,
    check_sentinels_load,
    check_correct_judge_is_trusted,
    check_pass_everything_judge_is_untrusted,
    check_fail_everything_judge_is_untrusted,
    check_unreachable_judge_is_unverified,
    check_sentinels_never_pollute_campaign_cache,
    check_graph_reports_untrusted_judge_on_findings,
    check_graph_default_off,
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
