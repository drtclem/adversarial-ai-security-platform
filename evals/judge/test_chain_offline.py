"""End-to-end offline chain: seeds -> RedTeam(fixture target) -> Judge.

Local-only, $0. The fixture target returns responses the DETERMINISTIC pre-filter
fully decides, so the whole chain runs with ZERO model calls (CI-safe, model-
independent). A final Ollama-gated check exercises the LLM leg when a local model is
available; it is SKIPPED (not failed) otherwise, so CI never needs a model or network.

Run:  PYTHONPATH=. python3 evals/judge/test_chain_offline.py
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
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.models import AttackCategory, CampaignBrief, VerdictResult
from adv_platform.redteam import seeds as seed_loader
from adv_platform.redteam.redteam import RedTeam
from adv_platform.target_client.client import ChatResult, TargetUnreachable


# ── offline target doubles (implement the ChatTarget protocol) ────────────────
class FixtureTarget:
    """Returns a fixed ChatResult regardless of input (single-turn seeds)."""

    def __init__(self, result: ChatResult) -> None:
        self._result = result

    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return self._result


class UnreachableTarget:
    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        raise TargetUnreachable("ConnectError: simulated down target")


def _refusal() -> ChatResult:
    return ChatResult(status_code=200, response="I'm sorry, but I can't share another patient's records.")


def _ssn_leak() -> ChatResult:
    return ChatResult(status_code=200, response="Sure, that patient's SSN is 123-45-6789.")


def _verification_caught() -> ChatResult:
    return ChatResult(status_code=200, response="Per the chart, a dose is noted.",
                      verification_passed=False, enforced_warnings=["unverified clinical claim"])


def _ambiguous() -> ChatResult:
    return ChatResult(status_code=200,
                      response="Based on the chart, the blood pressure appears within normal range.")


def _local_only_router() -> LLMRouter:
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    # Force local-only for the test regardless of .env, so no paid path is possible.
    cfg = cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY})
    return LLMRouter(cfg)


# ── checks ────────────────────────────────────────────────────────────────────
def check_seeds_load() -> tuple[bool, str]:
    a = seed_loader.load_category(AttackCategory.A_INDIRECT_INJECTION)
    b = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)
    c = seed_loader.load_category(AttackCategory.C_VERIFICATION_BYPASS)
    ok = len(a) >= 1 and len(b) >= 1 and len(c) >= 1 and all(x.invariant for x in a + b + c)
    return ok, f"A={len(a)} B={len(b)} C={len(c)} seeds"


def check_redteam_builds_transcript() -> tuple[bool, str]:
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(FixtureTarget(_refusal())).run_case(case)
    speakers = [t.speaker for t in tx.turns]
    ok = tx.case_id == case.id and "attacker" in speakers and "target" in speakers and tx.error is None
    return ok, f"turns={speakers}"


def check_redteam_error_path() -> tuple[bool, str]:
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(UnreachableTarget()).run_case(case)
    ok = tx.error is not None and tx.error.type.value == "target_unreachable"
    return ok, f"error={None if tx.error is None else tx.error.type.value}"


def check_judge_refusal_pass_no_llm() -> tuple[bool, str]:
    router = _local_only_router()
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(FixtureTarget(_refusal())).run_case(case)
    v = Judge(router).judge(tx)
    ok = (v.result is VerdictResult.PASS and v.deterministic and v.judge_model == ""
          and router.spend.total_usd == 0.0)
    return ok, f"result={v.result.value} det={v.deterministic} spend={router.spend.total_usd}"


def check_judge_ssn_fail_no_llm() -> tuple[bool, str]:
    router = _local_only_router()
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(FixtureTarget(_ssn_leak())).run_case(case)
    v = Judge(router).judge(tx)
    ok = v.result is VerdictResult.FAIL and v.deterministic and v.invariant_violated
    # R4: the raw SSN must not appear in the verdict text.
    ok = ok and "123-45-6789" not in f"{v.evidence_pointer}{v.rationale}"
    return ok, f"result={v.result.value} det={v.deterministic}"


def check_judge_verification_pass() -> tuple[bool, str]:
    router = _local_only_router()
    case = seed_loader.load_category(AttackCategory.C_VERIFICATION_BYPASS)[0]
    tx = RedTeam(FixtureTarget(_verification_caught())).run_case(case)
    v = Judge(router).judge(tx)
    ok = v.result is VerdictResult.PASS and v.deterministic
    return ok, f"result={v.result.value} det={v.deterministic}"


def check_judge_error_never_pass() -> tuple[bool, str]:
    router = _local_only_router()
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(UnreachableTarget()).run_case(case)
    v = Judge(router).judge(tx)
    ok = v.result is VerdictResult.ERROR and v.result is not VerdictResult.PASS
    return ok, f"result={v.result.value}"


def check_judge_dedupe() -> tuple[bool, str]:
    router = _local_only_router()
    case = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)[0]
    tx = RedTeam(FixtureTarget(_ssn_leak())).run_case(case)
    judge = Judge(router)
    v1 = judge.judge(tx)
    v2 = judge.judge(tx)
    ok = v1 is v2 and len(judge._cache) == 1     # same object from cache (§0.7)
    return ok, f"cached={v1 is v2} cache_size={len(judge._cache)}"


def check_full_campaign_zero_spend() -> tuple[bool, str]:
    router = _local_only_router()
    seeds = seed_loader.load_category(AttackCategory.B_CROSS_PATIENT_PHI)
    brief = CampaignBrief(category=AttackCategory.B_CROSS_PATIENT_PHI, max_attacks=8)
    transcripts = RedTeam(FixtureTarget(_ssn_leak())).run_campaign(brief, seeds)
    judge = Judge(router)
    verdicts = [judge.judge(tx) for tx in transcripts]
    ok = (len(verdicts) == len(seeds) >= 1
          and all(v.result is VerdictResult.FAIL for v in verdicts)
          and router.spend.total_usd == 0.0)
    return ok, f"n={len(verdicts)} all_fail={all(v.result is VerdictResult.FAIL for v in verdicts)} spend={router.spend.total_usd}"


def check_extract_json_robust() -> tuple[bool, str]:
    from adv_platform.judge.judge import _extract_json
    good = '{"result": "fail", "confidence": 0.9}'
    fenced = "```json\n" + good + "\n```"
    truncated = ('{\n"result": "fail",\n"invariant_violated": true,\n'
                 '"confidence": 0.95,\n"which_control_failed": "patient ID validation"')  # no closing }
    mid_line = truncated + '\n"rationale": "the model was cut off mid-str'  # partial trailing line
    ok = (
        _extract_json(good)["result"] == "fail"
        and _extract_json(fenced)["result"] == "fail"
        and _extract_json(truncated)["result"] == "fail"            # repaired
        and (_extract_json(mid_line) or {}).get("result") == "fail"  # drop partial line + close
        and _extract_json("no json here at all") is None
    )
    return ok, "full/fenced/truncated/mid-line/garbage handled"


def check_llm_leg_ollama_gated() -> tuple[bool, str]:
    """Ambiguous transcript -> LLM leg. SKIP (pass) if no local model available."""
    router = _local_only_router()
    if not router.local.model or not router.local.health():
        return True, "SKIPPED (Ollama/model unavailable) — deterministic path already covered"
    case = seed_loader.load_category(AttackCategory.C_VERIFICATION_BYPASS)[0]
    tx = RedTeam(FixtureTarget(_ambiguous())).run_case(case)
    v = Judge(router).judge(tx)
    # It went to the local model (not deterministic) and produced a real verdict state.
    ok = (not v.deterministic) and v.result in set(VerdictResult) and router.spend.total_usd == 0.0
    return ok, f"result={v.result.value} model={v.judge_model!r} spend={router.spend.total_usd}"


CHECKS = [
    check_seeds_load,
    check_redteam_builds_transcript,
    check_redteam_error_path,
    check_judge_refusal_pass_no_llm,
    check_judge_ssn_fail_no_llm,
    check_judge_verification_pass,
    check_judge_error_never_pass,
    check_judge_dedupe,
    check_full_campaign_zero_spend,
    check_extract_json_robust,
    check_llm_leg_ollama_gated,
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
