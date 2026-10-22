"""Score a captured transcript — PLATFORM ZONE, offline, $0.

Reads a raw transcript JSON (written by `run_client.py --attack`) and runs the
independent Judge on it. This is a SEPARATE process/context from the Red Team that
produced the transcript (R7): different module, fresh Judge context, its own rubric
prompt. In local-only the Judge model is the local model ($0); the router refuses any
paid path outside `live`.

The printed verdict carries no raw PHI (the Judge builds evidence pointers from the
kind/position of a match, not its value — R4).

Run:  PYTHONPATH=. python3 adv_platform/judge/run_judge.py <transcript.json>
"""

from __future__ import annotations

import pathlib
import sys

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass

from adv_platform.config import Config, PlatformMode
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.models import Transcript
from adv_platform.redteam import seeds as seed_loader


def _local_only_router() -> LLMRouter:
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    # Force local-only here regardless of .env — scoring a transcript never spends.
    cfg = cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY})
    return LLMRouter(cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: run_judge.py <transcript.json>")
        return 2
    path = pathlib.Path(argv[0])
    if not path.exists():
        print(f"transcript not found: {path}")
        return 2

    tx = Transcript.model_validate_json(path.read_text())
    # Pull the case's canary identifiers (known non-authorized patient data) so the
    # deterministic judge can hard-catch a disclosure for a known-target test.
    canaries: list[str] = []
    if tx.case_id:
        case = next((c for c in seed_loader.load_all() if c.id == tx.case_id), None)
        if case is not None:
            canaries = case.canaries

    router = _local_only_router()
    verdict = Judge(router).judge(tx, canaries=canaries)

    print(f"=== VERDICT — transcript {tx.case_id} ({tx.correlation_id}) ===")
    print(f"  category:            {tx.category.value}")
    print(f"  invariant:           {tx.invariant}")
    print(f"  result:              {verdict.result.value.upper()}"
          f"  (invariant_violated={verdict.invariant_violated})")
    print(f"  decided by:          {'deterministic pre-filter ($0)' if verdict.deterministic else 'LLM judge ' + (verdict.judge_model or '')}")
    print(f"  confidence:          {verdict.confidence}")
    print(f"  evidence_pointer:    {verdict.evidence_pointer}")
    print(f"  which_control:       {verdict.which_control_failed}")
    print(f"  rationale:           {verdict.rationale}")
    print(f"  rubric_version:      {verdict.rubric_version}")
    if verdict.error is not None:
        print(f"  error_state:         {verdict.error.type.value} — {verdict.error.message}")
    print(f"  estimated spend:     ${router.spend.total_usd:.4f}  (local-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
