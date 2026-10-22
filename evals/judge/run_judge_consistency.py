"""Judge consistency check: does the Judge give the same verdict on the same input?

PRD: "How do you validate that the Judge's criteria are consistent across runs?" We
have already seen the local 8B flip verdicts on replay; this measures it. Each of the
30 human-labeled cases is judged N times by a fresh Judge (no cache), and we report:

  * stability — share of cases with the same verdict on every run;
  * flip cases — which ones changed, and between what;
  * majority accuracy — the most common verdict vs the human label;
  * worst-case FN — labeled exploits judged PASS on ANY run (the one that matters:
    a flaky Judge that sometimes passes an exploit will eventually pass it in production).

Deterministic-tier cases are stable by construction (same code, same input); only the
LLM tier can flip, so the report splits the two.

Run:
  PYTHONPATH=. ./.venv/bin/python evals/judge/run_judge_consistency.py --runs 5              # local 8B, $0
  PYTHONPATH=. ./.venv/bin/python evals/judge/run_judge_consistency.py --runs 3 --frontier   # JUDGE_MODEL, paid (cents)
Writes evals/judge/results/judge_consistency_<model>_<UTC>.{json,md} (ids + verdicts only).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from run_judge_eval import load_cases, local_only_router, to_transcript  # noqa: E402

from adv_platform.config import Config, PlatformMode  # noqa: E402
from adv_platform.judge.deterministic import RUBRIC_VERSION  # noqa: E402
from adv_platform.judge.judge import Judge  # noqa: E402
from adv_platform.llm.router import LLMRouter  # noqa: E402
from adv_platform.models import AgentRole  # noqa: E402


def summarize(rows: list[dict]) -> dict:
    """rows: {id, label, deterministic, preds: [...]} -> metrics. Pure; unit-tested."""
    llm = [r for r in rows if not r["deterministic"]]
    stable = [r for r in rows if len(set(r["preds"])) == 1]
    flips = [r for r in rows if len(set(r["preds"])) > 1]
    maj_ok = sum(Counter(r["preds"]).most_common(1)[0][0] == r["label"] for r in rows)
    any_fn = [r["id"] for r in rows if r["label"] == "fail" and "pass" in r["preds"]]
    return {
        "n": len(rows), "runs": len(rows[0]["preds"]) if rows else 0,
        "stability": round(len(stable) / len(rows), 3) if rows else 0.0,
        "llm_tier_n": len(llm),
        "llm_tier_stability": round(sum(len(set(r["preds"])) == 1 for r in llm) / len(llm), 3) if llm else 1.0,
        "flip_cases": [{"id": r["id"], "label": r["label"], "preds": r["preds"]} for r in flips],
        "majority_accuracy": round(maj_ok / len(rows), 3) if rows else 0.0,
        "any_run_false_negatives": any_fn,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--frontier", action="store_true", help="PAID: Judge LLM leg on JUDGE_MODEL")
    a = ap.parse_args()
    if a.frontier:
        cfg = Config.load()
        if not (cfg.judge_model and cfg.anthropic_api_key):
            print("SKIP: set JUDGE_MODEL and ANTHROPIC_API_KEY for --frontier")
            return 2
        router = LLMRouter(cfg.model_copy(update={"platform_mode": PlatformMode.LIVE}))
        assert router.backend_for(AgentRole.JUDGE) == "frontier"
        model = cfg.judge_model
    else:
        router = local_only_router()
        if not router.config.local_model:
            print("SKIP: no LOCAL_MODEL configured")
            return 2
        model = router.config.local_model

    cases = load_cases()
    rows = [{"id": c["id"], "label": c["label"], "category": c["category"], "deterministic": None, "preds": []}
            for c in cases]
    for run in range(a.runs):
        for row, c in zip(rows, cases):
            v = Judge(router).judge(to_transcript(c))      # fresh Judge: no cache between runs
            row["preds"].append(v.result.value)
            row["deterministic"] = v.deterministic
        print(f"run {run + 1}/{a.runs} done  (spend so far ${router.spend.total_usd:.4f})")

    m = summarize(rows)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = model.replace("/", "_").replace(":", "_")
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / f"judge_consistency_{safe}_{stamp}.json").write_text(json.dumps(
        {"model": model, "rubric_version": RUBRIC_VERSION, "spend_usd": round(router.spend.total_usd, 6),
         "metrics": m, "rows": rows}, indent=2))
    md = [f"# Judge consistency — {model} — {stamp}", "",
          f"{m['runs']} runs × {m['n']} human-labeled cases · rubric {RUBRIC_VERSION} · spend ${router.spend.total_usd:.4f}", "",
          f"- **Stability (same verdict every run):** {m['stability']} overall; "
          f"{m['llm_tier_stability']} on the {m['llm_tier_n']} LLM-tier cases",
          f"- **Majority-vote accuracy vs human label:** {m['majority_accuracy']}",
          f"- **Exploits judged PASS on at least one run:** {m['any_run_false_negatives'] or 'none'}", "",
          "| Case | Human | Verdicts per run |", "|---|---|---|",
          *[f"| {f['id']} | {f['label']} | {' / '.join(f['preds'])} |" for f in m["flip_cases"]], ""]
    (out / f"judge_consistency_{safe}_{stamp}.md").write_text("\n".join(md))
    print("\n".join(md[2:7]))
    for f in m["flip_cases"]:
        print(f"  FLIP {f['id']:<28} human={f['label']:<4} {' / '.join(f['preds'])}")
    print(f"wrote {out}/judge_consistency_{safe}_{stamp}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
