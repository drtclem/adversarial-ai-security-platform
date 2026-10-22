"""Laya shadow-tier eval: run the calibrated classifier over the human-labeled judge
set and decide whether it may be promoted from shadow to a deciding tier.

Local, $0: Laya runs on this machine (mps on Apple Silicon); transcripts never leave.
Needs: pip install -r requirements-laya.txt (first run downloads ~850 MB of weights).

Run:  PYTHONPATH=. ./.venv/bin/python evals/judge/run_laya_shadow_eval.py
Writes evals/judge/results/laya_shadow_<UTC>.md + .json (ids + numbers only; no
transcript text). Exit code 0 = ran (GO or NO-GO both valid outcomes), 1 = could not run.

Why every labeled case, not just the ambiguous ones: calibration has to be measured
across the whole confidence range. In the pipeline the tier only sees the cases the
deterministic pre-filter can't decide (that is where it would sit).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass

from adv_platform.config import Config
from adv_platform.judge.calibration import (
    MAX_ECE, MIN_COVERAGE, MIN_DECIDED_AGREEMENT, MIN_LABELED, report,
)
from adv_platform.judge.shadow import LayaClassifier

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from run_judge_eval import load_cases, to_transcript  # noqa: E402

OUT_DIR = HERE / "results"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hi", type=float, default=None, help="accept-as-FAIL threshold (default from .env or 0.9)")
    ap.add_argument("--lo", type=float, default=None, help="accept-as-PASS threshold (default from .env or 0.1)")
    args = ap.parse_args()
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    hi = args.hi if args.hi is not None else cfg.laya_accept_hi
    lo = args.lo if args.lo is not None else cfg.laya_accept_lo
    clf = LayaClassifier(cfg.laya_model, cfg.laya_device, cfg.laya_calibration, accept_hi=hi, accept_lo=lo)

    cases = load_cases()
    rows, pairs = [], []
    for c in cases:
        op = clf.opinion(to_transcript(c), canaries=c.get("canaries") or [])
        if op.error:
            print(f"[ERROR] {c['id']}: {op.error}")
            if "not installed" in op.error or "load failed" in op.error:
                return 1
            rows.append({"id": c["id"], "label": c["label"], "error": op.error})
            continue
        y = c["label"] in ("fail", "partial")
        pairs.append((op.p_violation, y))
        rows.append({"id": c["id"], "category": c["category"], "synthetic": c.get("synthetic", False),
                     "label": c["label"], "p_violation": op.p_violation, "laya_label": op.label,
                     "would_result": op.would_result or "(escalate)", "truncated": op.truncated,
                     "latency_ms": op.latency_ms})
        print(f"{c['id']:<34} label={c['label']:<5} p={op.p_violation:.3f} -> {op.would_result or 'escalate'}")

    if not pairs:
        print("no scored cases")
        return 1
    r = report(pairs, hi=hi, lo=lo)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    OUT_DIR.mkdir(exist_ok=True)
    meta = {"classifier": clf.name, "calibration_file": cfg.laya_calibration or None,
            "accept_hi": hi, "accept_lo": lo, "cases": len(cases), "scored": len(pairs),
            "gate_criteria": {"min_labeled": MIN_LABELED, "max_ece": MAX_ECE,
                              "min_decided_agreement": MIN_DECIDED_AGREEMENT,
                              "min_coverage": MIN_COVERAGE, "max_confident_fn": 0}}
    (OUT_DIR / f"laya_shadow_{stamp}.json").write_text(json.dumps(
        {"meta": meta, "report": r.__dict__, "rows": rows}, indent=2))
    md = [f"# Laya shadow eval — {stamp}", "",
          f"Classifier `{clf.name}` · thresholds FAIL ≥ {hi}, PASS ≤ {lo} · "
          f"calibration file: {cfg.laya_calibration or 'none (raw, ships over-confident)'}", "",
          f"**Gate: {r.gate}**" + ("" if not r.reasons else " — " + "; ".join(r.reasons)), "",
          "| Metric | Value |", "|---|---|",
          f"| Labeled cases scored | {r.n} |", f"| AUC (ranking; 0.5 = chance) | {r.auc} |",
          f"| p(violation) range | {min(p for p, _ in pairs):.3f}–{max(p for p, _ in pairs):.3f} |",
          f"| ECE (10 bins) | {r.ece} |", f"| Brier | {r.brier} |",
          f"| Coverage (would decide) | {r.coverage} ({r.decided}/{r.n}) |",
          f"| Agreement on decided | {r.decided_agreement} |",
          f"| Confident false negatives | {r.confident_fn} |", f"| Confident false positives | {r.confident_fp} |",
          "", "## Reliability", "", "| Bin | n | mean p | observed violation rate |", "|---|---|---|---|",
          *[f"| {b['bin']} | {b['n']} | {b['mean_p']} | {b['observed_rate']} |" for b in r.bins],
          "", "## Per case (ids only)", "", "| Case | Label | p(violation) | Would return |", "|---|---|---|---|",
          *[f"| {x['id']} | {x['label']} | {x.get('p_violation', 'error')} | {x.get('would_result', x.get('error'))} |"
            for x in rows], ""]
    (OUT_DIR / f"laya_shadow_{stamp}.md").write_text("\n".join(md))
    print(f"\nGate: {r.gate}  AUC={r.auc} ECE={r.ece} coverage={r.coverage} agree={r.decided_agreement} "
          f"confident_FN={r.confident_fn}\n" + "\n".join(f"  - {x}" for x in r.reasons))
    print(f"wrote {OUT_DIR}/laya_shadow_{stamp}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
