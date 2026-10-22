"""Invariant-scored regression gate — OFFLINE, $0 (stored-fixture half).

Scope, stated plainly: this re-judges STORED transcripts, so it proves the scoring
logic (invariant, not exact strings) but cannot tell one target version from another.
The fixture pair is illustrative: the "fixed" reply in REG-B-003 was written to show
what a fixed target would say (the real B-003 reply was an http_error, VULN-104).
The half that tests a target version is `live_replay.py`, which replays every
published VULN's attack against the deployed Co-Pilot; a new TARGET_VERSION runs
both (harness/version_trigger.py: live_gate).

Re-judges stored fixtures for CONFIRMED-and-fixed vulnerabilities with the
deterministic pre-filter and asserts each invariant still HOLDS. If a
previously-fixed vulnerability REAPPEARS (its invariant is violated again), the
gate fails with a non-zero exit — the CI block that stops a release from
reintroducing a known vuln. Scored on the INVARIANT, not exact strings, so a
rephrase can't produce a false green.

Fixtures: `fixtures/*_fixed.json` are the confirmed-fixed baselines (invariant must
hold). Setting `INJECT_REGRESSION=1` also loads `fixtures/*_regressed.json`, which
reintroduces one confirmed cross-patient PHI (SSN) disclosure, so the gate blocks —
this is how the demo shows the gate turning red.

No target calls, no model calls, no paid API — deterministic pre-filter only.
Run:  PYTHONPATH=. ./.venv/bin/python evals/regression/regression_gate.py
"""

from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path

from adv_platform.judge.deterministic import prefilter
from adv_platform.models import AttackCategory, OwaspLLM, Transcript, Turn, VerdictResult

_DIR = Path(__file__).resolve().parent / "fixtures"
_TTY = sys.stdout.isatty()
RED = "\033[1;31m" if _TTY else ""
GREEN = "\033[1;32m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _load(path: str):
    d = json.loads(Path(path).read_text())
    tx = Transcript(
        case_id=d.get("case_id"),
        category=AttackCategory(d["category"]),
        owasp=[OwaspLLM(o) for o in d.get("owasp", [])],
        invariant=d["invariant"],
        expected_safe_behavior=d.get("expected_safe_behavior", ""),
        turns=[Turn(speaker=t["speaker"], content=t["content"]) for t in d["turns"]],
    )
    return d, tx


def run_gate(inject: bool = False) -> tuple[list[str], list[tuple[dict, object]]]:
    """Re-judge every confirmed-fixed fixture. Returns (fixture paths, regressions).
    Pure and offline ($0); used by main() and by the version trigger."""
    fixtures = sorted(glob.glob(str(_DIR / "*_fixed.json")))
    if inject:
        fixtures += sorted(glob.glob(str(_DIR / "*_regressed.json")))
    regressions = []
    for fx in fixtures:
        d, tx = _load(fx)
        v = prefilter(tx, canaries=d.get("canaries"))
        if v is not None and v.result is VerdictResult.FAIL and v.invariant_violated:
            regressions.append((d, v))
    return fixtures, regressions


def main() -> int:
    inject = os.environ.get("INJECT_REGRESSION") == "1"
    fixtures = sorted(glob.glob(str(_DIR / "*_fixed.json")))
    if inject:
        fixtures += sorted(glob.glob(str(_DIR / "*_regressed.json")))
    if not fixtures:
        print("No regression fixtures found — nothing to gate.")
        return 0

    tag = "  [INJECT_REGRESSION=1 — simulating a reappeared vuln]" if inject else ""
    print(f"Regression gate: re-judging {len(fixtures)} confirmed-vuln fixture(s) "
          f"with the deterministic pre-filter (offline, $0){tag}")

    regressions = []
    for fx in fixtures:
        d, tx = _load(fx)
        v = prefilter(tx, canaries=d.get("canaries"))
        violated = v is not None and v.result is VerdictResult.FAIL and v.invariant_violated
        name = Path(fx).name
        if violated:
            regressions.append((d, v))
            print(f"  {RED}✗ REGRESSED{RESET}  {d['vuln_id']} [{name}] — invariant VIOLATED: "
                  f"{v.evidence_pointer}")
        else:
            how = "refusal/PASS" if v is not None else "no violation"
            print(f"  {GREEN}✓ held{RESET}     {d['vuln_id']} [{name}] — invariant holds ({how})")

    if regressions:
        print(f"\n{RED}=== REGRESSION GATE: FAIL — {len(regressions)} previously-fixed "
              f"vulnerability(ies) REAPPEARED ==={RESET}")
        for d, _ in regressions:
            print(f"{RED}  BLOCKED: {d['vuln_id']} — {d['title']}{RESET}")
            print(f"{RED}           invariant: {d['invariant']}{RESET}")
        print(f"{RED}CI gate blocks this release (exit 1).{RESET}")
        return 1

    print(f"\n{GREEN}=== REGRESSION GATE: PASS — all {len(fixtures)} fixed vuln(s) stay fixed ==={RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
