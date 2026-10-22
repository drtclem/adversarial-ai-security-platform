"""Seed-case schema checks — local-only, $0.

Spec Stage 3 asks every test case for a severity rating and an exploitability
assessment (reviewer note on the early submission: they lived on the VULN reports,
not on the cases). These checks make that a contract, not a convention:
every seed is rated, the vocabulary matches the reports, YAML keys can't silently
drop (pydantic ignores unknown keys), mutations inherit their parent's rating, and
the Documentation agent's drafts start from the case's own rating.

Run:  PYTHONPATH=. ./.venv/bin/python evals/seeds/test_seed_schema.py
"""

from __future__ import annotations

import pathlib
import sys

import yaml

from adv_platform.documentation.documentation import Documentation
from adv_platform.models import (
    AttackCase,
    AttackCategory,
    Exploitability,
    Severity,
    Transcript,
    Verdict,
    VerdictResult,
)
from adv_platform.redteam import seeds as seed_loader
from adv_platform.redteam.mutator import Mutator

SEEDS = seed_loader.load_all()
SEED_DIR = pathlib.Path(__file__).parent
CASE_SEVERITIES = {Severity.LOW, Severity.MEDIUM, Severity.HIGH}   # same scale as the VRs


def _is_control(c: AttackCase) -> bool:
    return c.exploitability is Exploitability.NOT_APPLICABLE


def check_every_seed_rated() -> tuple[bool, str]:
    bad = [c.id for c in SEEDS
           if c.severity is None or c.exploitability is None or not c.exploitability_note.strip()]
    return not bad and len(SEEDS) > 0, f"{len(SEEDS)} seeds; unrated: {bad or 'none'}"


def check_vocabulary_matches_reports() -> tuple[bool, str]:
    # Attacks use Low/Medium/High like the VULN reports; only control probes may be
    # INFO + n/a, and a control must not be a regression/security case.
    bad = []
    for c in SEEDS:
        if _is_control(c):
            if c.severity is not Severity.INFO or c.add_to_regression or c.owasp:
                bad.append(c.id)
        elif c.severity not in CASE_SEVERITIES:
            bad.append(c.id)
    return not bad, f"out-of-vocabulary or mis-flagged controls: {bad or 'none'}"


def check_no_silently_dropped_yaml_keys() -> tuple[bool, str]:
    known = set(AttackCase.model_fields)
    unknown = {}
    for f in sorted(SEED_DIR.glob("*.yaml")):
        for item in yaml.safe_load(f.read_text()) or []:
            extra = set(item) - known
            if extra:
                unknown[item.get("id", f.name)] = sorted(extra)
    return not unknown, f"unknown keys (would be ignored by pydantic): {unknown or 'none'}"


def check_every_category_has_a_rated_attack() -> tuple[bool, str]:
    cats = {c.category for c in SEEDS}
    rated = {c.category for c in SEEDS if not _is_control(c) and c.severity in CASE_SEVERITIES}
    return cats == rated, f"categories {sorted(x.value for x in cats)}; with a rated attack {sorted(x.value for x in rated)}"


def check_mutations_inherit_rating() -> tuple[bool, str]:
    parent = next(c for c in SEEDS if c.id == "E-001")
    child = Mutator(lambda *a, **k: "")._child(parent, ["reworded probe"], "llm-test")
    ok = (child.severity is parent.severity and child.exploitability is parent.exploitability
          and child.exploitability_note == parent.exploitability_note)
    return ok, f"{child.id}: severity={child.severity.value} exploitability={child.exploitability.value}"


def check_documentation_uses_case_severity() -> tuple[bool, str]:
    # A-002 is rated MEDIUM (config disclosure) while category A defaults to HIGH:
    # the draft must start from the case's own rating.
    case = next(c for c in SEEDS if c.id == "A-002")
    tx = Transcript(case_id=case.id, category=AttackCategory.A_INDIRECT_INJECTION, owasp=case.owasp,
                    invariant=case.invariant, expected_safe_behavior=case.expected_safe_behavior)
    v = Verdict(transcript_id=tx.id, correlation_id=tx.correlation_id,
                result=VerdictResult.FAIL, invariant_violated=True, rationale="synthetic")
    f = Documentation().write_finding(v, tx, case)
    return f.severity is Severity.MEDIUM and not f.human_approved, f"draft severity={f.severity.value} (case rating), human_approved={f.human_approved}"


# Category -> classic OWASP codes, as justified in THREAT_MODEL.md's coverage table.
CLASSIC_BY_CATEGORY = {"A": {"A03"}, "B": {"A01"}, "C": {"A04"}, "E": set(), "G": {"A03"}}


def check_classic_owasp_matches_threat_model() -> tuple[bool, str]:
    bad = [c.id for c in SEEDS if not _is_control(c)
           and set(c.owasp_web) != CLASSIC_BY_CATEGORY.get(c.category.value, set())]
    return not bad, f"per-case classic OWASP agrees with THREAT_MODEL mapping; mismatches: {bad or 'none'}"


def check_every_attack_declares_test_design() -> tuple[bool, str]:
    bad = [c.id for c in SEEDS if _is_control(c) == bool(c.test_design)]
    reg = [c.id for c in SEEDS if "regression" in c.test_design and not c.add_to_regression]
    return not bad and not reg, f"missing/mis-set test_design: {bad or 'none'}; regression-tagged but not in suite: {reg or 'none'}"


def check_seed_table_in_sync() -> tuple[bool, str]:
    sys.path.insert(0, str(SEED_DIR.parents[1] / "scripts"))
    from render_seed_table import OUT, render
    ok = OUT.exists() and OUT.read_text() == render()
    return ok, f"{OUT} matches the YAML" if ok else f"{OUT} is stale: run scripts/render_seed_table.py"


CHECKS = [
    check_every_seed_rated,
    check_vocabulary_matches_reports,
    check_no_silently_dropped_yaml_keys,
    check_every_category_has_a_rated_attack,
    check_mutations_inherit_rating,
    check_documentation_uses_case_severity,
    check_classic_owasp_matches_threat_model,
    check_every_attack_declares_test_design,
    check_seed_table_in_sync,
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
