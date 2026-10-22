"""Render evals/SEED_CASES.md from evals/seeds/*.yaml (the YAML is the source of truth).

Run:  PYTHONPATH=. ./.venv/bin/python scripts/render_seed_table.py
evals/seeds/test_seed_schema.py fails if the committed table drifts from the YAML.
"""

from __future__ import annotations

import pathlib
import sys

from adv_platform.redteam import seeds as seed_loader

OUT = pathlib.Path("evals/SEED_CASES.md")


def render() -> str:
    rows = []
    for c in seed_loader.load_all():
        owasp = ", ".join([o.value for o in c.owasp] + list(c.owasp_web)) or "none (control)"
        tests = ", ".join(c.test_design) or "control"
        note = " ".join(c.exploitability_note.split()).replace("|", "\\|")
        rows.append(
            f"| {c.id} | {c.category.value} / {c.subcategory} | {owasp} | "
            f"{c.severity.value.title() if c.severity else '—'} | "
            f"{c.exploitability.value.title() if c.exploitability else '—'} | "
            f"{'yes' if c.add_to_regression else 'no'} | {tests} | {note} |"
        )
    return "\n".join([
        "# Seed attack cases: severity and exploitability",
        "",
        "Generated from `evals/seeds/*.yaml` by `scripts/render_seed_table.py`; do not edit by hand.",
        "",
        "- **Severity** is the clinical impact *if the attack lands* (the ceiling), on the same",
        "  Low / Medium / High scale as the VULN reports. A published finding's severity is what was",
        "  *demonstrated*, so it can be lower (B-003 is High here; VULN-101 is Medium because the",
        "  leak was averted by a broken worker, not shown).",
        "- **Exploitability** is how likely an attacker with only a clinician chat session lands it:",
        "  preconditions plus what we observed against the live target (9/29 campaign, 31 attacks).",
        "- **OWASP** lists the LLM Top 10 (2025) tags and the classic OWASP Top 10 (2021) codes",
        "  (A01 broken access control, A03 injection, A04 insecure design). Category-level coverage,",
        "  including the scoped-out classic rows (A06, A09, A10, partial A07), is in THREAT_MODEL.md.",
        "- **Tests** says what each case exercises: an *invariant* (a rule that must hold), a",
        "  *boundary* (an edge-case multi-turn sequence), or a *regression* risk (a stored fixture",
        "  or canary-armed re-test for a known finding).",
        "- Observed pass/fail per run lives with the results, not here, so these ratings don't go",
        "  stale when a new run disagrees.",
        "",
        "| Case | Category / subcategory | OWASP | Severity | Exploitability | Regression | Tests | Why this exploitability |",
        "|---|---|---|---|---|---|---|---|",
        *rows,
        "",
    ])


def main() -> int:
    OUT.write_text(render())
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
