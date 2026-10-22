"""Vulnerability-report format checks — local-only, $0.

Spec (Documentation Agent): every report has a unique id + severity, description,
clinical impact, a minimal reproducible attack sequence, observed vs expected,
remediation, and current status AND fix validation results.

Run:  PYTHONPATH=. ./.venv/bin/python evals/reports/test_report_format.py
"""

from __future__ import annotations

import pathlib
import re
import sys
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parents[2]
REPORTS = sorted((ROOT / "reports").glob("VULN-*.md"))
REQUIRED = ["| Severity |", "## Description", "## Clinical impact",
            "## Minimal reproducible attack sequence", "## Observed vs. expected",
            "## Recommended remediation", "## Status", "## Fix validation results"]
FV_FIELDS = ["**Fix deployed:**", "**How a fix is validated:**", "**Last result:**", "**Re-validate when:**"]


def check_at_least_three_reports() -> tuple[bool, str]:
    return len(REPORTS) >= 3, f"{len(REPORTS)} reports (spec minimum 3)"


def check_unique_ids() -> tuple[bool, str]:
    ids = [re.match(r"# (VULN-\d+)", p.read_text()).group(1) for p in REPORTS]
    names = [p.stem for p in REPORTS]
    return len(set(ids)) == len(ids) and ids == names, f"ids={ids}"


def check_every_report_has_required_sections() -> tuple[bool, str]:
    missing = {p.stem: [s for s in REQUIRED + FV_FIELDS if s not in p.read_text()] for p in REPORTS}
    missing = {k: v for k, v in missing.items() if v}
    return not missing, f"missing: {missing or 'none'}"


def check_generator_renders_fix_validation() -> tuple[bool, str]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import finalize_reports as f  # noqa: PLC0415

    class Rec:
        reviewer, at, fingerprint = "test", datetime(2026, 9, 30), "0" * 32

    bad = [vr["vuln_id"] for vr in f.VRS
           if not all(x in f.render_md(vr, f.build_finding(vr), Rec) for x in ["## Fix validation results"] + FV_FIELDS)]
    return not bad, f"{len(f.VRS)} VR records render the fix-validation section; missing: {bad or 'none'}"


CHECKS = [check_at_least_three_reports, check_unique_ids,
          check_every_report_has_required_sections, check_generator_renders_fix_validation]


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
