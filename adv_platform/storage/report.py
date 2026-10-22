"""VULN report + coverage renderer — PLATFORM ZONE.

Reads the (already-redacted) exploit DB and renders a human-readable Markdown
report: a coverage summary plus one section per Finding. Findings persisted by the
graph are `open` / `human_approved=False`; this report makes clear that NONE is
`critical`/`published` until the deterministic human-approval gate (D4/R8) signs
off — the report never promotes a finding itself.

Nothing raw reaches here: Findings are redacted at creation (R4) and the DB stores
them as-is.
"""

from __future__ import annotations

from adv_platform.models import AttackCategory, Finding, OwaspLLM
from adv_platform.storage.exploit_db import ExploitDB

_CATEGORY_NAMES = {
    "A": "Indirect prompt injection (uploaded doc)",
    "B": "Cross-patient PHI / authorization bypass",
    "C": "Verification bypass (ungrounded clinical claim)",
    "D": "Multi-turn erosion (crescendo)",
    "E": "System-prompt / config leakage",
    "F": "Unbounded consumption (denial-of-wallet)",
    "G": "Insecure output handling (HTML/script)",
}


def _coverage_md(cov: dict) -> list[str]:
    lines = ["## Coverage", ""]
    tested = set(cov["categories_tested"])
    lines.append("| Category | Tested | pass | fail | error | unique |")
    lines.append("|---|---|---|---|---|---|")
    for c in cov["all_categories"]:
        b = cov["by_category"].get(c, {})
        mark = "✓" if c in tested else "—"
        lines.append(
            f"| {c}: {_CATEGORY_NAMES.get(c, c)} | {mark} | "
            f"{b.get('pass', 0)} | {b.get('fail', 0)} | {b.get('error', 0)} | "
            f"{b.get('unique', 0)} |"
        )
    d = cov["dedupe"]
    lines += [
        "",
        f"**OWASP covered:** {', '.join(cov['owasp_covered']) or '—'} "
        f"(of {len(cov['all_owasp'])})",
        f"**Findings:** {cov['findings_total']} "
        f"({', '.join(f'{k}={v}' for k, v in sorted(cov['findings_by_severity'].items())) or 'none'})",
        f"**Dedupe:** {d['unique_transcripts']} unique transcript(s), "
        f"{d['duplicates_skipped']} duplicate judge call(s) skipped "
        f"(§0.7 — never judge the same transcript twice).",
        "",
    ]
    return lines


def _finding_md(f: Finding) -> list[str]:
    owasp = ", ".join(o.value for o in f.owasp)
    lines = [
        f"### {f.vuln_id} — {f.title}",
        "",
        f"- **Severity:** {f.severity.value}  |  **Status:** {f.status.value}  "
        f"|  **Human-approved:** {'yes' if f.human_approved else 'NO (awaiting D4 gate)'}",
        f"- **Category:** {f.attack_category.value} ({_CATEGORY_NAMES.get(f.attack_category.value, '')})  "
        f"|  **OWASP:** {owasp}",
        f"- **Clinical impact:** {f.clinical_impact}",
        "",
        "**Reproduction (black-box, redacted):**",
    ]
    lines += [f"{i}. {step}" for i, step in enumerate(f.repro_steps, 1)] or ["1. (none recorded)"]
    lines += [
        "",
        f"**Observed:** {f.observed}",
        "",
        f"**Expected:** {f.expected}",
        "",
        "**Remediation (named controls):**",
    ]
    lines += [f"- {r}" for r in f.remediation] or ["- (none recorded)"]
    lines += [""]
    return lines


def render_markdown(db: ExploitDB, title: str = "Adversarial Campaign — VULN Report") -> str:
    cov = db.coverage()
    findings = db.all_findings()
    out = [
        f"# {title}",
        "",
        "> Generated from the exploit DB (PHI-redacted at source, R4). Findings are "
        "`open` and **NOT** published — each requires the deterministic human-approval "
        "gate (D4/R8) before it can become `critical`/`published`.",
        "",
    ]
    out += _coverage_md(cov)
    out += ["## Findings", ""]
    if not findings:
        out += ["_No findings: every judged attack was defended (or errored — never scored as pass, R11)._", ""]
    else:
        for f in findings:
            out += _finding_md(f)
    return "\n".join(out)


def main() -> int:
    """CLI: render the report for the configured exploit DB to stdout."""
    import sys

    from adv_platform.config import Config

    cfg = Config.load()
    db = ExploitDB(cfg.exploit_db_path)
    try:
        sys.stdout.write(render_markdown(db))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
