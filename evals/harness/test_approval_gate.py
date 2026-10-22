"""Offline tests for the deterministic human-approval gate (D4/R8). $0.

Focus: nothing but an explicit human decision recorded in the gate's ledger can
make a finding publishable/critical — no forged flag, no agent reviewer, no
tampering, no prompt shortcut.

Run:  PYTHONPATH=. ./.venv/bin/python evals/harness/test_approval_gate.py
"""

from __future__ import annotations

import sys

from adv_platform.harness.approval_gate import ApprovalError, ApprovalGate
from adv_platform.models import (
    AttackCategory,
    Finding,
    FindingStatus,
    OwaspLLM,
    Severity,
)


def _finding(**over) -> Finding:
    base = dict(
        vuln_id="VULN-001",
        title="B: cross-patient",
        severity=Severity.HIGH,
        owasp=[OwaspLLM.LLM02_SENSITIVE_INFO_DISCLOSURE],
        attack_category=AttackCategory.B_CROSS_PATIENT_PHI,
        clinical_impact="PHI disclosure",
        repro_steps=["POST /chat: ..."],
        observed="leaked identifier",
        expected="refuse",
        remediation=["scope to patient"],
        transcript_id="tx-1",
    )
    base.update(over)
    return Finding(**base)


def check_new_finding_not_publishable() -> tuple[bool, str]:
    g = ApprovalGate()
    f = _finding()
    ok = (not g.is_publishable(f)) and (not f.human_approved) and f.status is FindingStatus.OPEN
    return ok, "fresh finding is not publishable"


def check_approve_promotes() -> tuple[bool, str]:
    g = ApprovalGate()
    f = g.approve(_finding(), reviewer="taylor", severity=Severity.CRITICAL, note="confirmed")
    ok = (f.human_approved and f.status is FindingStatus.PUBLISHED
          and f.severity is Severity.CRITICAL and g.is_publishable(f)
          and g.can_mark_critical(f))
    return ok, f"approved -> published/critical/publishable"


def check_blank_reviewer_refused() -> tuple[bool, str]:
    g = ApprovalGate()
    for bad in ["", "   ", None]:
        try:
            g.approve(_finding(), reviewer=bad)  # type: ignore[arg-type]
            return False, f"blank reviewer {bad!r} was NOT refused"
        except ApprovalError:
            pass
    return True, "blank reviewer refused"


def check_agent_cannot_self_approve() -> tuple[bool, str]:
    g = ApprovalGate()
    for agent in ["judge", "documentation", "redteam", "orchestrator", "JUDGE"]:
        try:
            g.approve(_finding(), reviewer=agent)
            return False, f"agent reviewer {agent!r} was NOT refused"
        except ApprovalError:
            pass
    return True, "agent reviewers refused (no self-approval)"


def check_forged_flag_not_publishable() -> tuple[bool, str]:
    # THE key R8 test: a finding with human_approved=True but NO gate approval.
    g = ApprovalGate()
    forged = _finding(human_approved=True, status=FindingStatus.PUBLISHED, severity=Severity.CRITICAL)
    ok = not g.is_publishable(forged)
    raised = False
    try:
        g.assert_publishable(forged)
    except ApprovalError:
        raised = True
    return ok and raised, "forged human_approved flag is NOT publishable (ledger authoritative)"


def check_tamper_invalidates_approval() -> tuple[bool, str]:
    g = ApprovalGate()
    approved = g.approve(_finding(), reviewer="taylor")
    tampered = approved.model_copy(update={"observed": "something else entirely"})
    ok = g.is_publishable(approved) and not g.is_publishable(tampered)
    return ok, "altering an approved finding invalidates the approval (fingerprint)"


def check_reject_not_publishable() -> tuple[bool, str]:
    g = ApprovalGate()
    f = g.reject(_finding(), reviewer="taylor", reason="broken worker, not a leak")
    ok = (not f.human_approved) and f.status is FindingStatus.RESOLVED and not g.is_publishable(f)
    rec = g.record_for("VULN-001")
    ok = ok and rec is not None and rec.decision == "rejected" and rec.reviewer == "taylor"
    return ok, "rejected -> resolved, not publishable, audited"


def check_requires_transcript() -> tuple[bool, str]:
    g = ApprovalGate()
    try:
        g.approve(_finding(transcript_id=None), reviewer="taylor")
        return False, "approved a finding with no transcript_id"
    except ApprovalError:
        return True, "finding without transcript_id is not reviewable"


def check_audit_record() -> tuple[bool, str]:
    g = ApprovalGate()
    g.approve(_finding(), reviewer="dr. taylor", note="verified against chart")
    rec = g.record_for("VULN-001")
    ok = rec is not None and rec.decision == "approved" and rec.reviewer == "dr. taylor" and rec.at is not None
    return ok, f"audit record: {rec.decision if rec else None}/{rec.reviewer if rec else None}"


CHECKS = [
    check_new_finding_not_publishable,
    check_approve_promotes,
    check_blank_reviewer_refused,
    check_agent_cannot_self_approve,
    check_forged_flag_not_publishable,
    check_tamper_invalidates_approval,
    check_reject_not_publishable,
    check_requires_transcript,
    check_audit_record,
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
