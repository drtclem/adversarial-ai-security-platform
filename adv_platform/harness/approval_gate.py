"""Deterministic human-approval gate — PLATFORM ZONE (D4/R8).

The trust boundary: a `Finding` may become `critical` or `published` ONLY via an
explicit human decision recorded here. This is plain code, outside any LLM's
control — no agent, prompt, or model output can promote a finding. There is no
prompt-instruction shortcut.

Hardening against bypass:
  - The gate keeps its OWN ledger: an in-memory map holding the latest decision
    per VULN id (a new decision replaces the old one; it is not append-only, and
    it lasts for the life of the gate instance). `is_publishable()` trusts the
    LEDGER, not the `Finding.human_approved` flag — so forging that flag on a
    Finding object (by a buggy caller or a model-authored dict) does NOT make it
    publishable.
  - `approve()` requires a human `reviewer` id. A blank reviewer, or one that
    matches an agent role name, is refused (an agent cannot pose as the reviewer).
  - Each approval is bound to a content FINGERPRINT of the finding; altering the
    finding after approval invalidates it (tamper-evident).
  - `assert_publishable()` is the guard any publish/report path must call first.

This module is invoked by the human operator / harness, and is deliberately NOT a
node in the agent graph — the graph only ever produces `open`, unapproved findings.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from adv_platform.models import AgentRole, Finding, FindingStatus, Severity


class ApprovalError(Exception):
    """A gate precondition failed. Promotion is refused."""


_AGENT_NAMES = {r.value for r in AgentRole} | {r.name.lower() for r in AgentRole}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def fingerprint(finding: Finding) -> str:
    """Stable content hash binding an approval to this exact finding."""
    basis = {
        "vuln_id": finding.vuln_id,
        "attack_category": finding.attack_category.value,
        "transcript_id": finding.transcript_id or "",
        "observed": finding.observed,
        "expected": finding.expected,
    }
    raw = json.dumps(basis, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApprovalRecord:
    vuln_id: str
    decision: str            # "approved" | "rejected"
    reviewer: str            # human identity (never an agent)
    fingerprint: str
    note: str
    at: datetime


class ApprovalGate:
    def __init__(self) -> None:
        self._ledger: dict[str, ApprovalRecord] = {}

    # ---- validation ---------------------------------------------------------
    @staticmethod
    def _require_human_reviewer(reviewer: str) -> str:
        r = (reviewer or "").strip()
        if not r:
            raise ApprovalError("a human reviewer id is required (R8): none supplied")
        if r.lower() in _AGENT_NAMES:
            raise ApprovalError(f"reviewer '{r}' is an agent role — agents cannot self-approve (R8)")
        return r

    @staticmethod
    def _require_reviewable(finding: Finding) -> None:
        # Minimal preconditions: a finding must trace to evidence.
        if not finding.transcript_id:
            raise ApprovalError("finding has no transcript_id — not reviewable")
        if not finding.vuln_id:
            raise ApprovalError("finding has no vuln_id")

    # ---- decisions (the ONLY writers of the ledger) -------------------------
    def submit_for_review(self, finding: Finding) -> Finding:
        """Mark a finding as a review candidate. Does NOT approve anything."""
        return finding.model_copy(update={"status": FindingStatus.IN_PROGRESS})

    def approve(
        self,
        finding: Finding,
        reviewer: str,
        *,
        note: str = "",
        severity: Optional[Severity] = None,
    ) -> Finding:
        """The ONLY path to human_approved=True / PUBLISHED (and CRITICAL). Requires
        a human reviewer. Records the decision in the ledger, bound to the finding's
        fingerprint."""
        r = self._require_human_reviewer(reviewer)
        self._require_reviewable(finding)
        fp = fingerprint(finding)
        self._ledger[finding.vuln_id] = ApprovalRecord(
            vuln_id=finding.vuln_id, decision="approved", reviewer=r,
            fingerprint=fp, note=note, at=_now(),
        )
        return finding.model_copy(update={
            "human_approved": True,
            "status": FindingStatus.PUBLISHED,
            "severity": severity or finding.severity,
        })

    def reject(self, finding: Finding, reviewer: str, *, reason: str = "") -> Finding:
        r = self._require_human_reviewer(reviewer)
        self._ledger[finding.vuln_id] = ApprovalRecord(
            vuln_id=finding.vuln_id, decision="rejected", reviewer=r,
            fingerprint=fingerprint(finding), note=reason, at=_now(),
        )
        return finding.model_copy(update={
            "human_approved": False,
            "status": FindingStatus.RESOLVED,   # resolved as not-a-vuln / not published
        })

    # ---- authoritative checks (trust the LEDGER, not the flag) --------------
    def record_for(self, vuln_id: str) -> Optional[ApprovalRecord]:
        return self._ledger.get(vuln_id)

    def is_publishable(self, finding: Finding) -> bool:
        rec = self._ledger.get(finding.vuln_id)
        return bool(
            rec
            and rec.decision == "approved"
            and rec.fingerprint == fingerprint(finding)   # tamper check
            and finding.human_approved                    # flag must also agree
        )

    def assert_publishable(self, finding: Finding) -> None:
        """Guard for any publish/report/critical path. Raises unless a matching
        human approval exists in the ledger."""
        if not self.is_publishable(finding):
            raise ApprovalError(
                f"finding {finding.vuln_id} is not human-approved via the gate — "
                f"refusing to publish/mark critical (R8)"
            )

    def can_mark_critical(self, finding: Finding) -> bool:
        return self.is_publishable(finding)
