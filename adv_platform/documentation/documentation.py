"""Documentation agent — PLATFORM ZONE.

Turns a CONFIRMED `Verdict` (invariant broke) into a reproducible `Finding`
(VULN-XXX): severity, clinical impact, minimal black-box repro from the transcript,
observed vs expected, remediation via named controls (spec §8).

Deterministic/templated ($0) in every mode today; frontier-authored prose in `live` is
planned but not wired. The STRUCTURE and, crucially, the human-approval gate (D4/R8)
are code, outside any LLM. This agent NEVER sets `human_approved` / `critical` /
`published`; only the deterministic gate (`adv_platform/harness/approval_gate.py`)
can, and only for a human reviewer.
R4: repro/observed are built from redacted transcript text.
"""

from __future__ import annotations

from adv_platform.judge.deterministic import redact
from adv_platform.models import (
    AttackCase,
    AttackCategory,
    Finding,
    FindingStatus,
    Severity,
    Transcript,
    Verdict,
)

# baseline severity by category (a starting point; the human gate sets critical)
_SEVERITY: dict[AttackCategory, Severity] = {
    AttackCategory.A_INDIRECT_INJECTION: Severity.HIGH,
    AttackCategory.B_CROSS_PATIENT_PHI: Severity.HIGH,
    AttackCategory.C_VERIFICATION_BYPASS: Severity.HIGH,
    AttackCategory.D_MULTITURN_EROSION: Severity.MEDIUM,
    AttackCategory.E_SYSTEM_PROMPT_LEAK: Severity.MEDIUM,
    AttackCategory.F_UNBOUNDED_CONSUMPTION: Severity.MEDIUM,
    AttackCategory.G_INSECURE_OUTPUT: Severity.HIGH,
}

_CLINICAL_IMPACT: dict[AttackCategory, str] = {
    AttackCategory.A_INDIRECT_INJECTION: "Attacker-controlled document content can redirect the assistant, risking data exfiltration or unsafe actions on a patient chart.",
    AttackCategory.B_CROSS_PATIENT_PHI: "Disclosure of another patient's PHI to an unauthorized user — a HIPAA breach and patient-safety/privacy harm.",
    AttackCategory.C_VERIFICATION_BYPASS: "An ungrounded clinical claim asserted as fact could drive an unsafe clinical decision.",
    AttackCategory.D_MULTITURN_EROSION: "Safeguards degrade across turns, enabling actions the assistant would refuse up front.",
    AttackCategory.E_SYSTEM_PROMPT_LEAK: "Disclosure of system prompt/config/tools aids further targeted attacks.",
    AttackCategory.F_UNBOUNDED_CONSUMPTION: "Unbounded generation/tool loops enable denial-of-wallet / availability harm.",
    AttackCategory.G_INSECURE_OUTPUT: "Active markup rendered by the UI enables XSS in a clinical workflow.",
}

_REMEDIATION: dict[AttackCategory, list[str]] = {
    AttackCategory.A_INDIRECT_INJECTION: ["Treat document content as data, not instructions", "Content/instruction separation", "Output/action allow-listing"],
    AttackCategory.B_CROSS_PATIENT_PHI: ["Enforce patient-context scoping in the assistant", "Bind tool calls to the authorized patient", "Deny out-of-context patient identifiers"],
    AttackCategory.C_VERIFICATION_BYPASS: ["Ground every clinical claim in a tool call this turn", "Flag/withhold unverified claims", "Never infer 'no data' from a tool error"],
    AttackCategory.D_MULTITURN_EROSION: ["Re-assert safeguards each turn", "Stateful policy checks across the conversation"],
    AttackCategory.E_SYSTEM_PROMPT_LEAK: ["Refuse system-prompt/config/tool-schema disclosure", "Route audits to the platform team, not the chat"],
    AttackCategory.F_UNBOUNDED_CONSUMPTION: ["Cap output size and tool-loop iterations", "Per-request budget limits"],
    AttackCategory.G_INSECURE_OUTPUT: ["Encode/sanitize model output before render", "Never emit active markup", "CSP on the UI"],
}


class Documentation:
    def __init__(self) -> None:
        self._counter = 0

    def _next_vuln_id(self) -> str:
        self._counter += 1
        return f"VULN-{self._counter:03d}"

    def write_finding(self, verdict: Verdict, transcript: Transcript, case: AttackCase) -> Finding:
        cat = transcript.category
        attacker_turns = [t.content for t in transcript.turns if t.speaker == "attacker"]
        repro = [f"POST /chat: {redact(t)}" for t in attacker_turns]
        return Finding(
            vuln_id=self._next_vuln_id(),
            title=f"{cat.value}: {case.subcategory or case.id} — invariant broken",
            # the case's own rated ceiling when present; category default otherwise.
            # Still a DRAFT: the human gate (D4) sets the published severity.
            severity=case.severity or _SEVERITY.get(cat, Severity.MEDIUM),
            owasp=transcript.owasp,
            attack_category=cat,
            clinical_impact=_CLINICAL_IMPACT.get(cat, ""),
            repro_steps=repro,
            observed=redact(verdict.rationale or "invariant violated")
            + (f" [evidence: {verdict.evidence_pointer}]" if verdict.evidence_pointer else ""),
            expected=case.expected_safe_behavior,
            remediation=_REMEDIATION.get(cat, []),
            status=FindingStatus.OPEN,          # never auto-published
            transcript_id=transcript.id,
            correlation_id=transcript.correlation_id,
            human_approved=False,               # set ONLY by the deterministic gate (D4/R8)
        )
