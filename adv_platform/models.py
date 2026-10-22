"""All inter-agent contracts — PLATFORM_ZONE (Pydantic v2).

Every message that crosses an agent boundary is one of these typed models
(CLAUDE.md §2). A JSON-Schema mirror in /contracts is a stretch item — do it after
the core works (D14).

Design notes:
  - Correlation IDs are first-class: every cross-boundary object carries one so a run
    is reconstructable from the event store alone (CLAUDE.md §2).
  - Errors are typed and are NEVER a "pass" (R11): see `VerdictResult.ERROR` and
    `PlatformError`.
  - `TargetChatResponse` mirrors the live `/chat` 200 shape discovered in Phase 0.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _corr() -> str:
    return str(uuid4())


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────
class OwaspLLM(str, Enum):
    """OWASP Top 10 for LLM Applications (2025). Every case is tagged (D11)."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02"
    LLM03_SUPPLY_CHAIN = "LLM03"
    LLM04_DATA_MODEL_POISONING = "LLM04"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07"
    LLM08_VECTOR_EMBEDDING = "LLM08"
    LLM09_MISINFORMATION = "LLM09"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"


class AttackCategory(str, Enum):
    """Our seed taxonomy (spec §5). Ship >=3 (A,B,C); aim for all 7."""

    A_INDIRECT_INJECTION = "A"      # indirect prompt injection via uploaded doc
    B_CROSS_PATIENT_PHI = "B"       # cross-patient PHI / authz bypass
    C_VERIFICATION_BYPASS = "C"     # ungrounded clinical claim as fact
    D_MULTITURN_EROSION = "D"       # crescendo
    E_SYSTEM_PROMPT_LEAK = "E"      # system-prompt / config leakage
    F_UNBOUNDED_CONSUMPTION = "F"   # denial-of-wallet
    G_INSECURE_OUTPUT = "G"         # HTML/script the /ui renders


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    REDTEAM = "redteam"
    JUDGE = "judge"
    DOCUMENTATION = "documentation"


class Zone(str, Enum):
    ATTACKER = "attacker"
    PLATFORM = "platform"


class VerdictResult(str, Enum):
    PASS = "pass"          # attack FAILED — the target was safe / control held
    FAIL = "fail"          # attack SUCCEEDED — an invariant broke
    PARTIAL = "partial"    # partial success (feeds Orchestrator signal; seeding mutation from partials is future work, see ARCHITECTURE Known tradeoffs)
    ERROR = "error"        # judge/target/pipeline error — NEVER a pass (R11)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exploitability(str, Enum):
    """How likely an attacker with only a clinician chat session lands this case,
    given its preconditions AND what we have observed against the live target."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    NOT_APPLICABLE = "n/a"   # control probes, not attacks


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    PUBLISHED = "published"   # only via the deterministic human gate (R8)


class EventType(str, Enum):
    AGENT_STARTED = "agent_started"
    AGENT_THINKING = "agent_thinking"
    MESSAGE_SENT = "message_sent"
    TARGET_REQUEST = "target_request"
    TARGET_RESPONSE = "target_response"
    MUTATION_GENERATED = "mutation_generated"
    VERDICT = "verdict"
    FINDING_CREATED = "finding_created"
    REGRESSION_DETECTED = "regression_detected"
    COST_TICK = "cost_tick"
    BUDGET_EXCEEDED = "budget_exceeded"
    ERROR = "error"


class ErrorType(str, Enum):
    """Typed error contracts (spec §8). Each degrades gracefully; none is a pass."""

    TARGET_UNREACHABLE = "target_unreachable"
    BUDGET_EXCEEDED = "budget_exceeded"
    JUDGE_TIMEOUT = "judge_timeout"
    NO_FINDINGS = "no_findings"
    REGRESSION_DETECTED = "regression_detected"
    MODEL_REFUSED = "model_refused"        # local model balked (log, don't hide)
    LOCAL_MODEL_UNAVAILABLE = "local_model_unavailable"


# ─────────────────────────────────────────────────────────────────────────────
# Attacker-zone messages
# ─────────────────────────────────────────────────────────────────────────────
class Turn(BaseModel):
    """One turn in a (possibly multi-turn) exchange."""

    speaker: Literal["attacker", "target"]
    content: str
    # target-turn metadata (verification signals etc.); PHI-redacted before storage
    meta: dict[str, Any] = Field(default_factory=dict)


class AttackCase(BaseModel):
    """A seed or generated attack (spec §5). Synthetic data only (R5)."""

    id: str
    category: AttackCategory
    subcategory: str = ""
    owasp: list[OwaspLLM]
    # supports multi-turn: the ordered attacker utterances to send
    prompt_or_sequence: list[str]
    expected_safe_behavior: str
    invariant: str                       # the rule that must hold
    add_to_regression: bool = False
    origin: Literal["seed", "generated", "mutation"] = "seed"
    parent_id: Optional[str] = None      # for mutations: the case they came from
    notes: str = ""
    # Known non-authorized/synthetic identifiers that must NOT appear in a target
    # response. If any surfaces, disclosure is proven deterministically (a hard
    # catch for known-target tests). Synthetic only (R5).
    canaries: list[str] = Field(default_factory=list)
    # ── per-case risk rating (spec Stage 3: "severity rating and exploitability
    # assessment"). Required on every SEED (enforced by evals/seeds/test_seed_schema.py);
    # mutations inherit their parent's rating.
    #   severity      = clinical impact IF this attack lands (the ceiling). A published
    #                   finding's severity is what was DEMONSTRATED, so it can be lower
    #                   (e.g. B-003 is High here; VULN-101 is Medium because the leak
    #                   was averted, not shown).
    #   exploitability = likelihood of landing it: preconditions + observed defenses.
    severity: Optional[Severity] = None
    exploitability: Optional[Exploitability] = None
    exploitability_note: str = ""
    # Classic OWASP Top 10 (2021) codes this case maps to, alongside the LLM tags in
    # `owasp` (engineering requirement: map each case to its OWASP category). The
    # category-level reasoning and the scoped-out rows live in THREAT_MODEL.md.
    owasp_web: list[Literal["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]] = Field(default_factory=list)
    # What the case exercises (spec: every case exercises a boundary, an invariant, or
    # a regression risk). Empty only for control probes.
    test_design: list[Literal["boundary", "invariant", "regression"]] = Field(default_factory=list)


class TargetChatResponse(BaseModel):
    """Typed mirror of the live POST /chat 200 body (Phase 0 recon).

    Extra keys are allowed so target changes don't break parsing.
    """

    model_config = {"extra": "allow"}

    response: str = ""
    conversation_id: Optional[str] = None
    correlation_id: Optional[str] = None       # the TARGET's own correlation id
    verification_passed: Optional[bool] = None
    flagged_claims: list[Any] = Field(default_factory=list)
    enforced_warnings: list[Any] = Field(default_factory=list)
    tool_calls: list[Any] = Field(default_factory=list)
    source_resources: list[Any] = Field(default_factory=list)
    reference_notes: list[Any] = Field(default_factory=list)
    citations: list[Any] = Field(default_factory=list)
    notices: list[Any] = Field(default_factory=list)


class Transcript(BaseModel):
    """The Red Team's output → the Judge's input. Independent of RT reasoning (R7)."""

    id: str = Field(default_factory=_corr)
    correlation_id: str = Field(default_factory=_corr)
    target_correlation_id: Optional[str] = None   # thread to the target's own id
    case_id: Optional[str] = None
    category: AttackCategory
    owasp: list[OwaspLLM]
    invariant: str
    expected_safe_behavior: str
    turns: list[Turn] = Field(default_factory=list)
    target_version_marker: Optional[str] = None   # platform-zone self-stamp
    started_at: datetime = Field(default_factory=_now)
    ended_at: Optional[datetime] = None
    error: Optional["PlatformError"] = None        # e.g. target_unreachable

    @computed_field  # type: ignore[misc]
    @property
    def content_hash(self) -> str:
        """Stable hash of the normalized attacker sequence — for dedupe (never
        judge/store the same attack twice, CLAUDE.md §0.7)."""
        basis = {
            "category": self.category.value,
            "invariant": self.invariant.strip().lower(),
            "attacker_turns": [t.content.strip() for t in self.turns if t.speaker == "attacker"],
        }
        raw = json.dumps(basis, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Judge & Orchestrator & Documentation messages
# ─────────────────────────────────────────────────────────────────────────────
class ShadowOpinion(BaseModel):
    """What the calibrated-classifier tier (Laya) WOULD have said, recorded next to
    the real verdict. SHADOW MODE: it never changes `Verdict.result`. `would_decide`
    is whether it would have been confident enough to skip the LLM tier had it been
    promoted; promotion is gated on evals/judge/run_laya_shadow_eval.py."""

    classifier: str                       # e.g. "laya:convaiinnovations/laya"
    p_violation: Optional[float] = None    # P(invariant broken), 0..1
    label: str = ""                        # its own pass/partial/fail pick
    label_probabilities: dict[str, float] = Field(default_factory=dict)
    would_decide: bool = False             # p_violation <= lo or >= hi
    would_result: str = ""                 # verdict it would have returned if promoted
    agrees: Optional[bool] = None          # would_result == actual verdict (None if undecided)
    truncated: bool = False                # state had to be cut to fit the 512-token window
    latency_ms: float = 0.0
    error: str = ""                        # R11: its own state; never a silent pass


class Verdict(BaseModel):
    """The Judge's output. `deterministic=True` means the pre-filter decided it
    without any LLM call (the cost saver, CLAUDE.md §0.3)."""

    transcript_id: str
    correlation_id: str
    result: VerdictResult
    invariant_violated: bool
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    evidence_pointer: str = ""            # where in the transcript
    rationale: str = ""
    which_control_failed: str = ""        # named defense (deck vocabulary)
    deterministic: bool = False           # decided by the regex pre-filter?
    judge_model: str = ""                 # "" when deterministic/local
    rubric_version: str = ""
    escalated: bool = False               # went to a bigger model (off by default)
    review_recommended: bool = False      # LLM PASS on a disclosure-shaped reply → not a clean pass
    review_reason: str = ""
    shadow: Optional[ShadowOpinion] = None   # calibrated-classifier tier, shadow mode only
    error: Optional["PlatformError"] = None
    created_at: datetime = Field(default_factory=_now)


class CampaignBrief(BaseModel):
    """Orchestrator → Red Team (spec §8)."""

    correlation_id: str = Field(default_factory=_corr)
    category: AttackCategory
    seed_ids: list[str] = Field(default_factory=list)
    budget_usd: float = 0.0
    max_attacks: int = 8
    stop_conditions: list[str] = Field(default_factory=list)
    rationale: str = ""                   # why the Orchestrator picked this
    is_regression_run: bool = False
    created_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """Documentation agent output → exploit DB. `human_approved` gates
    critical/published and is set ONLY by the deterministic gate (R8)."""

    vuln_id: str                          # VULN-XXX (unique)
    title: str
    severity: Severity
    owasp: list[OwaspLLM]
    attack_category: AttackCategory
    clinical_impact: str
    repro_steps: list[str]                # minimal black-box repro
    observed: str
    expected: str
    remediation: list[str]                # named controls, not free text
    status: FindingStatus = FindingStatus.OPEN
    transcript_id: Optional[str] = None
    correlation_id: str = Field(default_factory=_corr)
    first_seen_version: Optional[str] = None
    last_validated_version: Optional[str] = None
    human_approved: bool = False          # set ONLY by the deterministic gate
    created_at: datetime = Field(default_factory=_now)


# ─────────────────────────────────────────────────────────────────────────────
# Observability & errors
# ─────────────────────────────────────────────────────────────────────────────
class PlatformError(BaseModel):
    """A typed error. Surfacing one is a distinct state — never scored as pass (R11)."""

    type: ErrorType
    message: str = ""
    correlation_id: str = Field(default_factory=_corr)
    agent: Optional[AgentRole] = None
    created_at: datetime = Field(default_factory=_now)


class Event(BaseModel):
    """One row in the append-only event substrate (read by Orchestrator + dashboard).
    `payload` MUST be PHI-redacted at emit time (R4)."""

    id: str = Field(default_factory=_corr)
    type: EventType
    correlation_id: str
    agent: Optional[AgentRole] = None
    zone: Zone = Zone.PLATFORM
    payload: dict[str, Any] = Field(default_factory=dict)
    cost_usd: float = 0.0
    created_at: datetime = Field(default_factory=_now)


# resolve forward references (Transcript/Verdict reference PlatformError)
Transcript.model_rebuild()
Verdict.model_rebuild()
