# USERS.md — Who the Platform Serves and Why Automation

> Author: Taylor Clements · Updated 2026-09-29

---

## Summary

The adversarial platform exists so that an organization deploying an LLM into a clinical workflow can
**continuously** know whether that system is safe to trust — not once at launch, but on every change,
as attackers adapt. Its users are the people accountable for that trust: the security engineers who
test the system, the platform/ML engineers who ship changes to it, and the clinical-security leadership
(a hospital CISO or equivalent) who must decide whether physicians can rely on it. Each has a distinct
workflow, and each is served by a different part of the platform. Automation is the right solution
because the problem is continuous, adversarial, and larger than any human review cadence can cover by
hand.

---

## Primary users and their workflows

### 1. The AI Security Engineer / Red-Team Operator
**Who:** the person responsible for adversarially testing the Co-Pilot.
**Workflow:** defines seed attack cases and invariants per category; launches campaigns; reviews the
live console as the agents attack, judge, and file findings; approves or rejects findings at the
human-approval gate; converts confirmed exploits into regression tests.
**What they use:** the seed suite, the Red Team + Orchestrator, the live dashboard, the D4 approval
gate, the exploit DB.
**Why automation:** a human cannot manually generate, mutate, and escalate attacks across seven
categories against every deploy. The Red Team autonomously turns a partial success into variants to
find the one that breaks through — the operator sets direction and approves outcomes, rather than
hand-firing every prompt.

### 2. The Platform / ML Engineer (owner of the Co-Pilot)
**Who:** the engineer shipping changes to the target system.
**Workflow (target state):** on each new deploy, the platform re-runs the regression suite (triggered by
the target's version marker); the engineer sees whether a fix actually removed a capability, whether a
previously fixed vulnerability reappeared, and whether fixing one attack introduced a regression
elsewhere. A CI gate blocks a release that reintroduces a confirmed vulnerability.
**Today:** a new operator-stamped target version (`TARGET_VERSION`, or the
`scripts/check_target_version.py` deploy hook) runs the regression suite before any attack and exits
non-zero on a reappeared vulnerability; cross-category regressions between versions are flagged.
The dashboard shows pass rate per target version once versioned campaigns exist; a hosted CI pipeline is not yet built (see ARCHITECTURE.md).
**What they use:** the regression harness, `run_regression.py`, the CI gate, the analytics dashboard
(pass/fail over versions, resilience trend).
**Why automation:** "did this fix actually work, and did it break something else?" cannot be answered
reliably by manual re-testing — LLM behavior drifts run to run. Invariant-scored regression tests
answer it deterministically, on every change, without a human re-running the suite.

### 3. Clinical-Security Leadership (the CISO)
**Who:** the decision-maker who must trust the system with patient safety.
**Workflow:** reviews the coverage map (which categories are tested, how thoroughly), the open/resolved
findings with severities and evidence, the resilience trend over versions, and the professional VULN
reports — each reproducible by an engineer who was not present when it was found.
**What they use:** the analytics dashboard, the VULN reports, this threat model, the AI-use disclosure.
**Why automation:** leadership needs *evidence that the claim is true*, produced continuously and
consistently, not a one-time pen-test that goes stale. The platform provides a standing, measurable
answer to "is this system becoming more or less resilient over time?"

---

## Why automation is the right solution (not a nice-to-have)

Three properties of this problem make manual testing insufficient, and each maps to an automated
component:

1. **It is continuous.** The target changes; attackers adapt; static payload lists go stale. → The
   Orchestrator re-prioritizes and the harness re-runs on every deploy.
2. **It is adversarial and generative.** Defenses built on a few known examples rarely hold as attacks
   mutate. → The Red Team autonomously generates novel inputs and escalates partial successes.
3. **Trust requires reproducible evidence, produced without bias.** A tester who both attacks and
   judges is compromised; a human who re-runs by hand introduces inconsistency. → An independent Judge,
   deterministic anchors, invariant-scored regression, and a human-approval gate produce evidence that
   is consistent, independently verifiable, and honestly bounded.

Automation is bounded deliberately: the platform runs autonomously up to the point of consequence — it
will not mark a finding critical or published without a human at the deterministic approval gate. That
boundary is where the CISO's trust is protected.

---

## What the platform does *not* do

It does not modify the target Co-Pilot (findings recommend remediation; engineers implement it). It
does not auto-publish findings. It does not require a human in the loop for every attack — only at the
approval boundary. These limits are the design, not gaps.
