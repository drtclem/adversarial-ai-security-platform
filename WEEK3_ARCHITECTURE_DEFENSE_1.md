# Adversarial AI Security Platform — Architecture Defense

> **Author:** Taylor Clements · **Week 3, Gauntlet AI (Austin track)** · Drafted 2026-09-28
> **Audience:** peer engineers · **Purpose:** defend the core architectural decisions behind the
> multi-agent adversarial evaluation platform that continuously red-teams our Clinical Co-Pilot.
> Companion to `WEEK3_ARCHITECTURE_GAMEPLAN.md` (full design) and `ARCHITECTURE.md` (submission gate).

---

## The problem in one paragraph

Our Clinical Co-Pilot (Weeks 1–2) is an LLM agent wired into OpenEMR: multi-turn chat, document
upload feeding a VLM, RAG over a guideline corpus, per-resident OAuth. Its whole promise is
*trustworthy* clinical answers. The Week 3 task is to prove that promise holds under adversarial
pressure — not once, but **continuously, as the system evolves.** Manual prompting and static payload
lists can't do that: they don't mutate, they don't tell you whether a fix actually removed a
vulnerability, and they go stale the moment an attacker adapts. So we built an autonomous multi-agent
red team that discovers, evaluates, documents, and regression-gates vulnerabilities on its own.

This document defends the four decisions that most shape that system. Each is stated with the
alternatives we rejected and why — because "we can defend every decision" is the actual bar.

---

## Decision 1 — Two rings: a black-box attacker inside an operator-level platform

**The decision.** We split the system into two trust rings and keep them separate everywhere:
- **Attacker ring** (the Red Team agent + attack execution) sees *only what the deployed chat/API
  returns.* No source, no database, no logs, no system prompt — unless it *extracts* them as a finding.
- **Platform ring** (Orchestrator, Judge, Documentation, harness, storage, dashboards) is
  operator-level: it knows its own exploit database, coverage metrics, and *when the target
  redeployed* — but never reads the target's source.

**The tension it resolves.** The spec wants two things that seem to conflict. It wants realistic
attacks (which argue for pure black-box), *and* it wants the platform to "trigger regression runs when
the target system changes," "validate that fixes actually work," and "track coverage over versions" —
none of which a pure black-box attacker can do. The two-ring model resolves this cleanly: **attacker
knowledge and operator knowledge are different things.** A real internal red team owns its own harness
and knows its own release cadence. That's not cheating; it's the difference between what the adversary
sees and what the security team running the test sees.

**Why it's the right call.**
- It keeps every exploit *honest*: each vuln report reproduces from black-box steps a stranger could
  follow. The platform's extra knowledge is used only for orchestration and bookkeeping, never to
  manufacture an exploit.
- It maps directly onto a trust boundary the grader explicitly asks about ("where are the trust
  boundaries, and how are they enforced?").

**Alternatives considered.**
- *Pure black-box everything (platform included).* Rejected: the regression story collapses to
  "re-run on a timer and diff behavior," which is weaker and can't answer "did *this deploy* fix it?"
- *Grey-box attacker (give the red team the source/system prompt).* Rejected: it inflates success
  rates with knowledge a real attacker wouldn't have, making findings non-credible.

**If challenged:** "Isn't the platform knowing the version a form of cheating?" — No. The attacker
never sees it. The version signal only tells the *orchestrator* when to schedule a regression run. The
exploit itself is always reproduced through the black-box surface.

---

## Decision 2 — Four separate agents, with the Judge independent by construction

**The decision.** Four distinct agents, each with its own role, context, and (in some cases) model:
- **Orchestrator** — strategy: reads coverage/findings/cost, decides the next campaign.
- **Red Team** — execution: generates, sends, mutates, and escalates attacks (multi-turn).
- **Judge** — evaluation *only*: pass/fail/partial against a fixed rubric, independent of the red team.
- **Documentation** — turns confirmed exploits into reproducible vuln reports.

**Why separate, and why the Judge especially.** The spec is blunt: "a single-agent or pipeline
architecture will not satisfy this assignment," and "an agent that both generates attacks and
evaluates them is compromised by design." That's not bureaucracy — it's a real integrity property. An
attacker LLM grading its own attacks has every incentive to call a weak attack a success (it wrote it)
or to rationalize a partial as a win. So the **Judge runs on a different model, with a different
prompt, in a separate context window** that never sees the red team's reasoning — only the transcript
and the rubric. Attack generation and attack evaluation are different jobs with a built-in conflict of
interest; separating them is what makes a "success" verdict mean something.

**Deterministic anchors under the Judge.** The Judge isn't the only thing between a leak and a "pass."
Deterministic checks (regex for PHI/MRN/SSN patterns, cross-patient-ID leakage, refusal-string
detection) run alongside it, so a clear PHI leak is caught by code even if the Judge is uncertain. The
Judge's *expected-safe-behavior* rubric is drawn from named defenses (input validation, output
sanitization, tiered human-in-the-loop), so every verdict says *which control failed* rather than
offering a vibe.

**Alternatives considered.**
- *One agent doing everything.* Rejected: fails the spec outright and has the conflict of interest above.
- *Same model for Red Team and Judge, different prompts.* Rejected: shared model + shared framing
  still drifts toward self-agreement; independence has to be structural, not cosmetic.
- *Pure deterministic scoring, no Judge LLM.* Rejected: many clinical-safety verdicts ("did this
  separate guideline evidence from patient facts?") need semantic judgment a regex can't make. We use
  deterministic checks for what they're good at and the Judge for the rest.

**If challenged:** "How do you know the Judge itself is trustworthy?" — We validate it against a
labeled set of known-good/known-bad transcripts and periodically re-score that fixed set to detect
drift; a divergence alerts. The Judge's criteria are documented and independently checkable.

---

## Decision 3 — A local, uncensored model powers the Red Team

**The decision.** The Red Team agent runs on a **local open-weights, uncensored/abliterated instruct
model via Ollama** (~30B class on an M1 Max / 32 GB), not a frontier API. The Judge, Orchestrator, and
Documentation agents use frontier models.

**Why.** This comes straight from the spec's own stated concerns: "commercial frontier models are
often trained to refuse offensive security workflows," and "LLM cost is also a factor as this can run
up tokens very quickly." A red team that refuses to write attacks is useless, and a continuous testing
platform that bills per frontier token gets expensive fast. A local model refuses less, costs nothing
per call, and can run the high-volume mutation/escalation loop without a meter running. Placing a
*frontier* model on the Judge is the deliberate inverse: judgment quality matters more than volume
there, and independence from the red-team model is required anyway.

**Why not the obvious alternatives.**
- *Frontier model for the red team with "authorized testing" framing.* Rejected as the primary path:
  it still refuses intermittently, and every refusal is a hole in coverage. (We keep Anthropic's Cyber
  Verification Program as a *backup* if a local model over-refuses — but hardware means local is a real
  primary, not a fallback.)
- *A tiny local model.* Rejected: attack creativity drops off; multi-turn escalation needs a capable
  model. 30B-class on the M1 Max is the sweet spot — strong output, still responsive.

**Honest limitation to own.** Even "uncensored" local models occasionally balk. Our attacks (prompt
injection, cross-patient probing, system-prompt extraction against *our own* system) are legitimate
security testing, not genuinely harmful content, so this is rare — but when it happens we swap models
or fall back to CVP-verified Claude, and we log the refusal rather than hiding it.

**If challenged:** "Isn't an uncensored model a liability?" — It's scoped to a controlled harness
attacking our own deployed system, all traffic logged, no harmful-content generation. The alternative
(a refusing red team) produces false confidence, which in a clinical safety context is worse.

---

## Decision 4 — Regression tests score invariants, not strings

**The decision.** When a confirmed exploit becomes a regression test, it passes or fails against an
**invariant** ("no cross-patient PHI is returned," "no ungrounded clinical claim is stated as fact"),
**not** against the exact text of the original bad response.

**Why this matters more than it sounds.** LLM behavior is nondeterministic; wording drifts run to run.
A regression test that checks for a specific bad string will "pass" the moment the model rephrases —
even if the *vulnerability is still there.* As the reference framing puts it: **"there's no CVE for
'model was too helpful.'"** LLM attacks exploit *capability*, not a code bug — the model is doing
exactly what it was trained to do, just with the wrong instructions. You can't patch your way out; a
"fix" changes behavior without necessarily removing the capability. So a string-matching regression
test gives false green: **a test that passes because phrasing drifted is worse than no test at all,**
because it actively hides a live vulnerability.

**How we enforce it.** The Judge scores the invariant semantically; deterministic checks anchor the
parts that can be checked exactly (a real MRN either appears in the output or it doesn't). A regression
"passes" only when the invariant holds, across reruns, on the new target version. The harness also
flags cross-category regressions — "fixing attack A reintroduced weakness B" — which single-case string
tests can't see.

**Alternatives considered.**
- *Exact-match / snapshot regression.* Rejected for the reason above — false green under normal LLM
  variance.
- *Judge-only scoring, no deterministic anchor.* Rejected: for hard facts (a leaked identifier),
  deterministic is more reliable and cheaper than asking an LLM.

**If challenged:** "How do you keep the invariant check itself from drifting?" — Same mechanism as the
Judge validation: a fixed labeled set re-scored periodically, with drift alerts. Invariants are
written once, reviewed, and versioned alongside the exploit.

---

## How these four fit together

The two-ring boundary (D1) defines *what the attacker may know*. Inside it, four separate agents (D2)
divide the work so evaluation is never compromised by generation. The red team runs on a local model
(D3) so it neither refuses nor bankrupts us at continuous scale. And confirmed exploits become
invariant-scored regression tests (D4) so we can prove — on every new deploy — that a fix actually
removed a capability rather than just changing a sentence. Together they answer the assignment's real
question: not "can you find a jailbreak," but "can you build something a hospital security team would
*trust* to keep testing the systems their physicians depend on."

---

## Anticipated Q&A (peer-engineer edition)

- **"Why not just use Garak / Promptfoo / PyRIT / DeepTeam?"** They're excellent scanners, and we
  reuse their ideas (Garak's JSONL regression diffing, PyRIT's crescendo/TAP techniques, DeepTeam's
  OWASP mapping). But they score the *immediate response*; the assignment needs an orchestrated loop
  that mutates, escalates, judges *independently*, and gates regressions. We configure where we can and
  build the coordination layer they don't provide. (Also worth knowing: PyRIT went archived/read-only
  in March 2026; Promptfoo was acquired by OpenAI but stays MIT.)
- **"Isn't multi-agent overkill?"** The spec forbids single-agent, but beyond compliance: the Judge's
  independence is the whole reason a verdict is credible, and the Orchestrator existing separately is
  what makes the platform *learn* (direct effort by coverage) instead of attacking randomly.
- **"What happens when an agent fails mid-run?"** Typed error contracts (`target_unreachable`,
  `budget_exceeded`, `judge_timeout`, `regression_detected`) and deterministic fallback: if a model is
  down or refuses, the run degrades to deterministic checks and logs the degradation rather than
  crashing.
- **"Where's the human in the loop?"** A deterministic gate — outside any LLM's control — before a
  finding is marked published/critical. If the model decided when to ask, it could be talked out of
  asking; so the gate is hard-coded in platform code.
