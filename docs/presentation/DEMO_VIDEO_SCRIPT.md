# Demo video — walk-through script (final submission)

> Target **4:30–5:00** (spec: 3–5 min). Taylor Clements · updated 2026-10-01 (adds OWASP probes + VULN-106, Category F = deferred).
> **Core story:** *"A platform you can trust: it found real gaps, proved a fix live, and refused to call a fix finished when its own check was too easy."*
> Format: the 14-slide deck (`WEEK3_Architecture_Defense.pptx`), with **three live moments** dropped in (dashboard, live replay, regression gate).
> Deck order: 1 title · 2 agent graph · 3–4 decisions · 5 dashboard · 6 results · 7 OWASP · 8 findings · 9–10 evidence · **11 find → fix → prove it** · 12 judge · 13 regression gate · 14 thesis.
> Bullets are talking points, not lines to read.

---

## What the video must show (grading)

- [ ] The platform **running live attacks against the deployed Co-Pilot** (spec) → Beat 3.
- [ ] The **multi-agent design**: 4 agents, an independent Judge, two trust zones, a human gate.
- [ ] The **dashboard**, including the **two target versions**.
- [ ] The **findings + OWASP mapping**, with real transcript evidence.
- [ ] **Regression**: a fix validated live across versions, and the gate blocking a reintroduced vuln.
- [ ] Key decisions + honest limits.

## The five stories (pick your emphasis; 1 and 2 are the headliners)

1. **Find → fix → prove it live (10/01).** The platform reproduced VULN-103 and VULN-105 **3/3** against the deployed Co-Pilot (`8d65b3b`). I shipped a fix (prompt non-disclosure rule + deterministic response filter, MR !20, CI green), deployed `9ffd504`, and the **version change triggered the regression suite by itself**: **0/3** on both.
2. **"A detector pass is a fix candidate, never proof."** I didn't take the 0/3 at face value. Reading the VULN-105 replies: the tool's name, parameters and return codes were gone, but it still explained the allergy gate's three outcomes and rules in plain English. My detector only looked for identifiers. So **VULN-103 is resolved; VULN-105 stays open, partially mitigated**, documented in the report. This is the spec's exact warning: a test that passes because the behavior changed, not because the vulnerability was fixed.
3. **The audit caught my own harness.** My first regression gate re-judged a *stored* transcript, so every target version got the same answer. I rebuilt it to replay the real attacks against whatever is deployed. Same theme: don't trust a green check you haven't tested.
4. **Hardening my own Judge found a real one.** The first campaign's local Judge passed the VULN-105 transcript. Tightening a deterministic rule and re-scanning surfaced it. And the human gate rejected **6 of 6** agent-drafted findings as over-calls, so **0 false findings published**.
5. **Subtle, not flashy.** VULN-101: the Co-Pilot refuses a lookup by name, then forwards any raw patient UUID to its data tool with no check of its own. Nothing leaked only because the snapshot worker is broken (VULN-104), a failure, not a control. That's latent risk a static test list misses.
6. **Covered every OWASP category the PRD names.** Black-box probes (2026-10-01) exercised the classic-web rows too: auth failures → a new finding, **VULN-106** (no logout, non-expiring session cookie, not client-bound); SSRF → a clean **PASS** (the Co-Pilot named the metadata endpoint as "a common SSRF target" and refused); A06/A09 partially probed. Denial-of-wallet (F) is **deferred by choice** — exercising it runs up spend on a live target.

## Say it precisely

| Don't say | Say instead |
|---|---|
| "We fixed both vulnerabilities" | "VULN-103 is fixed and validated live. VULN-105 is partially mitigated and still open." |
| "The regression suite proved the fix" | "The replay went 3/3 → 0/3; a human read decided what that meant." |
| "The Judge runs on a different model" | "The Judge has its own context, rubric and a deterministic pre-filter. Every campaign ran on the same local 8B as the Red Team; the frontier Judge (Haiku 4.5) is validated at 96.7% and is what `live` mode uses." |
| "We use a calibrated classifier" | "It's built and running in **shadow mode**: it records what it would decide and changes nothing. It's NO-GO until it passes a 300-label calibration gate; we have 30." |
| "The Orchestrator learns" | "The Orchestrator is deterministic and finding-aware: it scores coverage gaps, open findings and clinical risk, and every choice is logged with its score table." |
| "We tested injection through document upload" | "Injection payloads were refused when sent inline; the real upload path is the top next coverage item." |
| "VULN-105 is an exploit" | "VULN-105 is a disclosure that maps a safety gate. A bypass was enabled, not demonstrated." |
| "The platform is deployed" | "The target is deployed; the platform is an operator tool that attacks it over HTTP. Its dashboard is operator-only on purpose." |
| "Category F is untested" | "Category F (denial-of-wallet) is **deferred by choice** — running it drives up spend on a live target. It is scoped out with a reason, not missed." |
| "We found and fixed VULN-106" | "VULN-106 (session management) is a probe finding, drafted and awaiting the human D4 gate — not yet an approved, published report." |

## Setup before recording

- [ ] Commit everything first; README/reports may be on screen. **Never show `.env`.**
- [ ] **Terminal 1, dashboard:** `./.venv/bin/python -m uvicorn adv_platform.dashboard.app:app --port 8799` → http://localhost:8799. Check the versions panel shows `8d65b3b` and `9ffd504`.
- [ ] **Terminal 2, live attacks:** start `PYTHONPATH=. ./.venv/bin/python scripts/run_live_campaign.py` a few minutes **before** recording so cards are already arriving (each target turn ~30–50 s).
- [ ] **Terminal 3, live replay:** `PYTHONPATH=. ./.venv/bin/python evals/regression/live_replay.py --live` (~70 s; run once beforehand so the output is in scrollback as a fallback).
- [ ] **Terminal 4, gate:** `evals/run_regression.py` green, then `INJECT_REGRESSION=1 …` red. Both in scrollback.
- [ ] Have open: `reports/VULN-105.md` (Fix validation section) and one VULN-105 reply from today (the "I won't reproduce internal tool names… but here are the three outcomes" reply).
- [ ] Deck full-screen, notifications off.

---

## Beats

**1 · Hook (0:00–0:20) · slide 1**
- An autonomous multi-agent red team that continuously attacks my own clinical Co-Pilot, and proves whether fixes hold.
- Tease the twist: "this week it found real gaps, I fixed one, and the platform proved it on the live system. Then it told me the other fix wasn't done."

**2 · Architecture (0:20–0:55) · slides 2–3**
- Four agents, four jobs: **Orchestrator** decides what to attack, **Red Team** attacks, **Judge** rules, **Documentation** drafts. Plus a human gate no agent can bypass.
- Two zones: the attacker only sees the chat API; the platform knows versions and history, never the target's source.
- Models only where judgment is needed (attack generation, ambiguous verdicts). Orchestrator and Documentation are deterministic on purpose, for explainability.

**3 · Live attacks on the dashboard (0:55–1:40) · slide 5 → dashboard** ★ spec requirement
- Show cards arriving: Orchestrator picked → Red Team sent → target replied → Judge ruled.
- Hover one: PHI-redacted, carries the target's correlation ID → any finding is traceable end-to-end.
- Point at the **versions panel**: two real target versions now.

**4 · Results + findings (1:40–2:20) · slides 6–8**
- 31 attacks in the findings run, 6 of 7 categories exercised across runs, 6 OWASP LLM categories, every case tagged, **$0 platform spend**.
- Five published findings (3 Medium, 2 Low). The target held against direct attacks; the findings are disclosures and defense-in-depth gaps.
- 6 of 6 Judge over-calls rejected at the human gate → 0 false findings.
- OWASP coverage (slide 7): every category the PRD names is exercised or deferred-with-reason. Today's probes added auth failures (→ VULN-106, draft, awaiting the gate), SSRF (a PASS), and A06/A09. F is deferred by choice.

**5 · Evidence (2:20–2:55) · slides 9–10**
- VULN-105: refused the verbatim dump, then gave the allergy tool's name, parameters, return values and rule when reframed as an "example." Read the quote slowly.
- VULN-101 in one line: forwards any UUID, saved only by a broken worker.
- Optional strong moment: the SSRF refusal — *"That address is the cloud instance metadata endpoint (a common SSRF target), and I don't have a tool to make arbitrary HTTP requests…"* The Co-Pilot named the attack itself.

**6 · Find → fix → prove it (2:55–3:55) · slide 11 (before/after) → terminal** ★ CENTERPIECE
- Before: `8d65b3b`, both leak **3/3**.
- The fix: prompt rule + deterministic output filter, MR !20, CI green, deployed `9ffd504`.
- The version change triggered the suite automatically: **0/3** on both.
- **Live:** run `live_replay.py --live` (or show scrollback): VULN-103 `[fixed]` HOLDS.
- **Then the turn:** open the VULN-105 reply. "My detector says it holds. But read it: it still explains the three outcomes. So I documented VULN-105 as partially mitigated, still open. A detector pass is a fix candidate, never proof."

**7 · The Judge (3:55–4:20) · slide 12**
- Layered: deterministic pre-filter → LLM only on ambiguity → human gate.
- Measured on 30 human labels: local 8B over-calls (FAIL precision 0.52); **Haiku 4.5 at 96.7%** for about $0.10 per full pass.
- Calibrated-classifier tier built in shadow mode, NO-GO by design; self-hosted because the transcripts it scores are the ones most likely to contain leaked PHI.

**8 · Regression gate blocking (4:20–4:40) · slide 13 → terminal**
- Green (217 checks), then reintroduce a fixed vuln → red, exit 1, release blocked. Offline, $0.
- Say it: this half proves the scoring logic on a synthetic fixture; live replay is the half that tests real versions.

**9 · Close (4:40–5:00) · slide 14**
- "Found five gaps, fixed one and proved it live, and wouldn't overclaim the second. In healthcare, a security tool that tells you a fix worked when it didn't is worse than no tool."
- Next: real document-upload attacks, finishing VULN-105, and acting on VULN-106 (add a logout + session expiry). Category F stays deferred by choice.

---

## Delivery notes

- **Three moments carry it:** live cards (Beat 3), the before/after plus the VULN-105 human read (Beat 6), the gate going red (Beat 8). Slow down on Beat 6.
- **Honesty is the selling point.** "Partially mitigated" said confidently lands better than "fixed."
- **Running long?** Compress Beat 2 (the diagram carries it) and Beat 5 to VULN-105 only.
- **If the live replay hiccups:** show the scrollback or `evals/regression/results/`; say "here's the run from this afternoon."

## Likely follow-up questions (have one-liners ready)

- *Only two agents use a model; isn't it a pipeline?* Agents are separate responsibility, context and authority; the Orchestrator makes real decisions (score, redirect, halt), deterministically so they're explainable.
- *Why a local uncensored Red Team?* Frontier models refuse offensive work and cost too much at continuous scale.
- *Who approved the reports?* I run `finalize_reports.py`, which routes each report through the D4 gate under my name as the human reviewer and binds the approval to a content fingerprint, so any later edit needs re-approval. (Be ready to say you personally ran that approval step.)
- *Why is VULN-105 still open?* Because the logic is still described in plain language; deciding whether that's acceptable transparency or a leak is a human call, and I documented it rather than closing it.
