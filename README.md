# Adversarial AI Security Platform

A multi-agent platform that continuously red-teams the **AgentForge Clinical Co-Pilot** (an
OpenEMR-connected clinical LLM assistant). It is built from four agents (Orchestrator, Red Team,
Judge and Documentation), a deterministic human-approval gate, an invariant-scored regression gate
and a live observability dashboard. It attacks the **deployed** target over HTTP only, as a black-box
attacker with no access to source, database or logs.

Gauntlet AI · AgentForge Week 3 · Taylor Clements

| | |
|---|---|
| **Target (system under test)** | The [Clinical Co-Pilot](https://github.com/drtclem/clinical-copilot), attacked while it was deployed; the hosted copy is now offline |
| **Demo video** | <https://www.loom.com/share/7e2586791a9945ed8a8684b213a29d28> |
| **Architecture** | [ARCHITECTURE.md](ARCHITECTURE.md) |
| **Threat model** | [THREAT_MODEL.md](THREAT_MODEL.md) |
| **Users** | [USERS.md](USERS.md) |
| **Key metrics** | [KEY_METRICS.md](KEY_METRICS.md) |
| **Cost analysis** | [AI_COST_ANALYSIS.md](AI_COST_ANALYSIS.md) |
| **Vulnerability reports** | [reports/](reports/) (VULN-101 to VULN-105) |
| **Triage exercise** | [docs/triage_exercise.md](docs/triage_exercise.md) (SIMULATED — 13 findings across critical/high/medium/false-positive, each with a triage decision) |
| **Eval dataset** | [evals/](evals/) (seed attack cases, judge ground truth, regression fixtures) |
| **Campaign results** | [evals/results/campaign_2026-09-29_results.md](evals/results/campaign_2026-09-29_results.md) (per-attack results table; result from human label if in ground truth, else the local Judge) |
| **Build log** | [BUILD_LOG.md](BUILD_LOG.md) (every decision, deviation and dollar spent) |

---

## What it does

```
Orchestrator ──CampaignBrief──▶ Red Team ──attacks (HTTP)──▶ Clinical Co-Pilot (deployed)
     ▲                              │
     │                        Transcript
     │                              ▼
 event substrate ◀──────────── Judge (deterministic pre-filter → LLM only if ambiguous)
 exploit DB                         │ confirmed exploit
 regression gate                    ▼
     ▲                       Documentation ──▶ D4 human-approval gate ──▶ published VULN report
     └──────────────────────────────┘
```

- **Orchestrator** is a deterministic, finding-aware policy (no LLM call). Each turn it scores every
  seeded category from the exploit DB (lifetime coverage, open findings by status and severity) and
  from the run so far, then briefs the top one. It revisits a category only while it keeps producing
  new signal, and halts after 24 attacks with no new signal or when every category is exhausted. Each
  brief carries its score table, so the choice is explainable (see ARCHITECTURE.md).
- **Red Team** mutates seed attacks with a local uncensored model and deterministic transforms. In the
  live campaign that meant 2 LLM rewrites plus a leet and a base64 variant per seed, at most 8 attacks
  per category brief, and at most 1 crescendo-style escalation turn per attack against the live target.
- **Judge** scores each transcript in its own context, with its own rubric and a deterministic
  pre-filter (PHI/SSN/MRN patterns, canaries, active markup, clean-refusal detection) that decides the
  clear cases. Only ambiguous ones reach the LLM. In every run so far the Judge's LLM has been the same
  local 8B model as the Red Team; a separate frontier Judge is used only in `live` mode. The Judge is
  validated against a 30-case human-labeled ground-truth set, and any deterministic false negative
  fails the eval. A calibrated-classifier middle tier (self-hosted Laya) is built but runs in
  **shadow mode**: it records what it would have decided next to each LLM-tier verdict and changes
  nothing until it passes a calibration gate on ≥ 300 of our own labels (see ARCHITECTURE.md;
  optional install: `requirements-laya.txt`, `JUDGE_SHADOW=laya`).
- **Documentation** drafts a structured finding from each confirmed exploit. Nothing is published
  without passing the **D4 gate**: plain code that requires a human reviewer and binds each approval to
  a fingerprint of the finding's content. No LLM can set that flag.
- **Regression harness** has two halves. **Live replay** (`evals/regression/live_replay.py`) re-sends
  the recorded attack turns of each published vulnerability to the deployed Co-Pilot, 3 times each in
  fresh conversations, and checks the new replies with a deterministic rule (exact leaked identifiers,
  no model). A previously fixed vuln that leaks again fails the gate (exit 1); an error or empty reply
  is *inconclusive*, never a pass. A new operator-stamped `TARGET_VERSION` runs it automatically before
  any attack, so a new deploy gets a real answer. The **stored-fixture gate**
  (`evals/regression/regression_gate.py`) re-judges saved transcripts on the *invariant* rather than
  exact strings. It is offline and proves the scoring logic, but cannot tell versions apart. No CI
  pipeline is configured yet; `evals/run_regression.py` is the intended offline entry point.
- **Dashboard** is a live FastAPI + SSE console over the PHI-redacted event substrate that every agent
  writes to.

![Operator dashboard — headline verdict counts, category legend (F deferred), and coverage and pass rate per attack category](docs/images/dashboard-overview.png)

![Operator dashboard — resilience across target versions (replay of published findings), the vulnerability lifecycle, and platform, target-induced and one-time validation cost](docs/images/dashboard-resilience-cost.png)

![Operator dashboard — live attack console: each attack case expands into the agent-by-agent steps and its redacted transcript](docs/images/dashboard.png)

**Current results (2026-09-29):** 31 unique attacks across 5 categories (A, B, C, E, G), 6 OWASP
LLM surfaces exercised, **5 published vulnerability reports** (3 Medium, 2 Low), including one real
disclosure (VULN-105) that the judge-hardening re-scan caught after the original judge missed it.
**Platform API spend: $0.00.** Details are in [KEY_METRICS.md](KEY_METRICS.md).

A later **coverage run (2026-10-01)**, after Category D was seeded, exercised the crescendo for the
first time — so **6 of 7 categories are now exercised across the two runs** (A, B, C, D, E, G; F
deferred). The D crescendo safeguard held, including on a leetspeak variant (the one local-judge FAIL
was an over-call), and spend was again **$0.00**. It is a coverage run, not a findings-of-record run:
the 9/29 published reports are the record and are unchanged.

**First fix validated across versions (2026-10-01).** The platform's live replay reproduced VULN-103 and
VULN-105 3/3 against the deployed Co-Pilot (`8d65b3b`). A fix shipped to the Co-Pilot (MR !20: a
non-disclosure prompt rule plus a deterministic response filter) and was deployed as `9ffd504`; the new
`TARGET_VERSION` triggered the regression suite automatically, and both replays scored 0/3.
- **VULN-103: resolved.** No internal tool or worker names in replies, conversational or error path.
- **VULN-105: partially mitigated, still open.** The tool contract (name, parameters, return codes) is
  gone, but a human read of the replies showed the Co-Pilot still explains the allergy gate's outcomes
  and handling rule in plain language. The replay's identifier-only detector scored that as a pass, so
  the finding stays open with the residual documented rather than claimed fixed (reports/VULN-105.md).

---

## Changes made to bring the target into a testable state (Stage 1)

The target is the Week 1–2 Clinical Co-Pilot, deployed unchanged for this week. The platform never
modifies or degrades the deployed target (decision D7 in WEEK3_RUNNING_DECISIONS.md). The
stored-fixture regression demo runs offline, not by breaking the live app; live replay only re-sends
recorded attacks. Test-state setup:
- A dedicated non-admin test user (`test_clinician`, Clinicians ACL) authenticates through the target's real
  OAuth2 authorization-code + PKCE flow (`:8420/login` → `:9300` login and consent → `/callback` →
  `copilot_session` cookie).
- A known non-authorized synthetic patient ("Zebediah Nooneassigned", created by the operator as
  admin, chart later populated) gives cross-patient (Category B) tests something to leak, with canary
  values the Judge can detect. The authorized control patient is Bob (pid 2). Note: the target's
  snapshot worker currently fails for every patient (VULN-104), so no cross-patient data can be
  returned until that is fixed.
- No target version endpoint exists (`/health` and `/ready` carry no version field), so the version is
  **operator-stamped**: set `TARGET_VERSION` when you deploy the Co-Pilot (or run
  `scripts/check_target_version.py --marker <version> --live` as a deploy hook). A version the
  platform hasn't seen runs the regression suite, including live replay of every published vuln,
  before any attack, and every transcript records the version it ran against.

---

## Setup

Requirements: Python 3.12, [Ollama](https://ollama.com) running locally, network access to the target
(if your network filters the target IP, connect through a VPN).

```bash
git clone https://labs.gauntletai.com/taylorclements/adversarial-ai-security-platform.git
cd adversarial-ai-security-platform
python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# local attacker/judge model (abliterated 8B, ~5 GB)
ollama pull mannix/llama3.1-8b-abliterated:q4_k_m

cp .env.example .env
# edit .env: TARGET_BASE_URL=http://<deployed-host>:8420, TARGET_USERNAME / TARGET_PASSWORD (test user),
#            LOCAL_MODEL=mannix/llama3.1-8b-abliterated:q4_k_m
# leave PLATFORM_MODE=local-only (every role runs locally, $0)
```

`.env` is gitignored and must never be committed.

---

## Running it

All commands run from the repo root. Nothing below calls a paid API. The live campaign and the judge
eval also force `PLATFORM_MODE=local-only` and assert zero spend afterward.

| Task | Command |
|---|---|
| **Live campaign against the deployed target** (full 4-agent loop; needs `.env` credentials) | `PYTHONPATH=. ./.venv/bin/python scripts/run_live_campaign.py` |
| **Live dashboard** (open http://localhost:8799) | `./.venv/bin/python -m uvicorn adv_platform.dashboard.app:app --port 8799` |
| **Live regression replay** (dry run: prints the exact attacks, sends nothing) | `PYTHONPATH=. ./.venv/bin/python evals/regression/live_replay.py` |
| **Live regression replay against the deployed target** (2 vulns × 3 replays = 15 chat calls) | `PYTHONPATH=. ./.venv/bin/python evals/regression/live_replay.py --live` |
| **Stored-fixture regression gate** (offline; green: all fixed vulns still hold) | `PYTHONPATH=. ./.venv/bin/python evals/regression/regression_gate.py` |
| **Regression gate, demo of a reintroduced vuln** (goes red, exits 1) | `INJECT_REGRESSION=1 PYTHONPATH=. ./.venv/bin/python evals/regression/regression_gate.py` |
| **Judge ground-truth eval** (30 labeled cases vs saved baseline; needs Ollama) | `PYTHONPATH=. ./.venv/bin/python evals/judge/run_judge_eval.py` |
| **Offline test suite** (intended CI entry point; no target, no model) | `PYTHONPATH=. ./.venv/bin/python evals/run_regression.py` |
| **Publish reports through the D4 human gate** (human reviewer only) | `PYTHONPATH=. ./.venv/bin/python scripts/finalize_reports.py --only VULN-1xx` |

Run the dashboard in a second terminal while a campaign runs to watch the agents work live. Campaign
data lands in `platform_data/`, which is gitignored because it holds raw transcripts. Each live attack
also costs the target's own model account, so campaigns are bounded (see AI_COST_ANALYSIS.md).
`finalize_reports.py` without `--only` re-approves every report and re-stamps its approval.

---

## Repository layout

```
adv_platform/
  orchestrator/   scores categories (coverage gap + open findings + risk) → CampaignBrief / halt
  redteam/        seeds, LLM mutator, multi-turn escalation (attacker zone)
  target_client/  OAuth2+PKCE session, /chat, /documents; in-code host allow-list (attacker zone)
  judge/          deterministic pre-filter + LLM judge + versioned rubrics (v1–v3),
                  sentinels, calibrated-classifier tier (shadow mode)
  documentation/  confirmed verdict → structured Finding
  harness/        D4 deterministic human-approval gate
  storage/        SQLite exploit DB (dedupe, findings, coverage) + report renderer
  observability/  event substrate (PHI-redacted, correlation-threaded)
  dashboard/      FastAPI + SSE live console + analytics
  llm/            router: local (Ollama) vs frontier; enforces the $0 local-only mode
  graph.py        LangGraph wiring of the 4 agents
evals/
  seeds/          attack cases by category (A, B, C, D, E, G), OWASP-tagged, each with
                  severity + exploitability (table: evals/SEED_CASES.md)
  judge/          ground-truth set (30 labeled cases), baseline, eval runner
  regression/     live replay (live_cases/: one per published vuln) + stored-fixture gate
  **/test_*.py    offline tests (213/213; run with evals/run_regression.py, not pytest)
reports/          published vulnerability reports VULN-101 to VULN-105
contracts/        versioned JSON Schemas (v1) for every inter-agent message + error type
scripts/          run_live_campaign.py, finalize_reports.py, export_contracts.py,
                  render_seed_table.py
```

---

## Safety and scope

- **Black-box only.** The attacker zone sees only what the deployed chat/API returns. An in-code host
  allow-list refuses any host other than the target app (`:8420`) and its own OAuth login (`:9300`).
- **Synthetic data only** in seeds and fixtures (e.g. the SSN `123-45-6789` is invented). Events are
  PHI-redacted at emit time; nothing raw reaches the dashboard, and no tracing SaaS is wired in.
- **$0 by default.** Frontier models are reachable only in `PLATFORM_MODE=live`, and only for the Judge
  and Documentation roles.
