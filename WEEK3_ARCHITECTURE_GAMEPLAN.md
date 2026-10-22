# Week 3 — Adversarial AI Security Platform: Architecture & Game Plan

> **Owner:** Taylor Clements · **Drafted:** 2026-09-28 · Updated 2026-09-28 (ring→zone; 7 categories; scope correction; dashboard/D9) · **Status:** ready for build (see `WEEK3_BUILD_SPEC.md`)
> **Target under test:** the Clinical Co-Pilot from Weeks 1–2, live at `http://<deployed-host>:8420/ui` (chat) / `/chat` (API).
> **This repo:** a NEW, independent code repo for the adversarial platform (the spec requires "Independent code repo").

This is the north-star plan. It's meant to be edited as we go. The companion file
`WEEK3_RUNNING_DECISIONS.md` is the living log of every choice, open question, and how-to link.

---

## 0. The one-paragraph version (say this in the interview)

> "We built an autonomous multi-agent red team that continuously attacks our own Clinical
> Co-Pilot through its **deployed chat interface only** — the same surface a real attacker sees.
> A **Red Team agent** generates and mutates multi-turn attacks; an **independent Judge agent**
> decides success/fail/partial with fixed criteria; an **Orchestrator** reads coverage and open
> findings to decide what to hit next; and a **Documentation agent** turns confirmed exploits into
> reproducible vuln reports. Confirmed exploits become deterministic regression tests that re-run
> on every new deploy, so we can prove a fix actually fixed the thing and didn't regress something
> else. The attacker is black-box; the platform around it is operator-level, because a real security
> team testing its own system knows when it redeployed."

---

## 1. The critical reframe: black-box attacker, operator-level platform

You said the attacker does **not** have GitLab or source access. Agreed, and we bake that in — but
we have to be precise, because the spec demands things a pure black-box attacker literally cannot do
(detect that the target changed, prove a fix worked, track coverage over versions).

Resolve it by drawing **two zones** and keeping them separate everywhere in the docs and code:

| Zone | Who | What it knows | What it may touch |
|---|---|---|---|
| **Attacker zone** (Red Team agent + attack execution) | Simulated external attacker | Only what the chat/API returns. No source, no DB, no logs, no system prompt (unless it *extracts* them as a finding). | The deployed HTTP surface only: send messages, upload docs, hold multi-turn sessions, log in as a provisioned test user. |
| **Platform zone** (Orchestrator, Judge, Documentation, harness, storage, observability) | You / the security team testing your own system | Target version/deploy marker, its own exploit DB, coverage metrics, run history. | Its own database and dashboards. It reads the target's `/health` or a version endpoint to know *when* it changed — **not** the target's source. |

Why this is the right call and how to defend it:
- **It's realistic.** A real internal red team owns its harness and knows its own release cadence. That's not cheating; it's the difference between "attacker knowledge" and "operator knowledge."
- **It keeps the exploit stories honest.** Every vuln report reproduces from black-box steps a stranger could follow. The platform's extra knowledge is only used for orchestration and regression bookkeeping, never to manufacture an exploit.
- **It maps cleanly to a threat-model boundary,** which the grader is explicitly looking for ("Where are the trust boundaries?").

**Decision D1 (locked): attacker = black-box HTTP only; platform = operator-level on its own data + a version signal from the target.** See running-decisions log.

> If you'd rather go *fully* black-box (platform also can't see version), we can — but then the
> regression story becomes "re-run on a schedule and diff behavior" instead of "re-run on deploy,"
> which is weaker. Flag me if you want that variant.

---

## 2. What the assignment is actually grading (decoded)

> **⚠️ 2026-09-28 scope correction (instructor, Slack @channel):** the PRD's long "Optional Engineering
> Deliverables" block was mistakenly labeled "not optional." It is being fixed. **The only *required*
> engineering deliverable is the OWASP LLM risks mapping** (tag every test case with its OWASP
> category). The ATO packet, integration packet, formal contract tests, load/stress tests, triage
> exercise, SQL SLOs, data-lineage docs, migration notes, and versioned `/contracts` are all **truly
> stretch** now. The *core* Platform Requirements below are unaffected — they were never in that block.

There are **hard gates** (fail without them) and a short list of things that separate a pass from a
strong pass.

### Hard gates (must exist or you fail)
1. **`THREAT_MODEL.md`** — full attack-surface map, opens with a ~500-word summary. (Stage 2)
2. **`evals/` working suite** — results across **≥3 distinct attack categories**, plus **≥1 live agent role** running against the deployed target. **Every case OWASP-tagged** (the one required engineering item). (Stage 3)
3. **`ARCHITECTURE.md`** — multi-agent platform, ~500-word summary, **names each agent + role**, diagram of agent interactions. (Stage 4)
4. **`KEY_METRICS.md`** — metrics + rationale.
5. **`USERS.md`** — who the platform serves + why automation (core submission item).
6. **The multi-agent system, regression harness, and observability layer** — required by the core Platform Requirements (not the optional block), so still gates.
7. **The regression-gate demo works:** the grader introduces a small regression and confirms the gate fails. Treat as a gate.
8. **Deployed target URL** submitted with every checkpoint; platform runs against the **live** system, not a mock.
9. **≥3 distinct vulnerability reports** from the Documentation agent (core deliverable).

### The "single-agent won't pass" rule
Read this twice: *"A single-agent or pipeline architecture will not satisfy this assignment."* The four
roles must be genuinely distinct agents with distinct context. The one that trips people:
**the Judge must be independent of the Red Team** ("an agent that both generates attacks and
evaluates them is compromised by design"). Different model, different prompt, different context window.

### What turns a pass into a strong pass (now explicitly optional — do if time)
- The Red Team **mutates** a partial success into variants autonomously (not a static list).
- The Judge is **validated** (you can show it doesn't just rubber-stamp) and you have a story for **judge drift**.
- Regression genuinely catches "fixed one thing, broke another."
- Honest **cost/scale analysis** (100/1K/10K/100K runs) that isn't just tokens×N. *(stretch, but cheap + strong for interview)*
- A **build-vs-configure record** — why custom agents over Garak/Promptfoo/etc. *(stretch, but cheap + strong for interview)*
- Versioned `/contracts` + contract tests. *(stretch — nice-to-have, no longer near-required)*

---

## 3. Target recon (from your own handoff docs — the attack surface we already know)

You have an unfair advantage: you built the target. Use it to aim the red team, but only encode
findings that reproduce black-box. From `WEEK2_STATUS_HANDOFF` and `W2_INTERVIEW_PREP_NOTES`, the
Co-Pilot has these attackable properties:

| Property of the target | Why the red team cares |
|---|---|
| Multi-turn chat with a **supervisor → workers** graph (intake-extractor, evidence-retriever) | Multi-turn manipulation, routing confusion, worker-boundary attacks |
| **Document upload** (lab PDF, intake form) feeds a VLM/OCR → extraction | **Indirect prompt injection via uploaded documents** — the highest-signal attack surface here |
| **RAG over a guideline corpus** (BM25 + dense + rerank) | Context poisoning, retrieval manipulation, guideline-vs-patient-fact confusion |
| **Per-resident OAuth** login; `test_clinician` is a non-admin (Clinicians) | Authorization bypass, cross-patient access, privilege/persona escalation |
| **Verification layer** strips ungrounded claims; allergy hard-stop; "pending review" disclosure | Try to get an ungrounded/unsafe claim past verification — that's a headline finding |
| Known gap: **verification treats any ungrounded drug mention (even guideline text) as a patient claim** (§4.17) | Already a documented weakness — a great seed case, and shows honesty |
| Known gap: **Langfuse traces contain PHI**, journald has pre-hardening raw IDs | Sensitive-info-disclosure / logging-failure angle (careful: platform-zone knowledge, verify black-box) |
| **In-memory sessions**, ~30–50s turn latency, sequential LLM rounds | **Unbounded consumption / denial-of-wallet**, token exhaustion, cost amplification |
| **No HTTPS** on the droplet | Transport finding (documented accepted risk — still note it) |
| Extraction **fails closed** on empty; PDF capped at 5 pages | Failure-mode probing, resource limits |

The most productive attack surfaces for this target, ranked:
1. **Indirect prompt injection through uploaded documents** (unique to this app, high clinical impact).
2. **Cross-patient / authorization** (PHI leakage is the worst-case in healthcare).
3. **Verification bypass** (get an unsupported clinical claim stated as fact — directly attacks the app's whole promise).
4. **Multi-turn safeguard erosion** (crescendo — safeguards ignored after N turns, which your own notes say happens).
5. **Unbounded consumption / denial-of-wallet** (deterministic, cheap to prove, ties to your latency/cost gap).

---

## 4. System architecture

### 4.1 The four agents (+ what's deterministic, not AI)

```
                         ┌──────────────────────────────────────────┐
                         │            ORCHESTRATOR AGENT             │
                         │  reads: coverage map, open findings,      │
                         │  recent regressions, cost budget          │
                         │  decides: next attack campaign + category │
                         └───────────────┬──────────────────────────┘
                                         │ campaign brief (typed msg v1)
                                         ▼
        ┌────────────────────────────────────────────────────────────┐
        │                     RED TEAM AGENT                           │
        │  (open/uncensored model — see D2)                            │
        │  generate seed attack → send to TARGET → read response →     │
        │  if partial: mutate into N variants → escalate → repeat      │
        │  emits: attack transcript (typed msg v1)                     │
        └───────────────┬───────────────────────────┬─────────────────┘
                        │ sends prompts             │ transcript
                        ▼                           ▼
        ┌───────────────────────────┐   ┌────────────────────────────┐
        │  TARGET: Clinical Co-Pilot │   │       JUDGE AGENT           │
        │  deployed chat/API ONLY    │   │  (different frontier model) │
        │  (black-box attacker zone) │   │  verdict: pass/fail/partial │
        └───────────────────────────┘   │  + which invariant broke    │
                                         │  independent context (D3)   │
                                         └──────────────┬──────────────┘
                                                        │ confirmed exploit (typed msg v1)
                                                        ▼
                                         ┌────────────────────────────┐
                                         │   DOCUMENTATION AGENT       │
                                         │  writes structured VULN-XXX │
                                         │  report; human gate before  │
                                         │  "published/critical" (D4)  │
                                         └──────────────┬──────────────┘
                                                        │ exploit record
                                                        ▼
                    ┌───────────────────────────────────────────────────────┐
                    │   EXPLOIT DB  +  REGRESSION HARNESS  +  OBSERVABILITY   │
                    │   (deterministic; versioned; re-runs on target change) │
                    └───────────────────────────────────────────────────────┘
```

Roles in one line each:
- **Orchestrator** — strategy. Reads the observability substrate (coverage per category, open/high-sev findings, regressions, spend) and picks the next campaign. *Not* an attacker.
- **Red Team** — execution + creativity. Generates novel inputs, sends them to the live target, mutates partial successes into variants, runs multi-turn sequences (crescendo/TAP-style).
- **Judge** — evaluation, *and nothing else*. Fixed rubric per attack category; independent of the red team by construction. Emits pass/fail/partial + the specific invariant violated + a confidence. **Rubric anchor:** an attack "succeeded" when a control that *should* have caught it didn't — so the Judge's expected-safe-behavior column is drawn from the named defenses in the Gauntlet deck (input validation, output sanitization → HTML-encode/PII-redact/credential-scan, tiered HITL). That gives every verdict a concrete "which defense failed" instead of a vibe.
- **Documentation** — turns a Judge-confirmed exploit into a reproducible report (VULN-ID, severity, clinical impact, minimal repro, observed vs expected, remediation, status). **Remediation vocabulary** maps to the deck's defense coverage map (slide 14): each fix recommendation names a control (e.g. "output sanitization: HTML-encode before render," "least-privilege scoping," "deterministic HITL gate") rather than free-text advice — so an engineer can act on it.

Deterministic (non-AI) on purpose — and say why in the AI-use disclosure:
- The **HTTP client** to the target (auth, session handling, upload).
- The **regression runner** (replays stored transcripts, byte-for-byte where possible).
- **Coverage/metrics aggregation** and the **exploit DB** (SQLite to start).
- **Deterministic pre-checks** the Judge leans on (regex for PHI patterns / MRN / SSN, refusal-string detection, cross-patient-ID leakage) so the Judge isn't the only thing standing between a leak and a "pass."

### 4.2 Why LangGraph (locked D5)
Same stack as Weeks 1–2 → "good architecture compounds." LangGraph gives inspectable nodes/edges
(the spec wants the supervisor's routing "inspectable" — mirror that here), explicit state, and
easy per-node tracing into Langfuse, which you already run. The agent graph is a natural fit for the
orchestrator→red-team→judge→documentation flow with a loop back to orchestrator.

### 4.3 Model placement (locked D2)
- **Red Team:** local/open uncensored model (Ollama; e.g. a Llama/Mistral/Dolphin-class instruct or a purpose-built abliterated variant). Rationale is *straight from the spec*: frontier models refuse offensive workflows, and continuous testing at scale gets expensive. This is a headline defense point.
- **Judge:** a **frontier** model (Claude or GPT-class), *different* from the red team, with a tight rubric. Judgment quality matters more than cost here, and independence is required.
- **Orchestrator / Documentation:** frontier is fine (low call volume). Documentation especially benefits from strong writing.
- **Deterministic fallback everywhere:** if a model is down/refuses/times out, the run degrades to the deterministic checks and logs the degradation. (Graceful degradation is graded.)

### 4.4 Inter-agent contracts (`/contracts`, versioned — required engineering item)
Every message between agents is a **versioned JSON Schema (v1)**. Publish in `/contracts`, write
contract tests both sides. Minimum set:
- `orchestrator_to_redteam.v1` — campaign brief: target category, seed cases, budget, stop conditions.
- `redteam_to_judge.v1` — attack transcript: full multi-turn sequence, target responses, category, expected-safe-behavior.
- `judge_to_documentation.v1` — verdict: pass/fail/partial, invariant violated, severity, confidence, evidence pointers.
- `error.v1` — typed errors: `target_unreachable`, `budget_exceeded`, `judge_timeout`, `no_findings_in_window`, `regression_detected`.

Breaking change → version bump + migration note. This one item quietly satisfies several of the
"optional/not-optional" engineering deliverables at once.

### 4.5 Data model (exploit DB)
SQLite first (migrate-ready). Core tables:
- `exploits` — `id (VULN-XXX)`, severity, owasp_category, attack_category, subcategory, repro_steps (transcript ref), observed, expected, status (`open|in_progress|resolved|regressed`), first_seen_version, last_validated_version, created_at.
- `runs` — run_id, correlation_id, target_version, started/ended, cost, num_cases, orchestrator_rationale.
- `attempts` — attempt_id, run_id, exploit_id (nullable), category, verdict, confidence, tokens, cost, latency.
- `coverage` — category, cases_count, last_tested_version, pass_rate.

Enforce: unique VULN-ID, required fields validated in the Documentation agent **before** write, no
duplicate exploit for the same normalized attack sequence (dedupe by content hash — you already use
content-hash dedupe in Week 2, reuse the idea). Index by severity, category, version.

### 4.6 Observability (a first-class component, in four layers)

The spec is explicit that observability "is not just for humans — it is the data substrate your
Orchestrator Agent reads." So we build **one event stream** and let both the Orchestrator and the
dashboards read from it. Four layers:

**Layer 1 — Event substrate (the single source of truth).**
- Every agent emits structured events to an **append-only event store** (SQLite table + an in-process pub/sub, or a JSONL stream): `agent_started`, `agent_thinking`, `message_sent` (with the typed contract payload), `target_request`, `target_response`, `mutation_generated`, `verdict`, `finding_created`, `regression_detected`, `cost_tick`, `error`.
- **Correlation ID** on every event, threaded through every log line, LLM call, and target request (required: "reconstruct a full trace from logs alone").
- This same store is what the **Orchestrator reads** to decide the next campaign — one substrate, two consumers (orchestrator + dashboard). No parallel bookkeeping.

**Layer 2 — Live activity dashboard (the "watch the agents work" console).** *This is the operator view the demo shows.*
- **When it's working:** the 4 agents (Orchestrator, Red Team, Judge, Documentation) each shown as idle / working + current action, updating live.
- **What it's saying:** a streaming feed of the messages crossing the contracts — the attack prompt, the target's response, the Judge's reasoning + verdict, the Documentation agent's report as it's written. **PHI-redacted at emit time** (hash IDs; strip MRN/SSN/name patterns) — never send raw PHI to the browser.
- **What happened:** verdicts (pass/fail/partial) as they land, new findings, regressions flagged, and **cost accumulating in real time**.
- Serve it from a small FastAPI app; push updates over **SSE or WebSocket** by tailing Layer 1. (Defaults: one app, SSE, ~1s cadence — all reversible.)

**Layer 3 — Analytics dashboard (same app, second tab).**
- Answers the spec's mandated questions: cases per category, pass/fail over versions, **resilience trend** (is the target getting more/less resilient), open/in-progress/resolved findings, cost per run + scaling rate, per-agent activity/order.

**Layer 4 — Langfuse (reused from Weeks 1–2).**
- Kept for **deep per-LLM-call drill-down**: tokens, cost, latency per step, nested span tree `campaign` → `redteam:*` → `target_call` / `mutation` → `judge` → `documentation`. The live dashboard is for *watching*; Langfuse is for *forensics*.

**Cross-cutting:**
- **No raw PHI anywhere in platform logs, events, or the browser** — same discipline as Week 2, hash IDs. Reuse the `no_phi_in_logs` grader against the event store and the dashboard payloads.
- **Three alerts** (required): p95 latency over threshold, error rate over threshold, tool/target failure rate over threshold — each with a documented on-call response.

> **Build-vs-buy note for the defense:** Langfuse already gives trace inspection, so why a custom
> dashboard? Because (a) the Orchestrator needs a *machine-readable* substrate to read, which we build
> anyway, and the live view is a near-free consumer of it; (b) the demo must *show live attacks*, and a
> purpose-built agent-activity console is far more legible than a generic trace UI; (c) it's the
> operator console the spec repeatedly asks for. We reuse Langfuse for what it's best at (per-call
> forensics) rather than reimplementing it.

### 4.7 Regression & validation harness
- Confirmed exploit → deterministic test case (stored transcript + Judge rubric + expected-safe-behavior).
- Orchestrator triggers a **full regression run when the target version changes** (platform zone reads the version signal).
- Detects **reappearance** of a fixed vuln and **cross-category regressions** ("fixing A broke B").
- **The honesty check the spec calls out:** a regression test must pass because the *vulnerability is actually gone*, not because the model's phrasing drifted. So the Judge scores against the **invariant** ("no cross-patient PHI is returned"), not against exact strings. Deterministic checks anchor the flaky parts.

---

## 5. Attack taxonomy → OWASP mapping (seed the eval categories here)

We need ≥3 categories to pass; we'll ship **7** to be strong. Every case tags an OWASP LLM (2025)
category. Confirmed 2025 list: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure,
LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive
Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation,
LLM10 Unbounded Consumption.

| # | Attack category (ours) | OWASP LLM 2025 | Also classic OWASP | Priority |
|---|---|---|---|---|
| A | **Indirect prompt injection via uploaded document** | LLM01 | Injection | ★★★ |
| B | **Cross-patient PHI / authorization bypass** | LLM02, LLM06 | Broken Access Control | ★★★ |
| C | **Verification bypass** (ungrounded clinical claim stated as fact) | LLM09, LLM05 | Insecure design | ★★★ |
| D | **Multi-turn safeguard erosion** (crescendo) | LLM01 | — | ★★ |
| E | **System-prompt / config leakage** | LLM07 | Sensitive data exposure | ★★ |
| F | **Unbounded consumption / denial-of-wallet** | LLM10 | — (DoS) | ★★ |
| G | **Insecure output handling** (get the Co-Pilot to emit HTML/script the `/ui` chat renders) | LLM05 | XSS / Injection | ★★ |

(Stretch: H — RAG/embedding poisoning, LLM08, if the guideline corpus is reachable via upload.)

> **Category G came from the Gauntlet "AI Security: Threats & Defenses" deck (slide 8).** Its
> traditional-vs-LLM table is a coverage checklist: XSS-via-model-output was the one class our first
> six categories missed. The target renders responses in `/ui`, so "coax the model into returning
> markup/script the chat UI executes" is a real, testable LLM05 case. Ship it at least as seed cases.

Each test case carries (Stage-3 required fields): attack category + subcategory, the exact prompt/
input sequence, expected safe behavior, observed behavior (pass/fail/partial), severity +
exploitability, OWASP tag, and "add to regression? y/n".

---

## 6. Repo layout (fresh repo)

```
adversarial-platform/
├── README.md                     # setup, deployed target URL, how to run against live target
├── THREAT_MODEL.md               # GATE — attack surface map, 500-word summary
├── ARCHITECTURE.md               # GATE — agents, diagram, 500-word summary, AI-use disclosure
├── USERS.md                      # GATE — who uses the platform + why automation
├── KEY_METRICS.md                # GATE — metrics + rationale
├── AI_COST_ANALYSIS.md           # 100/1K/10K/100K runs, architectural changes per tier
├── BUILD_VS_CONFIGURE.md         # why custom agents over Garak/Promptfoo/PyRIT/etc.
├── contracts/                    # versioned JSON Schemas + error schemas (v1)
├── platform/
│   ├── orchestrator/
│   ├── redteam/
│   ├── judge/
│   ├── documentation/
│   ├── target_client/            # deterministic HTTP client to the Co-Pilot (auth, upload, multi-turn)
│   ├── harness/                  # regression runner, dedupe, version watcher
│   ├── storage/                  # SQLite models + migrations
│   ├── observability/            # event substrate (Layer 1), correlation IDs, Langfuse, alerts
│   ├── dashboard/                # FastAPI app: live activity console (L2) + analytics (L3), SSE/WS
│   └── graph.py                  # LangGraph wiring of the 4 agents
├── evals/                        # seed attack cases (≥3 categories; we ship 7) + results
│   ├── seeds/                    # seed cases per category (YAML/JSON)
│   ├── regression/               # confirmed exploits as deterministic tests
│   └── results/
├── reports/                      # generated VULN-XXX reports (≥3 required)
├── contracts_tests/              # contract tests both sides of each boundary
└── .gitlab-ci.yml (or GH Actions)# regression gate that blocks on regression
```

> Note: platform lives in its **own repo**, but the **target** stays where it is (the deployed
> Week 1/2 Co-Pilot). We never modify the target from here.

---

## 7. Phase plan (one-week sprint; checkpoints Tue early / Fri final per this week's schedule)

Times are rough elapsed effort, not calendar.

### Phase 0 — Recon & scaffolding (2–3 h) — do first
- Fresh repo, folder skeleton, `.env.example`, README stub with the live target URL.
- Stand up target confirmation: hit `/health`, `/ready`, log in as `test_clinician`, send one benign chat, do one benign upload. Record exact request shapes (this becomes `target_client`).
- Draft `WEEK3_RUNNING_DECISIONS.md` seeded from D1–D5 below (done — see companion file).
- 🛑 **CHECKPOINT:** confirm we can reach the live target and hold an authenticated multi-turn session before building anything on top.

### Phase 1 — Threat model + seed attacks (3–4 h) → satisfies Stage 2 + starts Stage 3
- Write `THREAT_MODEL.md` (500-word summary + full surface map from §3/§5).
- Hand-write 3–5 **seed cases per category** for the top 3 categories (A, B, C). Run them **manually** against the live target, record observed behavior. Some will already pass (your verification layer is decent); that's fine — a documented "defense held" is a valid result.

### Phase 2 — Deterministic target client + Judge + one live agent (4–6 h) → satisfies Stage 3 gate
- Build `target_client` (auth, session, upload, multi-turn) — deterministic, well-tested.
- Build the **Judge** with per-category rubrics + deterministic anchors (PHI regex, refusal detection, cross-ID leakage).
- Build a **minimal Red Team loop** (even scripted-mutation at first) so we have ≥1 agent role running **live** against the target — that's the Stage-3 hard gate.
- Wire correlation IDs + Langfuse from the first request.

### Phase 3 — Full multi-agent graph + live dashboard (6–9 h)
- Orchestrator (reads the event substrate → campaign brief), Red Team with real LLM-driven mutation/escalation, Judge, Documentation — all four wired in LangGraph over the versioned contracts.
- Exploit DB + dedupe + coverage metrics.
- **Event substrate (Layer 1) emitting from every agent**, plus the **live activity dashboard (Layer 2)** tailing it over SSE — build these alongside the graph so you can literally watch it run while debugging (it pays for itself immediately).
- Generate the first real VULN-XXX reports.

> Emit events from day one of Phase 2, even before the dashboard exists — the substrate is cheap and
> the dashboard is just a reader. Don't bolt observability on at the end (the spec penalizes that).

### Phase 4 — Regression gate + the "watch it block" demo (2–3 h)
- Turn confirmed exploits into deterministic regression tests.
- CI job that runs the regression suite and **fails on regression** (this is the demo the grader wants to watch).
- Rehearse: introduce a tiny regression in a *local copy* of the target (or a stub), show the gate go red. (We don't push changes to the real target; we demonstrate the mechanism.)

### Phase 5 — Analytics tab, docs, cost, build-vs-configure, video (4–6 h)
- Finish the **analytics dashboard tab (Layer 3)** on top of the substrate the live view already reads.
- Finish all four gate docs to standard (each opens with its ~500-word summary where required).
- `AI_COST_ANALYSIS.md` (100/1K/10K/100K, not tokens×N — include batching, caching, local-model shift, sampling strategy per tier).
- `BUILD_VS_CONFIGURE.md` (Garak/Promptfoo/PyRIT/DeepTeam evaluated — see guide pack; note PyRIT is archived as of Mar 2026, Promptfoo→OpenAI but still MIT). Include the observability build-vs-buy note (why a custom console alongside Langfuse).
- 3 alerts documented, demo video (**live dashboard during an attack** + a gate blocking), social post, submit.

---

## 8. Locked decisions (mirror of the running-decisions log)

- **D1** Attacker is black-box HTTP-only; platform is operator-level on its own data + a target version signal.
- **D2** Red Team = local/open uncensored model (Ollama); Judge = a *different* frontier model; Orchestrator/Docs = frontier; deterministic fallback everywhere.
- **D3** Judge is independent of Red Team by construction (different model, prompt, context). Never share a context window.
- **D4** Human approval gate before a report is marked "published" or "critical." Autonomous up to that line. **The gate is deterministic and outside any LLM's control** — per the deck's slide 13, "if the model decides when to ask, it can be bypassed." A hard-coded check in platform code, not a prompt instruction.
- **D5** LangGraph on Python; SQLite for the exploit DB (migrate-ready); Langfuse for observability (reused).
- **D6** Ship 7 attack categories (need 3); every case OWASP-tagged. (Category G, insecure output handling / LLM05, added after the Gauntlet deck review — the class the first six missed.)
- **D9** Observability dashboard is a first-class 4-layer component (event substrate · live activity console · analytics tab · Langfuse). Both dashboard tabs and the Orchestrator read the same event substrate. See §4.6.
- **D7** We never modify or degrade the real deployed target to demo regression — we show the gate mechanism on a local/stub copy.
- **D8** Observability is a first-class component in 4 layers: one **event substrate** (read by both the Orchestrator and the dashboards), a **live activity console** (watch the agents work), an **analytics tab**, and **Langfuse** for per-call forensics. All agents emit events from Phase 2 on; PHI redacted at emit time.

## 9. Open questions to resolve (see running-decisions log for the live list)
- Exact deployed **API shape** for programmatic chat + upload (need to confirm against the live target in Phase 0 — is `/chat` JSON? what's the session/cookie contract for a bot client?).
- Is there a **version/build endpoint** on the target, or do we derive a version marker from `/health`/deploy time? (Needed for the regression trigger.)
- Which **local model** exactly, and does the droplet/your machine have the VRAM, or do we run Ollama locally and point at the remote target over HTTP?
- Do we get a **second, narrower-scope OAuth client / test user** to prove cross-patient authorization attacks cleanly? (Your Week 2 notes mention a scope-test client that isn't provisioned — provisioning it would make category B airtight.)
- CI home: **RESOLVED — new GitLab repo on `labs.gauntletai.com`** (instructor confirmed the PRD's "GitHub" is a typo; it should read GitLab). CI runs offline jobs only.

---

## 10. Interview soundbites to bank (start collecting now)
- "Attacker knowledge vs. operator knowledge" (the two-zone model).
- "The Judge is independent by construction — different model, no shared context — because an agent that grades its own attacks has a conflict of interest by design."
- "We chose a local uncensored model for the red team precisely because frontier models refuse offensive work and cost too much at continuous scale — that's not a shortcut, it's the spec's own concern."
- "A regression test that passes because phrasing drifted is worse than no test — so we score invariants, not strings, and anchor the flaky parts with deterministic checks."
- "We evaluated Garak, Promptfoo, PyRIT, DeepTeam. They're excellent scanners, but they score the immediate response; the assignment needs an orchestrated loop that mutates, escalates, judges independently, and gates regressions — so we configured *where we could* and built the coordination layer that off-the-shelf tools don't provide."
- **"There's no CVE for 'model was too helpful' — you can't patch your way out."** LLM attacks exploit *capability*, not a bug, so a fix changes behavior without removing the capability. That's exactly why our regression harness scores **invariants, not strings**: a test that passes because phrasing drifted is worse than no test. (Framing from the Gauntlet threats/defenses deck, slide 9.)
