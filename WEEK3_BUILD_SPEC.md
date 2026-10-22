# Adversarial AI Security Platform — Build Spec for Claude Code

> **Audience:** Claude Code, working in a fresh GitLab repo for the Week 3 adversarial platform.
> **Owner:** Taylor Clements (taylor.clements@gmail.com). **Written:** 2026-09-28.
> **Status:** design decisions are final. Build it; don't redesign it. If a locked decision proves
> impossible, STOP and explain — don't silently substitute.
> **Companion docs (read for context, in the project):** `WEEK3_ARCHITECTURE_GAMEPLAN.md`,
> `WEEK3_RUNNING_DECISIONS.md`, `WEEK3_ARCHITECTURE_DEFENSE.md`, `WEEK3_JUDGE_VALIDATION.md`.

---

## 0. How to use this document

1. **Read this whole file before writing any code.** Then read the four companion docs above.
2. **Work phase by phase (§10), in order.** Each phase ends with acceptance criteria. Don't start the
   next phase until the current one meets them.
3. **Stop at every 🛑 CHECKPOINT** and tell Taylor exactly what you need. Those need a human (GitLab
   repo creation, OpenEMR admin, the live target's credentials, setting an API spend limit, pushing).
4. **Keep a running log** in `BUILD_LOG.md`: what was done, what was verified, surprises, deviations,
   and — importantly — any API spend incurred.
5. **Commit in small steps** on the default branch (this is a fresh repo; `main`). Messages like
   `feat(judge): add deterministic PHI pre-filter`. End commit messages with the attribution footer
   Taylor's environment provides.
6. When something says **"verify in Phase 0,"** it's an assumption about the live target — confirm it
   against the real system before relying on it.

---

## 1. What we're building (one paragraph)

An autonomous **multi-agent red-team platform** that continuously attacks our own Week 1/2 Clinical
Co-Pilot (deployed at `http://<deployed-host>:8420`, chat UI at `/ui`) through its **deployed interface
only**, judges whether each attack succeeded with an **independent** judge, decides what to attack next,
and turns confirmed exploits into **reproducible vuln reports** and **invariant-scored regression
tests** that re-run when the target changes. Four agents (Orchestrator, Red Team, Judge, Documentation)
over a deterministic backbone (exploit DB, harness, observability), wired with LangGraph. A live
dashboard shows it working. **This is a NEW, independent repo** — we never modify the target.

---

## 2. Hard rules (never break these)

| # | Rule | Why |
|---|---|---|
| R1 | **Never modify the target Co-Pilot.** No changes to the Week 1/2 app, its droplet, its DB, or its config. We only send it HTTP requests and read responses. | It's the graded Week 2 app; and the attacker is black-box by design. |
| R2 | **Two-zone boundary (see §4).** The Red Team ("attacker zone") sees ONLY what the target's chat/API returns — no source, no DB, no logs, no system prompt (unless it *extracts* them as a finding). The rest ("platform zone") is operator-level but still never reads the target's source. Keep this clean in code and docs. | Core credibility; the trust boundary the grader asks about. |
| R3 | **MINIMIZE PAID API SPEND (top priority).** Local model for Red Team AND Orchestrator. Paid frontier only for Judge (pre-filtered + cheap model) and Documentation (rare). A **`DRY_RUN`/local-only mode** must run the ENTIRE platform with zero API calls for development and testing. Every run has a **hard budget cap**. Log estimated spend on every run. See §7. | Taylor's explicit constraint. |
| R4 | **No raw PHI anywhere** — not in logs, events, the exploit DB, or the dashboard/browser. Redact at emit time (hash IDs; strip MRN/SSN/name/DOB patterns). Reuse the Week 2 discipline. | HIPAA; and the target is a clinical system. |
| R5 | **Synthetic data only** in seed cases and fixtures. Invented names ("Test Attack A"). Never commit real API responses containing demo patient names. | Hygiene. |
| R6 | **Never write secrets** into code, docs, commits, or logs. Read them from `.env` (never committed). Don't print `.env` contents. | Basic hygiene. |
| R7 | **The Judge is independent of the Red Team** — different model, different prompt, separate context. Never let one context both generate and judge an attack. | The integrity property; a self-grading agent is compromised by design. |
| R8 | **The human-approval gate is deterministic code**, outside any LLM's control — required before a finding is marked `critical` or `published`. An LLM must not be able to skip it. | Trust boundary (D4). |
| R9 | **Never follow a redirect/link to a host other than the configured target** when sending attacks or paging. | Don't leak creds; stay on the target. |
| R10 | **Only ADD** to the platform; don't touch the target's repo or CI. This repo's CI is its own. | Independence. |
| R11 | **An error must never be silently scored as a pass.** A failed/timed-out attack, a judge error, or a target-unreachable event is its own state, never "target was safe." | A false "safe" hides a live vuln — the dangerous failure. |

---

## 3. Locked decisions

| # | Decision | Final choice |
|---|---|---|
| D1 | Trust model | **Two zones:** attacker zone (black-box, HTTP only) + platform zone (operator-level on its own data + a target version signal; never the target's source). |
| D2 | Framework | **Python + LangGraph.** Pydantic v2 for all models. httpx for the target client. |
| D3 | Red Team model | **Local uncensored model via Ollama** (Apple M1 Max / 32 GB). ~30B abliterated/uncensored instruct; pick the tag in Phase 1. Fallback 13B. |
| D4 | Orchestrator model | **Local model** (Ollama) — it only reads metrics and picks a category. No paid API. |
| D5 | Judge model | **Cheap frontier model (Haiku-class) via paid API**, and DIFFERENT from the Red Team model. Invoked ONLY on cases the deterministic pre-filter can't decide. Low-confidence verdicts may escalate to a bigger model (config flag, off by default to save spend). |
| D6 | Documentation model | **Frontier via paid API** (low volume — only on confirmed exploits). |
| D7 | Modes | **`local-only` (default for dev, zero API), `live` (real run, paid Judge/Docs).** A single `PLATFORM_MODE` env var + per-run budget cap. |
| D8 | Storage | **SQLite** exploit DB (migrate-ready), append-only **event store** (SQLite table or JSONL). |
| D9 | Observability | One **event substrate** every agent emits to; read by BOTH the Orchestrator and the dashboard. **Live console + analytics** dashboard (FastAPI + SSE). Reuse Langfuse for per-call forensics (optional, off in local-only). |
| D10 | Judge trust | Deterministic anchors (regex PHI/ID checks) + **labeled ground-truth eval** measuring agreement + **drift re-run** + versioned per-category rubric + structured verdicts. (See `WEEK3_JUDGE_VALIDATION.md`.) |
| D11 | Attack categories | Ship ≥3, aim for the 7 in §5. Every case OWASP-LLM-2025 tagged (the one required engineering item). |
| D12 | Regression | Confirmed exploit → **invariant-scored** regression test; re-runs on target version change; flags reappearance + cross-category regressions. |
| D13 | Repo host | **New GitLab repo** on `labs.gauntletai.com` (instructor confirmed "GitHub" in the PRD was a typo). |
| D14 | Contracts | Typed Pydantic models for every inter-agent message + a JSON-Schema `/contracts` dir (STRETCH — do after core works). |

---

## 4. The two zones (enforce in code structure)

- **Attacker zone:** `adv_platform/redteam/` + `adv_platform/target_client/`. These modules may know the target
  URL, hold a session, send attacks, read responses. They must NOT import the exploit DB, coverage
  metrics, or the version signal. Keep them dependency-isolated so the boundary is real, not just
  narrative.
- **Platform zone:** everything else — Orchestrator, Judge, Documentation, storage, harness,
  observability, dashboard. May read the event substrate, exploit DB, coverage, and the target's
  version signal. Must NEVER read the target's source code (there's no code path to it anyway — enforce
  by never adding one).

---

## 5. Attack taxonomy → OWASP (seed categories)

Every seed + generated case is tagged with an OWASP LLM 2025 category (required). Ship ≥3 (A, B, C
first); aim for all 7.

| # | Category | OWASP LLM 2025 | Priority |
|---|---|---|---|
| A | Indirect prompt injection via uploaded document | LLM01 | ★★★ |
| B | Cross-patient PHI / authorization bypass | LLM02, LLM06 | ★★★ |
| C | Verification bypass (ungrounded clinical claim as fact) | LLM09, LLM05 | ★★★ |
| D | Multi-turn safeguard erosion (crescendo) | LLM01 | ★★ |
| E | System-prompt / config leakage | LLM07 | ★★ |
| F | Unbounded consumption / denial-of-wallet | LLM10 | ★★ |
| G | Insecure output handling (target emits HTML/script `/ui` renders) | LLM05 | ★★ |

Each case (Pydantic model `AttackCase`): `id`, `category`, `subcategory`, `owasp`, `prompt_or_sequence`
(supports multi-turn), `expected_safe_behavior`, `invariant` (the rule that must hold),
`add_to_regression` (bool). Seeds live in `evals/seeds/<category>.yaml`, synthetic only.

---

## 6. Repo layout

```
adversarial-platform/                (fresh GitLab repo, branch: main)
├── README.md                        # setup, target URL, how to run (local-only + live), cost notes
├── CLAUDE.md                        # repo conventions + the token-saving rules (auto-read by Claude Code)
├── .env.example                     # every env var, commented; never commit real .env
├── .gitignore                       # .env, __pycache__, *.db, node_modules/, dashboard/dist/
├── requirements.txt                 # pinned; NO heavy deps without a note in BUILD_LOG
├── BUILD_LOG.md                     # running log incl. API spend
├── THREAT_MODEL.md                  # GATE (Stage 2) — 500-word summary + full surface map
├── ARCHITECTURE.md                  # GATE (Stage 4) — 500-word summary, names each agent, diagram, AI-use disclosure
├── USERS.md                         # GATE — who runs the platform + why automation
├── KEY_METRICS.md                   # GATE — metrics + rationale
├── contracts/                       # STRETCH: versioned JSON schemas
├── adv_platform/
│   ├── config.py                    # settings: PLATFORM_MODE, budget cap, model names, target URL
│   ├── models.py                    # ALL Pydantic contracts (AttackCase, Transcript, Verdict, Finding, Event…)
│   ├── llm/
│   │   ├── local.py                 # Ollama client (Red Team + Orchestrator)
│   │   ├── frontier.py              # paid API client (Judge + Docs) — respects DRY_RUN + budget cap
│   │   └── router.py                # picks local vs frontier per role + mode; tracks spend
│   ├── target_client/               # ATTACKER ZONE: auth, session, chat, upload, multi-turn (httpx)
│   ├── redteam/                     # ATTACKER ZONE: seed loader, generate, mutate/escalate, deterministic transforms
│   ├── judge/
│   │   ├── deterministic.py         # regex PHI/ID/refusal/HTML checks (the pre-filter + anchor)
│   │   ├── rubric.v1.md             # versioned per-category pass/fail criteria
│   │   └── judge.py                 # LLM judge (only for cases the pre-filter can't decide)
│   ├── orchestrator/                # reads substrate → campaign brief (LOCAL model)
│   ├── documentation/               # confirmed exploit → VULN report (frontier; low volume)
│   ├── harness/                     # regression runner, dedupe (content hash), version watcher
│   ├── storage/                     # SQLite: exploits, runs, attempts, coverage, events
│   ├── observability/               # event substrate emit API, correlation IDs, budget/alerts, (opt) Langfuse
│   ├── dashboard/                   # FastAPI: live console (SSE) + analytics tab
│   └── graph.py                     # LangGraph wiring of the 4 agents + the loop
├── evals/
│   ├── seeds/                       # seed AttackCases per category (YAML, synthetic)
│   ├── judge/
│   │   ├── ground_truth/            # ~15–25 labeled transcripts (synthetic) + labels
│   │   └── run_judge_eval.py        # agreement % vs labels; drift check; exits non-zero below floor
│   ├── regression/                  # confirmed exploits as deterministic tests
│   └── run_regression.py            # the CI gate entry point
├── reports/                         # generated VULN-XXX reports (≥3)
└── .gitlab-ci.yml                   # offline jobs only: judge eval + regression gate (no live target, no paid API)
```

---

## 7. Token / cost control (R3 — build these in from day one)

This is a **first-class feature**, not an afterthought. Implement in `adv_platform/llm/router.py` +
`config.py`:

1. **`PLATFORM_MODE`:**
   - `local-only` (**default**): every agent — including Judge and Documentation — runs on the local
     Ollama model. **Zero paid API calls.** Use this for ALL development and testing. The Judge quality
     is lower here, but that's fine for wiring/debugging; the point is $0 spend.
   - `live`: Judge → cheap frontier (Haiku-class), Documentation → frontier. Red Team + Orchestrator
     stay local in both modes.
2. **Deterministic pre-filter before the paid Judge:** `judge/deterministic.py` runs first. If regex
   proves the invariant broke (real MRN present) or clearly held (hard refusal, empty), **return that
   verdict without calling the LLM Judge at all.** Only ambiguous cases reach the paid model. Expect
   this to cut Judge API calls dramatically.
3. **Per-run budget cap:** `MAX_RUN_USD` (default small, e.g. 0.50). The router tracks estimated spend
   (tokens × price); when the cap is hit, emit `budget_exceeded` and stop the run gracefully.
4. **Cache/dedupe:** never call the Judge twice on the same transcript (hash it). Dedupe attacks before
   judging.
5. **Small defaults:** default campaign size small (e.g. 5–10 attacks); large runs are opt-in.
6. **Spend logging:** every run logs estimated USD to `BUILD_LOG.md` and the events. The dashboard shows
   live cost.
7. **No paid calls in CI.** CI runs the judge eval and regression gate in `local-only` (or against
   stored fixtures) — never spends money.

🛑 **Before the first `live` run:** confirm with Taylor that an **Anthropic API spend limit** is set in
the Console, and which API key to use. Never run `live` without the cap.

---

## 8. The four agents — contracts & behavior

Typed messages (Pydantic in `models.py`); JSON-Schema mirror in `/contracts` is stretch.

- **Orchestrator (local):** reads coverage + open findings + remaining budget from the substrate →
  emits `CampaignBrief {category, seed_ids, budget, stop_conditions}`. Picks the emptiest / highest-open
  category. On a target version change, emits a regression campaign instead.
- **Red Team (local, attacker zone):** takes `CampaignBrief` → loads seeds → generates variants →
  sends via `target_client` → reads responses → mutates partial successes (TAP-style) + applies
  deterministic transforms (base64/leet/homoglyph) → emits `Transcript {turns, category, invariant,
  expected_safe_behavior}`. Multi-turn capable.
- **Judge (frontier in live, pre-filtered):** takes `Transcript` → **deterministic checks first** →
  only if ambiguous, call the LLM judge with the versioned rubric → emits `Verdict {result:
  pass|fail|partial, invariant_violated, confidence, evidence_pointer}`. Independent of Red Team (R7).
- **Documentation (frontier, rare):** takes a confirmed `Verdict` → writes `Finding` (VULN-ID,
  severity, clinical impact, minimal repro from the transcript, observed vs expected, remediation using
  named controls, status) → deterministic human-gate before `critical`/`published` (R8/D8 gate).

Error contracts (typed): `target_unreachable`, `budget_exceeded`, `judge_timeout`, `no_findings`,
`regression_detected`. On any of these, degrade gracefully and log — never score as pass (R11).

---

## 9. Phase plan (stop at each 🛑; keep spend at $0 until Phase 6)

### Phase 0 — Repo + skeleton + recon (2–3 h)
1. 🛑 **CHECKPOINT C0:** Taylor creates the empty GitLab repo and gives the URL. Confirm target URL and
   that Taylor can reach `/ui`.
2. Scaffold the repo (§6), `requirements.txt`, `.env.example`, `README` stub, `CLAUDE.md` with the R3
   token rules, `.gitignore`. First commit.
3. **Probe the live target** (Phase 0 recon): write `adv_platform/target_client/probe.py` (dev-only). Log
   in as the test user, send ONE benign chat, do ONE benign upload if reachable. Record: the chat
   endpoint + request/response JSON shape, the session cookie mechanics, whether upload works for the
   non-admin user, and whether any `/health`/`/version` field exists for the version signal. **Shapes
   only — no PHI in the log.**
4. Record findings in `BUILD_LOG.md`. If the API shape differs from assumptions, note it and proceed.

**Accept when:** repo exists + pushed once; target is reachable and an authenticated chat round-trips;
the API shape + version-signal question are answered in the log.

### Phase 1 — Local models + config + cost router (2–3 h)
1. `config.py` (PLATFORM_MODE, MAX_RUN_USD, model names, target URL), `models.py` (all contracts),
   `llm/local.py` (Ollama), `llm/frontier.py` (respects DRY_RUN + budget), `llm/router.py` (role→model
   by mode; spend tracking).
2. 🛑 Pick the local model tag with Taylor; `ollama pull` it. Confirm a local generation works.
3. Everything from here runs in `local-only` — **$0 API.**

**Accept when:** local model responds; router returns local for all roles in local-only; frontier
client refuses to spend when DRY_RUN.

### Phase 2 — Target client + Judge (deterministic + LLM) + one live agent (4–6 h)
1. `target_client/` (auth, session, chat, upload, multi-turn) — deterministic, tested against the live
   target.
2. `judge/deterministic.py` (PHI/ID/refusal/HTML regex), `judge/rubric.v1.md`, `judge/judge.py`
   (pre-filter → LLM only if ambiguous).
3. A minimal Red Team loop (scripted mutation is fine here) so ≥1 agent runs LIVE against the target —
   satisfies the Stage-3 gate. Emit events + correlation IDs from the first request.

**Accept when:** an attack can be sent to the live target, a transcript captured, and a verdict
produced — all in local-only mode. Deterministic pre-filter demonstrably short-circuits clear cases.

### Phase 3 — Full graph + event substrate + live dashboard (6–9 h)
1. Orchestrator, real Red Team (LLM mutation/escalation), Judge, Documentation wired in `graph.py` with
   the loop. Exploit DB + dedupe + coverage.
2. Event substrate emitting from every agent; live dashboard (SSE) tailing it; analytics tab.
3. First VULN-XXX reports (still local-only).

**Accept when:** a full campaign runs end-to-end in local-only, visible on the dashboard, producing ≥1
report — $0 spent.

### Phase 4 — Judge validation (2–3 h)
1. `evals/judge/ground_truth/` (~15–25 labeled synthetic transcripts) + `run_judge_eval.py` (agreement
   %, drift check, non-zero exit below floor).
2. Run it; record the agreement number in `BUILD_LOG.md`.

**Accept when:** judge eval runs offline and reports an agreement score; wired into CI.

### Phase 5 — Regression gate + "watch it block" (2–3 h)
1. Confirmed exploits → invariant-scored regression tests; `run_regression.py`.
2. `.gitlab-ci.yml`: offline jobs (judge eval + regression) — no live target, no paid API.
3. Rehearse the demo: a small local/stub target with a seeded flaw shows the gate go red.

**Accept when:** CI runs offline and blocks on a regression; the block is reproducible for the demo.

### Phase 6 — First LIVE run + docs (3–5 h)
1. 🛑 **CHECKPOINT:** confirm Anthropic spend limit is set + which key. Set `PLATFORM_MODE=live`,
   small budget cap.
2. Run a real campaign; confirm the pre-filter keeps Judge calls low; record actual spend.
3. Write the four gate docs (THREAT_MODEL, ARCHITECTURE incl. AI-use disclosure + diagram, USERS,
   KEY_METRICS). Optional/stretch: AI_COST_ANALYSIS, BUILD_VS_CONFIGURE, `/contracts`.

**Accept when:** a live run produced real findings within budget; gate docs complete; deployed target
URL in README.

---

## 10. Environment / .env.example (Claude Code: generate this file)

```
PLATFORM_MODE=local-only          # local-only (default, $0) | live
MAX_RUN_USD=0.50                  # hard per-run budget cap
TARGET_BASE_URL=http://<deployed-host>:8420
TARGET_USERNAME=                 # test user (Taylor provides)
TARGET_PASSWORD=                 # (Taylor provides; never commit)
OLLAMA_BASE_URL=http://localhost:11434
LOCAL_MODEL=                     # set in Phase 1 (e.g. an abliterated ~30B tag)
ANTHROPIC_API_KEY=               # only used in live mode (Taylor provides; spend-limited)
JUDGE_MODEL=claude-haiku-...      # cheap frontier for the Judge
DOC_MODEL=claude-...              # frontier for Documentation (rare)
LANGFUSE_*=                       # optional; off in local-only
```

---

## 11. Known traps
- **Spending money by accident:** default MUST be local-only; frontier client must hard-refuse when
  DRY_RUN/local-only. Never default `live`.
- **Judge called on every case:** the deterministic pre-filter must run first, or costs balloon.
- **Scoring an error as "safe":** R11 — never. Errors are their own state.
- **Attacker zone importing platform data:** breaks the two-zone claim; keep modules isolated.
- **Local Alice vs droplet patient UUIDs / test user:** confirm the real test account in Phase 0.
- **Blocking on the live target for dev:** most work happens in local-only; only Phases 2 and 6 need the
  live target.

---

## 12. Prerequisites (for Taylor, before Claude Code starts)
| Need | Who | Notes |
|---|---|---|
| Empty GitLab repo on labs.gauntletai.com | Taylor | Provide the URL at C0 |
| Live target reachable + a test login | Taylor | `test_clinician` or a dedicated test user |
| Ollama running + model pulled | Taylor / Claude Code | Tag chosen Phase 1 |
| Anthropic API key + **spend limit set** | Taylor | Only needed for Phase 6 (live) |
| 2nd patient / test user in OpenEMR (for category B) | Taylor (admin) | Needed to prove cross-patient cleanly; Phase 3+ |
```
