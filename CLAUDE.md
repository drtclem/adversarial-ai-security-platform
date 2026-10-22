# CLAUDE.md — Repo Conventions & Guardrails

> Claude Code reads this automatically. It is the standing contract for how to work in this repo.
> The full plan is in `WEEK3_BUILD_SPEC.md` (+ companion docs). This file is the short, always-on rules.

---

## 0. TOP PRIORITY — minimize paid API spend

The owner (Taylor) is strict about this. Treat every paid API call as costing real money.

1. **Default to `PLATFORM_MODE=local-only`.** In this mode EVERY agent — including Judge and
   Documentation — runs on the local Ollama model. **Zero paid API calls.** Do all development,
   debugging, and testing here. Never change the default to `live`.
2. **Only the Judge and Documentation may ever use the paid frontier API, and only in `live` mode.**
   Red Team and Orchestrator are ALWAYS local, in every mode.
3. **Deterministic pre-filter before the paid Judge.** `adv_platform/judge/deterministic.py` runs first;
   if regex proves the invariant broke or clearly held, return that verdict WITHOUT calling the LLM
   judge. Only ambiguous cases may reach the paid model.
4. **Hard per-run budget cap** (`MAX_RUN_USD`). The LLM router tracks estimated spend; when the cap is
   hit, emit `budget_exceeded` and stop the run gracefully.
5. **The frontier client must hard-refuse to make a call when mode is `local-only` / `DRY_RUN`.** A
   paid call in the wrong mode is a bug, not an option.
6. **No paid calls in CI, ever.** CI runs offline (local-only or stored fixtures).
7. **Cache/dedupe:** never judge the same transcript twice (hash it).
8. **Log estimated USD** for every `live` run in `BUILD_LOG.md` and in the events.
9. Before the FIRST `live` run, STOP and confirm with Taylor that an Anthropic spend limit is set.

If a task seems to require a paid call during normal development, you're probably doing it wrong —
stay in local-only.

---

## 1. Never break these (see WEEK3_BUILD_SPEC.md §2 for full list)

- **Never modify the target Co-Pilot** (the Week 1/2 app at `http://<deployed-host>:8420`). We only send
  it HTTP and read responses. This is a separate, independent repo.
- **Two-zone boundary.** `adv_platform/redteam/` and `adv_platform/target_client/` are the ATTACKER ZONE: they
  see only what the target returns and must NOT import the exploit DB, coverage metrics, or the version
  signal. Everything else is the PLATFORM ZONE. Keep them dependency-isolated.
- **The Judge is independent of the Red Team** — different model, different prompt, separate context.
  Never let one context both generate and judge an attack.
- **The human-approval gate is deterministic code**, outside any LLM's control, before a finding is
  `critical`/`published`.
- **An error is never scored as "pass"/"safe."** Failed/timed-out attacks, judge errors, and
  target-unreachable are their own states.
- **No raw PHI** in logs, events, the DB, or the dashboard/browser. Redact at emit time (hash IDs;
  strip MRN/SSN/name/DOB patterns).
- **Synthetic data only** in seeds and fixtures (invented names).
- **Never commit secrets.** Read from `.env` (gitignored). Never print `.env`.
- **Stay on the configured target host** — never follow a redirect/link to another host.

---

## 2. Stack & conventions

- **Python + LangGraph.** Pydantic v2 for all inter-agent contracts (`adv_platform/models.py`).
- **httpx** for the target client. **SQLite** for the exploit DB and event store.
- **Local model:** Ollama at `OLLAMA_BASE_URL` (Red Team + Orchestrator).
- **Frontier:** paid API only for Judge (cheap Haiku-class) + Documentation, only in `live`.
- **Correlation ID** on every agent invocation, threaded through every event, log line, and target
  request — a full run must be reconstructable from the event store alone.
- **Every inter-agent message is a typed Pydantic model.** A JSON-Schema mirror in `/contracts` is
  stretch — do it after the core works.
- Pin dependencies in `requirements.txt`. Don't add heavy deps without a note in `BUILD_LOG.md`.
- Tests/evals follow a simple offline-runner convention (functions returning `(passed, detail)`, a
  `main()` that exits non-zero on failure) — no live target, no paid API in CI.

---

## 3. Workflow

- **Work phase by phase** per `WEEK3_BUILD_SPEC.md` §9. Don't start a phase until the prior one meets
  its acceptance criteria.
- **Stop at every 🛑 CHECKPOINT** — those need Taylor (GitLab repo, target creds, model pull, API spend
  limit, pushing).
- **Small commits** on `main`. Messages like `feat(judge): add deterministic PHI pre-filter`. End each
  commit message with the attribution footer the environment provides.
- **Keep `BUILD_LOG.md` current:** what was done, what was verified, surprises, deviations, and any API
  spend.
- **Ask before:** any `git push`, anything touching the target's droplet/repo/CI, any live/paid run, any
  OpenEMR admin action.

---

## 4. Where things live (see WEEK3_BUILD_SPEC.md §6 for the full tree)

- `adv_platform/llm/router.py` — the cost gate: role→model by mode, spend tracking, budget cap.
- `adv_platform/judge/deterministic.py` — the pre-filter (runs before any paid judge call).
- `adv_platform/target_client/` — attacker-zone HTTP client (auth, session, chat, upload, multi-turn).
- `adv_platform/graph.py` — LangGraph wiring of the 4 agents + the loop.
- `evals/judge/` — the Judge ground-truth eval + drift check.
- `evals/run_regression.py` — the CI gate entry point (offline).
