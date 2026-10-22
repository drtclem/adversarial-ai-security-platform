# Week 3 — Running Decisions, Open Questions & How-To Guide Pack

> Living log. Add to it as we go. Newest notes go under each section.
> Companion to `WEEK3_ARCHITECTURE_GAMEPLAN.md`.

---

## A. Locked decisions (with rationale + reversal cost)

| ID | Decision | Rationale | Cost to reverse |
|---|---|---|---|
| D1 | Attacker = black-box HTTP only. Platform = operator-level on its own data + a target version signal. | Realistic internal-red-team model; keeps exploits honest; gives us the regression trigger the spec needs. | Low now, high later — bake into threat model early. |
| D2 | Red Team = local/open uncensored model (Ollama). Judge = different frontier model. Orchestrator/Docs = frontier. Deterministic fallback everywhere. **Hardware confirmed: Apple M1 Max, 32 GB unified memory, Ollama already installed. Target size: ~30B-class abliterated/uncensored instruct (Hermes-class or abliterated Llama-3); fall back to 13B if sluggish. CVP-verified Claude kept as backup if a model over-refuses.** | Spec explicitly flags frontier refusal + cost at scale. Independence for the Judge. M1 Max comfortably runs 30B quantized. | Medium — model swap is config, but prompts are tuned per model. |
| D3 | Judge independent of Red Team by construction (diff model/prompt/context, never shared). | Spec: "an agent that both generates and evaluates is compromised by design." | High — it's the core integrity claim. |
| D4 | Human approval gate before "published"/"critical" report status. Autonomous below that line. **Gate is deterministic, outside any LLM's control.** | Spec wants deliberate trust boundaries + approval gates; deck slide 13: a model-controlled gate can be bypassed. | Low. |
| D5 | Python + LangGraph; SQLite exploit DB (migrate-ready); reuse Langfuse. | Compounds Weeks 1–2; inspectable graph; you already run Langfuse. | Medium. |
| D6 | Ship 7 attack categories (min 3). Every case OWASP-LLM-2025 tagged. | 3 is the floor; 7 shows breadth. Category G (insecure output handling / LLM05) added after the deck review — the one class the first six missed. | Low. |
| D7 | Never modify/degrade the real deployed target to demo regression — show the gate on a local/stub copy. | Don't break the graded Week 2 app; still prove the mechanism. | Low. |
| D8 | Observability = 4 layers: event substrate (shared by Orchestrator + dashboards) · live activity console · analytics tab · Langfuse for forensics. All agents emit events from Phase 2; PHI redacted at emit time. | Spec says the observability layer IS the Orchestrator's data substrate; the live console is a near-free reader and the strongest demo asset. | Low–medium (substrate schema is the sticky part). |

## B. Open questions (resolve these; check off as answered)

- [ ] **API shape of the live target** for programmatic chat + upload. Is `/chat` JSON in/out? What does a bot client send for the session cookie (`copilot_session`)? — *Resolve in Phase 0 by inspecting the live target.*
- [ ] **Version signal** on the target: real `/version` or `/health` field, or do we stamp a deploy marker ourselves? Needed for the regression trigger.
- [x] **Local model choice + hardware.** → **Apple M1 Max, 32 GB, Ollama installed.** Plan: ~30B-class uncensored/abliterated instruct (Hermes-class or abliterated Llama-3), pick the exact current tag from the Ollama library in Phase 2; 13B fallback; CVP-Claude backup. (2026-09-28)
- [ ] **Second narrow-scope OAuth client / test user** to prove cross-patient auth attacks cleanly. Week 2 notes mention an unprovisioned scope-test client — provisioning it makes category B airtight. Needs OpenEMR admin (you).
- [x] **Repo host:** **RESOLVED — new GitLab repo on labs.gauntletai.com** (Taylor, 2026-09-28). The Week 3 submission table saying "GitHub" is a known typo; instructor confirmed it should read GitLab. No caveat needed.
- [ ] **Do we have a second patient** on the target (Bob exists per Week 2 notes) so cross-patient tests have somewhere to leak *to*? Confirm at least 2 patients with distinct data.
- [ ] **Is document upload reachable for `test_clinician`** (non-admin)? Week 2 added the upload button in `/ui`; confirm the bot client can upload too.

## C. Questions answered (move items here with the answer + date)

- **2026-09-28** — Platform stack? → **Python + LangGraph** (Taylor).
- **2026-09-28** — Red team model? → **Local/open uncensored model** (Taylor).
- **2026-09-28** — Scope ambition? → **Core + high-ROI extras** (Taylor).
- **2026-09-28** — Attacker knowledge? → **No source/GitLab access; black-box chatbot only** (Taylor). Refined into the two-zone model as **D1**.
- **2026-09-28** — Want a live dashboard showing when the agent is working, what it's saying, what happened? → **Yes.** Added as **D8**: promoted observability to a 4-layer component with a dedicated live activity console reading a shared event substrate.
- **2026-09-28** — Reviewed the Gauntlet "AI Security: Threats & Defenses" deck (15 slides). Four takeaways folded in: (1) added **category G, insecure output handling / LLM05** — the one class the first six missed (deck slide 8); (2) Judge rubric's expected-safe-behavior now drawn from the deck's named defenses; (3) Documentation remediation uses the deck's slide-14 control vocabulary; (4) hardened **D4** — HITL gate is deterministic and outside LLM control (deck slide 13). Banked the "you can't patch your way out / no CVE for too-helpful" framing (slide 9) as the justification for invariant-scoring. Deck is defense-side; used only as Judge rubric + remediation vocabulary, not as a push to harden the target (D7 still holds).

## D. Deviations from the plan (log anything we change mid-build)

- **2026-09-28 — SCOPE CORRECTION from the instructor (Slack @channel).** The PRD wording that lists a
  long "Optional Engineering Deliverables" block as "not optional" was a **mistake**; the instructor
  will fix the doc. **The ONLY required engineering deliverable is the OWASP LLM risks item** (map each
  test case to its OWASP category). Everything else in that block — ATO evidence packet, integration
  packet, formal inter-agent contract tests, load/stress tests, triage-of-simulated-scan exercise, SQL
  indexing SLOs, data-lineage/access-control docs, migration notes, versioned `/contracts` — is **truly
  optional (stretch)**. Do them only if there's time.
  - **What this does NOT change:** items required by the *core* Platform Requirements (not the optional
    block) still stand — the **observability layer**, the **regression & validation harness**, the
    **multi-agent system** itself, the **Documentation agent + ≥3 vuln reports**, and the four gate docs
    (`THREAT_MODEL.md`, `ARCHITECTURE.md`, `USERS.md`, `KEY_METRICS.md`). Those are core, not optional.
  - **Net effect:** the **required floor** = 4 agents + harness + observability + OWASP-tagged eval
    suite (≥3 categories, ≥1 live agent) + the 4 gate docs + deployed target URL + the regression-gate
    demo. Our "Core + high-ROI extras" ambition is unchanged, but the extras are now *explicitly* stretch
    — drop any of them without guilt if time is short.
  - **Reclassified to stretch** (had crept toward near-required): versioned `/contracts` + contract
    tests, `AI_COST_ANALYSIS.md`, `BUILD_VS_CONFIGURE.md`, the triage exercise. Keep the cheap
    high-ROI ones (OWASP mapping is required anyway; cost analysis + build-vs-configure are cheap and
    strong for the interview) but treat them as optional polish, not gates.

---

# How-To Guide Pack (curated, current as of 2026-09-28)

Everything below was checked against live sources this session. Read them in this order.

## 1. Start here — the mental model (½ day of reading, high payoff)

- **OWASP Top 10 for LLM Applications (2025)** — the official list and the vocabulary graders expect. Every test case maps to one of these.
  - Official hub: `https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/`
  - Plain-English walkthrough: `https://securityboulevard.com/2026/03/the-owasp-top-10-for-llm-applications-2025-explained-simply/`
  - Per-category with attack types + code: DeepTeam's docs — `https://www.trydeepteam.com/docs/frameworks-owasp-top-10-for-llms`
  - **The 2025 list (memorize the numbers):** LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data & Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector & Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.

- **A methodology overview of LLM red teaming** (attack categories + how a program is run, not just a tool list):
  - `https://appsecsanta.com/ai-security-tools/llm-red-teaming` (2026 guide: categories, the four frameworks, program structure)
  - `https://qawerk.com/blog/llm-red-teaming-tools/` (what each tool *catches vs misses* — great for your build-vs-configure doc)

## 2. The tool landscape (for `BUILD_VS_CONFIGURE.md` — the spec names these)

You are **building** the orchestrated multi-agent loop, but you must show you evaluated the
off-the-shelf options and say why they don't fully satisfy the assignment. Current facts:

| Tool | Owner / License | What it's great at | Where it falls short for us | Currency note (2026) |
|---|---|---|---|---|
| **Garak** | NVIDIA, Apache-2.0 | Broad CLI vulnerability *scanner*, 120+ probes; JSONL results good for regression diffing | Model-level scanning; limited agentic/RAG/app-flow coverage; scores immediate response only | Active |
| **Promptfoo** | OpenAI (acq. Mar 2026), still **MIT** | Config-first (YAML) red team + eval, CI/CD-friendly, OWASP preset | Coverage shallower than dedicated offensive tools; "regression harness" more than "deep adversarial platform" | Acquired but open |
| **PyRIT** | Microsoft, MIT | Custom multi-turn campaigns, crescendo + TAP | You'd still build orchestration/judge/docs around it | **Archived read-only since 2026-03-27** — cite as a maintenance risk |
| **DeepTeam** | Confident AI, Apache-2.0 | Clearest OWASP-LLM-Top-10 mapping, lowest onboarding, built on DeepEval | Framework for scans; not an autonomous orchestrated multi-agent red team | Active |

**Defense line:** "These are excellent for *breadth* and *baseline regression*. The assignment
requires an *orchestrated loop* — an Orchestrator that prioritizes by coverage, a Red Team that
autonomously mutates/escalates, an *independent* Judge, and a Documentation agent — which none of
them provide out of the box. We reuse their *ideas* (Garak's JSONL regression diffing, PyRIT's
crescendo/TAP, DeepTeam's OWASP mapping) and build the coordination layer."

Consider actually running **Garak or DeepTeam once** against the target and citing the output as a
baseline — cheap, and it makes the build-vs-configure record evidence-based instead of theoretical.

## 3. The specific attack techniques to implement (with names to drop in interviews)

- **Direct vs. indirect prompt injection.** Direct = user overrides instructions. Indirect = hidden
  instructions inside content the model ingests (for you: **the uploaded lab PDF / intake form** — put
  injected instructions in the document text/OCR layer). This is your #1 category and it's unique to
  this app. (OWASP LLM01.)
- **Crescendo** (multi-turn escalation) — benign opener, escalate gradually across turns until a
  safeguard erodes. Your own Week 2 notes say multi-turn convos sometimes ignore prior safeguards —
  aim here. (PyRIT documents this technique.)
- **TAP (Tree of Attacks with Pruning)** — an attacker LLM generates + refines prompts based on the
  target's responses, pruning dead branches. This is essentially your Red Team's mutation loop; name
  it.
- **Encoding / obfuscation** — base64, leetspeak, translation, homoglyphs to slip past keyword
  filters. Cheap variants for the mutation step.
- **System-prompt extraction** — coax the target into revealing its instructions/config (OWASP LLM07).
- **Denial-of-wallet / unbounded consumption** — force long generations, recursive tool calls, giant
  uploads (respect the 5-page cap and see if it holds). Deterministic to prove. (OWASP LLM10.)
- **Cross-patient / authz** — as `test_clinician`, try to read a patient not assigned to you; try to make a
  worker fetch another patient's record. PHI leakage is the worst-case → highest severity.

## 4. Framework / infra how-tos

- **LangGraph multi-agent patterns** (supervisor, hand-offs, state): LangGraph docs —
  `https://langchain-ai.github.io/langgraph/` → tutorials → "multi-agent". Mirror the supervisor
  pattern you already used in Week 2 so the story is "same muscle, pointed at security."
- **Ollama** (local models): `https://ollama.com` — `ollama pull <model>`, then hit
  `http://localhost:11434/api/chat`. For an uncensored red-team model, look at Dolphin-/abliterated-
  class instruct models on the Ollama library; pick by what your VRAM allows.
- **Langfuse tracing** you already run — reuse: correlation ID as the trace id; nest spans per agent.
- **JSON Schema + contract tests:** define schemas in `/contracts`, validate with `jsonschema`
  (Python). Write a test per boundary that asserts both producer output and consumer input validate.

## 5. Reference framings for the required docs

- **Threat model structure:** OWASP's categories (from Stage 2 of the spec) are literally your
  section headings — prompt injection (direct/indirect/multi-turn), data exfiltration, state
  corruption, tool misuse, DoS, identity/role. For each: attack surface, impact, exploit difficulty,
  existing defense. Open with the ~500-word summary.
- **AI cost analysis (not tokens×N):** think per-tier architecture shifts — sampling instead of full
  sweeps at 10K+, batching judge calls, caching seed transcripts, shifting more load to the local
  model, queueing regression runs. Say what *breaks* at each tier and what you'd change.
- **AI-use disclosure (goes in ARCHITECTURE.md):** table of every AI-powered role → what deterministic
  check or human gate follows it → residual risk. Include the "how we'd detect a drifting Judge" bit
  (e.g., periodically re-score a fixed ground-truth set of known-good/known-bad transcripts and alert
  on divergence).

## 6. Things NOT to do (graders penalize these)

- Don't ship a **single agent** wearing four hats. The Judge especially must be its own agent.
- Don't let the **Judge rubber-stamp** — validate it against a labeled set; have a drift story.
- Don't build a **static payload list** and call it a red team — the mutation/escalation loop is the point.
- Don't log **raw PHI / raw attack payloads with patient data** to any SaaS. Same discipline as Week 2.
- Don't demo a regression block by **breaking the real target** — use a local/stub copy (D7).
- Don't claim the attacker sees source — keep the **two-zone** boundary clean in every artifact.

## 7. Sources checked this session (2026-09-28)
- OWASP LLM Top 10 (2025) — genai.owasp.org, DeepTeam docs, Security Boulevard, TrojAI.
- Tool landscape + currency (PyRIT archived; Promptfoo→OpenAI/MIT) — Braintrust, appsecsanta, QAwerk, SecureTom, dev.to (Ventrova), General Analysis.
