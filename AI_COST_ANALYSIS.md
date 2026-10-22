# AI_COST_ANALYSIS.md — Cost at Scale (100 / 1K / 10K / 100K runs)

> Author: Taylor Clements · Updated 2026-09-30
> This is **not** cost-per-token × N. Each tier names the architectural change required to stay viable.

---

## Summary

The platform is designed so that the expensive resource — frontier API calls — is spent only where it
buys trust, and everything high-volume runs locally at zero marginal cost. As run volume grows from 100
to 100K, the binding constraint changes at each tier, and so does the right architecture. At small
scale the platform is effectively free and the constraint is local-model throughput. At large scale the
constraints become the *target's* own API bill (each attack makes the Co-Pilot spend), the frontier
Judge bill, and wall-clock time — each of which is addressed by a specific architectural move
(sampling, pre-filter tuning, batching, parallelism, caching), not by paying linearly more.

Two cost surfaces must be tracked separately:
- **Platform spend** — the adversarial platform's own model calls. In `local-only` this is **$0**; in
  `live` it is only the frontier Judge (pre-filtered) + Documentation (rare).
- **Target-induced spend** — every attack makes the Co-Pilot answer, costing *its* model account
  ~$0.01–0.10/turn (Week-2 measured range). The platform never pays this, but it *causes* it, so
  bounding it is a first-class design concern (and is itself the denial-of-wallet threat we test for).

---

## Actual development spend (measured)

| Date | What | Model | Spend |
|---|---|---|---|
| through 2026-09-30 | Every campaign, Red Team mutation, local Judge, Orchestrator, Documentation, regression and offline test run | local 8B (Ollama) | **$0.00** (router asserts $0 in local-only) |
| 2026-09-30 | Claude-as-labeler check, 30 human-labeled cases (opt-in operator tool) | Claude Sonnet 5.5 | $0.14 |
| 2026-09-30 | Frontier Judge eval, 30 labeled cases | Claude Haiku 4.5 | $0.10 |
| 2026-09-30 | Judge consistency, 3 runs × 30 cases | Claude Haiku 4.5 | $0.30 |
| | **Total paid spend to date** | | **≈ $0.54** |

Target-induced spend (the Co-Pilot's own model bill from our attacks) is on the target's account and is
not included above.

**Measured unit cost of the frontier Judge.** On the 30-case set, 24 transcripts reached the LLM tier
(the deterministic pre-filter decided 6) and cost $0.099: **≈ $0.0041 per LLM-judged transcript, ≈ $0.0033
per transcript overall**. Projected Judge spend at that rate: **100 runs ≈ $0.33 · 1K ≈ $3.30 · 10K ≈ $33 ·
100K ≈ $330**, before any batching. This is likely an upper bound: the labeled set is deliberately hard
(many refusal-wrapped and disclosure-shaped replies), while real campaigns produce more clean refusals
the pre-filter settles for $0. Prompt caching does not reduce this on Haiku 4.5, whose minimum cacheable
prompt (4,096 tokens) is larger than the rubric (~2,200 tokens); it would apply to a larger-model Judge.

## Cost model per role

| Role | local-only | live | Volume profile |
|---|---|---|---|
| Red Team | local $0 | local $0 | **High** (generates + mutates every attack) |
| Orchestrator | local $0 | local $0 | Low (1 decision/campaign) |
| Judge | local $0 | frontier, **pre-filtered** | Medium — but deterministic pre-filter removes most calls |
| Documentation | local $0 | frontier | Very low (only confirmed findings) |
| Target (Co-Pilot) | its account | its account | = number of attack turns sent |

The deterministic pre-filter is the key cost lever: clear pass/fail cases (refusals, exact PHI/MRN
matches) are decided in code, so the frontier Judge only ever sees the genuinely ambiguous minority.

---

## Tier 1 — 100 runs (development / a single campaign)

- **Binding constraint:** local-model throughput (Ollama serves roles sequentially).
- **Platform spend:** $0 in local-only. In live, judge calls only on the ambiguous subset (~a few $).
- **Target-induced spend:** ~100–300 turns × ~$0.01–0.10 ≈ a few dollars, on the target's account.
- **Architecture:** as-is. Single process, sequential graph, one local model.
- **Change required:** none.

## Tier 2 — 1,000 runs (nightly regression + exploratory)

- **Binding constraint:** wall-clock time (sequential local inference) and target-induced spend.
- **Platform spend:** still ~$0 platform-side in local-only; modest frontier Judge spend in live,
  held down by the pre-filter.
- **Architecture change:** (a) **parallelize** the target client and local inference across workers so
  the run finishes overnight; (b) **cache/dedupe** — never re-judge an identical transcript (content
  hash), which the exploit DB already enforces; (c) enforce a **per-run budget cap** so target-induced
  spend can't run away.
- **Why not tokens×N:** dedupe + pre-filter mean judge cost grows sub-linearly with attack count.

## Tier 3 — 10,000 runs (continuous, multi-version)

- **Binding constraint:** target-induced spend and frontier Judge spend both become material; time
  requires real concurrency.
- **Architecture change:**
  1. **Sampling, not full sweeps** — the Orchestrator tests a risk-weighted sample of each category per
     cycle rather than every case every time; full sweeps run only on version change.
  2. **Batch the frontier Judge** — group ambiguous transcripts into batched requests; consider a
     cheaper Judge model (Haiku-class) with escalation to a larger model only on low confidence.
  3. **Shift more judgment left** — expand deterministic anchors so fewer cases reach any LLM at all.
  4. **Queue + rate-limit** target calls to respect the Co-Pilot's provider limits and smooth its bill.
- **Cost shape:** platform + judge cost scales with the *ambiguous sample*, not total attacks; target
  spend scales with sampled turns, bounded by the cap.

## Tier 4 — 100,000 runs (fleet / many targets)

- **Binding constraint:** aggregate target-induced spend across all targets, Judge throughput, and
  storage/observability volume.
- **Architecture change:**
  1. **Tiered judging** — deterministic → (optionally) a calibrated lightweight classifier → frontier
     LLM only on the residual (see the deferred judge-cascade plan). Most items never reach the
     frontier model.
  2. **Horizontal workers** — many local-model workers; the graph runs as a distributed job, not one
     process.
  3. **Aggressive sampling + prioritization** — spend attack budget where coverage is thin or findings
     are open; deprioritize categories with long clean streaks.
  4. **Spend governance** — hard spend limits on both the platform's frontier account and each target's
     account; alerts on cost-scaling rate.
  5. **Storage tiering** — roll up old events; keep the exploit DB queryable, archive raw transcripts.
- **Cost shape:** near-flat frontier cost per marginal run (most decided locally/deterministically);
  target spend is the dominant, explicitly-capped line item.

---

## The one-line cost thesis

Because attack generation is local ($0), judging is pre-filtered (frontier only on the ambiguous
minority), and coverage is sampled by risk at scale, **the platform's cost grows far slower than the
number of runs** — and the largest cost (the target answering) is bounded by design, which is also
exactly the denial-of-wallet property we red-team the target for.

---

## Cost tracking in-product

The observability layer records **cost per run and the rate cost is scaling** (a mandated dashboard
metric), and the router asserts $0 in local-only. Three alerts guard cost/latency/failure so a run that
starts spending abnormally is caught, not discovered on a bill.
