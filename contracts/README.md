# Inter-agent contracts (v1)

Every message that crosses an agent boundary has a published, versioned JSON Schema
(draft 2020-12) here, so a producer or consumer in any language can validate a message
without importing our code. The Pydantic models in `adv_platform/models.py` are the
source of truth; `scripts/export_contracts.py` generates this directory from them.

| Message | Schema | Producer → Consumer |
|---|---|---|
| `CampaignBrief` | `v1/campaign_brief.schema.json` | Orchestrator → Red Team |
| `AttackCase` | `v1/attack_case.schema.json` | seed suite / mutator → Red Team |
| `Transcript` | `v1/transcript.schema.json` | Red Team → Judge (no Red Team reasoning, R7) |
| `Verdict` | `v1/verdict.schema.json` | Judge → Documentation, regression harness, Orchestrator |
| `Finding` | `v1/finding.schema.json` | Documentation → exploit DB, D4 human gate |
| `Event` | `v1/event.schema.json` | every agent → event store, Orchestrator, dashboard |
| `PlatformError` | `v1/platform_error.schema.json` | any agent → any agent (never scored as a pass, R11) |

**Error schemas** (`v1/errors/`): one per failure mode. The five the spec names
(`target_unreachable`, `budget_exceeded`, `judge_timeout`, `no_findings`,
`regression_detected`) plus our two local-model cases (`model_refused`,
`local_model_unavailable`). Each pins `type` to its value, so a mislabeled error fails.

`v1/index.json` lists every schema with its producer and consumer.

## Versioning

- Every schema carries `x-contract-version`. The directory name is the version.
- **Additive** change (new optional field, new enum value): regenerate in place and note it
  in `MIGRATIONS.md`.
- **Breaking** change (field removed, new required field, type changed or narrowed, enum
  value removed): new version directory (`v2/`), `MIGRATIONS.md` entry, updated contract tests.
- `scripts/export_contracts.py --check` exits 1 when the committed schemas no longer match the
  models, and says whether the drift is additive or breaking.

## Tests

`evals/contracts/test_contracts.py` checks both sides of every boundary: real producer output
(Orchestrator, Red Team, Judge, Documentation, event sink, typed errors) validates against the
published schema; the consumer's model accepts it unchanged; a message missing a required field
is rejected by both the schema and the consumer; and the committed schemas match the models.
