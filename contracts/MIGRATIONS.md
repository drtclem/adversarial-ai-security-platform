# Contract migrations

## v1 — 2026-09-30 (first published version)

First publication of the JSON Schema mirror. The Pydantic contracts existed since Phase 1;
these fields were added before publication, all **additive** (optional, defaulted), so every
record written earlier still validates and no data migration is needed:

| Message | Field(s) | Added | Why |
|---|---|---|---|
| `AttackCase` | `severity`, `exploitability`, `exploitability_note` | 2026-09-30 | Reviewer: rate each seed case, not only the reports |
| `AttackCase` | `owasp_web`, `test_design` | 2026-09-30 | Map each case to classic OWASP; state what it exercises |
| `Verdict` | `shadow` | 2026-09-30 | Record the classifier tier's opinion (shadow mode) |
| `ErrorType` | (unchanged) | — | The five spec error types + `model_refused`, `local_model_unavailable` |

Stored data: the exploit DB keeps each `Finding` as a JSON blob plus indexed columns, and
findings are read with `model_validate_json`, so records written before an additive field
existed load with the field's default. A breaking change would need a `v2/` directory and a
one-off script that rewrites stored blobs; none has been needed.
