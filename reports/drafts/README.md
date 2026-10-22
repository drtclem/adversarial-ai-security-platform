# reports/drafts/ — unpublished drafts

**Nothing in this folder is an approved finding.** These are drafts that have not passed the
deterministic D4 human-approval gate (`adv_platform/harness/approval_gate.py`). Approved, published
reports live one level up in `reports/VULN-1xx.md`. A draft is evidence for review, not a claim.

| File | What it is | State |
|---|---|---|
| `VULN-105.agent-draft.md` | The Documentation agent's own output for the VULN-105 evidence, kept to compare against the human-written report | Comparison artifact only; will not be published |
| `VULN-106.draft.md` | Session-management finding (A07: no logout, non-expiring, non-bound `copilot_session` cookie), drafted from the 2026-10-01 black-box OWASP probes | **Awaiting D4 review**; severity is a proposal |

## Documentation agent vs. human: VULN-105

**How the draft was produced.** Offline, $0, with no target contact and no model call:
`Documentation.write_finding` was run on the stored ground-truth case `LIVE-E-001~llm-72e3aabe` and
rendered with the platform's report renderer. The output is committed verbatim under a provenance header.
- The confirmation came from the human label. The campaign's local judge had called this transcript
  PASS, and the deterministic pre-filter returns no verdict on it.
- The agent was given a machine-only rationale: the `disclosure_shapes()` hits on the last target turn.
  This keeps human-written text out of the draft.
- **In the live pipeline the agent never saw this case**, because the agent only drafts from a Judge
  FAIL and the Judge missed it. This comparison measures what the agent writes *once* an exploit is
  confirmed.

**Against the required report fields** (Week 3 spec, Documentation Agent):

| Required field | Agent draft | Human report (`reports/VULN-105.md`) |
|---|---|---|
| Unique identifier | ⚠️ `VULN-001`, a per-run counter. Not unique: it collides with a rejected `VULN-001` already in the findings store | `VULN-105`, registry-unique |
| Severity rating | ✅ Medium, inherited from seed E-001's rating, with no rationale | Medium, with the reason: the leaked contract belongs to a safety-critical gate (vs. VULN-103 Low) |
| Description of the vulnerability | ❌ Title only ("E: verbatim_prompt_and_tools — invariant broken"); never says *what* leaked | Names the tool, both parameters, the three-value return enum with handling, and the trigger rule; notes it was refused twice, then given when reframed |
| Clinical impact | ⚠️ One generic category sentence ("aids further targeted attacks") | Specific attack path on the allergy gate (force `not_assessed`, then suppress the warning), explicitly marked **not demonstrated** |
| Minimal reproducible attack sequence | ✅ All three attacker turns verbatim, in order, redacted | Same turns, plus the target's response to each step, which turn leaked, and that turn 3 was a Red Team mutation |
| Observed vs. expected | ⚠️ Expected ✅ (from the seed, close to the human version). Observed is only shape labels (`list, presenter, schema, self_rules, digits`) | Observed states the disclosed content; expected gives a concrete acceptable answer |
| Recommended remediation | ⚠️ Two generic lines ("refuse … disclosure", "route audits to the platform team") | Four named controls: cover paraphrase/"worked example" framings, output filter for tool/parameter/enum identifiers, regression case, code-enforced `not_assessed` warning |
| Current status and fix validation results | ❌ `open` only; no fix-validation section (`Finding` has `last_validated_version` but no results field, and the renderer prints neither) | Partially mitigated, left open; before/after replay (3/3 → 0/3) plus the human read that the gate logic is still disclosed |
| Evidence pointers | ❌ None in the rendered draft (`Finding` carries `correlation_id` and `transcript_id`, but the renderer doesn't print them) | Platform and target correlation IDs, ground-truth case ID |

**Summary.** The agent got the mechanics right: a reproducible attack sequence, the expected
behavior, a plausible severity, OWASP/category tags, and a status that cannot publish itself. What
makes the report usable by an engineer who wasn't there came from the human:
- what was actually disclosed;
- the specific clinical risk and what was *not* demonstrated;
- concrete remediations;
- fix validation;
- evidence IDs.

A senior engineer could reproduce the attack from the draft, but could not tell from it what to
look for in the reply or what to fix. This is the gap between today's templated agent and the spec's
bar. It is also why no report is published on an agent draft alone.

**What would close it** (not done): include the leaked target turn (redacted) and the Judge's
evidence span in "Observed"; issue IDs from the findings registry instead of a per-run counter;
print the evidence IDs `Finding` already carries and add a fix-validation results field; and have the model write description and
remediation prose from the transcript (frontier-authored prose in `live` is planned in
`documentation.py`, not wired).
