# VULN-106 (DRAFT) — Session-management weaknesses: no logout, non-expiring, non-bound session cookie

> **DRAFT — not published.** Surfaced by the 2026-10-01 black-box OWASP probes
> (`scripts/run_owasp_probes.py`, cases P-A07-001/002/003). Awaiting human review at the
> D4 gate before it becomes a published finding; severity below is a proposal.

| Field | Value |
|---|---|
| Proposed severity | Medium (Low in isolation; Medium combined with VULN-102 cleartext) |
| OWASP / CWE | A07 (Identification & Authentication Failures); CWE-613 (Insufficient Session Expiration), CWE-614 (Secure attribute), CWE-1018 (session not bound) |
| Classification | Authentication / session management — probe finding, not a chat attack |
| Status | **draft — not approved** |
| Evidence | `evals/probes/results/owasp_probes_live_20261001T182934Z.json` (P-A07-001/002/003) |

## Description

Black-box probes of the deployed Co-Pilot (`:8420`) found three session-management weaknesses:

1. **No logout.** `GET /logout` returns 404 — there is no way to end a session server-side. A
   `copilot_session` cookie stays valid until the service restarts.
2. **Cookie has no `Secure` flag and no expiry.** `Set-Cookie` for `copilot_session` is `HttpOnly`,
   `SameSite=Lax`, but carries no `Secure` and no `Max-Age`/`Expires`. (No `Secure` is the
   documented accepted-risk consequence of serving `:8420` over plain HTTP — see VULN-102.)
3. **Session is not bound to the client.** The same cookie, replayed from a different client with a
   different User-Agent, is accepted (`GET /me` → 200).

## Clinical impact

A captured `copilot_session` cookie grants an attacker an indefinite, fully usable clinician session:
there is no logout to revoke it, no expiry to age it out, and no client binding to reject it from a
different machine. Combined with VULN-102 (the cookie travels in cleartext on `:8420`), a network
eavesdropper can lift the cookie and reuse it against the clinical assistant until the service
restarts.

## Minimal reproducible steps (black-box)

1. Log in as the test user; capture the `Set-Cookie: copilot_session=…` attributes → no `Secure`, no `Max-Age`/`Expires`.
2. `GET /logout` → 404.
3. Replay the cookie from a fresh client with a different User-Agent; `GET /me` → 200 (`authenticated: true`).

**Pending (P-A07-004):** re-test the saved session's lifetime after ≥12 h with
`scripts/run_owasp_probes.py --check-session`. If it is still valid, that confirms sessions never
expire while the service runs.

## Observed vs. expected

**Observed:** no logout; cookie without `Secure` or expiry; session usable from any client.

**Expected:** a logout that invalidates the session server-side; a cookie with `Secure` (once TLS
fronts `:8420`) and a bounded lifetime (absolute + idle); ideally session binding to reduce the value
of a stolen cookie.

## Recommended remediation (named controls)

- Add a `/logout` route that deletes the session from the server-side store.
- Set an absolute and idle session lifetime in the session store; reject aged sessions.
- Put TLS in front of `:8420` and set `Secure` on the cookie (shared remediation with VULN-102).
- Consider binding the session to a client fingerprint so a lifted cookie is less portable.

## Fix validation (how the platform would check it)

Re-run `scripts/run_owasp_probes.py --live` (P-A07-001/002/003) and `--check-session`: PASS requires a
working `/logout`, a `Secure` cookie with a bounded lifetime, and an aged/ported session rejected.
