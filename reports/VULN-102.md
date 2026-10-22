# VULN-102 — Cleartext transport (no HTTPS) on the deployed app (`:8420`)

| Field | Value |
|---|---|
| Severity | medium |
| OWASP / CWE | CWE-319 (Cleartext Transmission of Sensitive Information) — no OWASP-LLM category |
| Classification | Infrastructure / transport security (surfaced during Category B testing). |
| Status | **published** (approved via D4 human-approval gate) |
| Reviewer | taylor |
| Approved (UTC) | 2026-09-29T20:10:43.643268+00:00 |
| Approval fingerprint | `aeb86139b1c855e1…` |
| Evidence | evidence:probe_auth+config — cleartext http on :8420 (app); :9300 (OAuth) is HTTPS (PHI-redacted, R4) |

## Description

The deployed target application (`http://<deployed-host>:8420`) is served over plain HTTP, not HTTPS. The app port exposes no TLS listener, so every connection to it is plaintext. The session cookie (`copilot_session`) and any PHI in chat requests/responses therefore traverse the network in cleartext.
Scope correction (2026-09-29): the OAuth login server (`https://…:9300`) IS served over HTTPS (TLS 1.3 verified; the login redirect goes to `https://…:9300`), so credentials submitted at login are encrypted in transit. The cleartext exposure is the app on `:8420`: the session cookie issued after login and all chat traffic.

## Clinical impact

PHI in chat traffic and the `copilot_session` cookie are exposed to network eavesdropping / MITM on the path. A captured `copilot_session` cookie enables session hijacking. (Login credentials go to the OAuth server on `:9300`, which is HTTPS.) Severity is Medium as an accepted-risk lab environment with synthetic data; this would be HIGH in any real PHI production deployment.

## Minimal reproducible attack sequence (PHI-redacted, R4)

1. Observation (not an attack): the application base URL is `http://…:8420` and no TLS listener is present on that port; `GET /login` returns a 307 to `https://…:9300/oauth2/default/authorize` (HTTPS); after the OAuth callback, the `copilot_session` cookie and every `/chat` request/response travel over plain HTTP to `:8420`.

## Observed vs. expected

**Observed:** The application on `:8420` (session cookie and PHI-bearing chat traffic) is served over plaintext HTTP. The OAuth login server on `:9300` uses HTTPS.

**Expected:** TLS (HTTPS) on all application and auth endpoints; session cookies flagged Secure / HttpOnly / SameSite; HSTS enabled; HTTP→HTTPS redirect.

## Recommended remediation (named controls)

- Terminate TLS (HTTPS) on the app (`:8420`); the OAuth server already uses HTTPS.
- Mark session cookies Secure, HttpOnly, and SameSite.
- Enable HSTS and redirect HTTP→HTTPS.

## Status

Documented / accepted risk for the lab environment; reported for completeness. Recorded severity Medium (accepted-lab-risk); real-world PHI-production severity is HIGH — both framings retained. Corrected 2026-09-29: scope narrowed to the app on `:8420` (the `:9300` OAuth server is HTTPS); severity unchanged (Taylor); re-approved via the D4 gate.

## Fix validation results

- **Fix deployed:** No. Accepted risk for the lab environment.
- **How a fix is validated:** Black-box probe: `http://…:8420` must redirect to HTTPS (or refuse), and the session cookie must carry `Secure`.
- **Last result:** **Not validated — open (accepted risk).** 2026-09-29 probe: `:8420` serves cleartext HTTP; `:9300` (OAuth login) is HTTPS.
- **Re-validate when:** TLS is put in front of `:8420`.

---

_Routed through the deterministic D4 human-approval gate (R8): a finding reaches `published` ONLY via an explicit human decision recorded in the gate ledger and bound to a content fingerprint. No agent or model output can promote a finding._