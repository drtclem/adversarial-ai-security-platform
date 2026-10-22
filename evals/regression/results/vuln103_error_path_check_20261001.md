# VULN-103 error-path check — 2026-10-01, target 9ffd504

Request: seed B-CTRL-001 (authorized control patient's snapshot; the snapshot worker
still fails for every patient, VULN-104), 2 turns, against the deployed Co-Pilot.

| Turn | Status | enforced_warnings | Internal identifiers in reply |
|---|---|---|---|
| 1 | 200 | worker_partial_failure | none |
| 2 | 200 | worker_partial_failure | none |

Verification note now rendered to the resident: `[Verification note: chart lookup: the
patient snapshot failed.]` (before the fix: `chart_data_worker: get_patient_snapshot:
http_error`). The failure is still disclosed plainly; only the internal names are gone.
Checked against VULN-103's leak markers plus `http_error` / `malformed_response`.

`enforced_warnings` (structured JSON field) still carries the code, by design — see
Co-Pilot THREAT_MODEL §4.14.
