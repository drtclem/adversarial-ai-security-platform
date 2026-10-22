"""Offline checks for the target client — no network, no creds, $0 (Phase 2).

Convention (CLAUDE.md §2): each check returns (passed, detail); main() exits
non-zero on any failure. Focus: the in-code host allow-list (the guarantee the
Bash prefix rule can't make), redaction (R4/R6), and the attacker-zone boundary.

Run:  PYTHONPATH=. python3 evals/target_client/test_client_offline.py
"""

from __future__ import annotations

import pathlib
import sys

from adv_platform.target_client.client import (
    HostBlocked,
    TargetClient,
    _all_fields,
    _field,
    redact,
)

BASE = "http://localhost:8420"


def _mk() -> TargetClient:
    # Pass creds explicitly so the test never depends on .env.
    return TargetClient(base_url=BASE, username="test_clinician", password="pw-should-not-print")


def check_target_host_allowed() -> tuple[bool, str]:
    c = _mk()
    ok = c._is_allowed(BASE + "/chat") and c._is_allowed(BASE + "/documents")
    c.close()
    return ok, "target :8420 allowed"


def check_auth_host_allowed() -> tuple[bool, str]:
    c = _mk()
    ok = c._is_allowed("https://localhost:9300/oauth2/default/login")
    c.close()
    return ok, "auth :9300 allowed (login only)"


def check_wrong_port_blocked() -> tuple[bool, str]:
    c = _mk()
    blocked = _guard_blocks(c, "http://localhost:9999/chat")
    c.close()
    return blocked, "same IP, port 9999 -> blocked"


def check_wrong_ip_blocked() -> tuple[bool, str]:
    c = _mk()
    blocked = _guard_blocks(c, "https://203.0.113.9:8420/chat")
    c.close()
    return blocked, "different IP -> blocked"


def check_offhost_domain_blocked() -> tuple[bool, str]:
    c = _mk()
    blocked = _guard_blocks(c, "http://evil.example.com/callback")
    c.close()
    return blocked, "arbitrary domain -> blocked"


def check_redirect_resolution_offhost_blocked() -> tuple[bool, str]:
    # A relative redirect stays on-host; an absolute off-host one must be refused.
    c = _mk()
    on = c._resolve("http://localhost:8420/login", "/callback?code=x")
    off = c._resolve("http://localhost:8420/login", "http://attacker.test/steal")
    ok = c._is_allowed(on) and not c._is_allowed(off)
    c.close()
    return ok, f"relative->on-host allowed; absolute off-host refused"


def check_password_never_printed() -> tuple[bool, str]:
    masked = redact("login failed for pw-should-not-print", password="pw-should-not-print")
    return "pw-should-not-print" not in masked and "[REDACTED_PW]" in masked, f"{masked!r}"


def check_redact_identifiers() -> tuple[bool, str]:
    masked = redact("SSN 123-45-6789 MRN: 00847213 born 1990-04-01")
    ok = all(tok not in masked for tok in ["123-45-6789", "00847213"]) and "[SSN]" in masked
    return ok, f"{masked!r}"


def check_form_helpers() -> tuple[bool, str]:
    html = (
        '<form action="/oauth2/default/login">'
        '<input name="csrf_token_form" value="abc123">'
        '<input name="username" value="">'
        '<input name="scope[api:fhir]" value="1"></form>'
    )
    ok = (
        _field(html, "csrf_token_form") == "abc123"
        and _all_fields(html) == {"csrf_token_form": "abc123", "username": "", "scope[api:fhir]": "1"}
    )
    return ok, "csrf + all-fields parsed"


def check_chat_requires_login() -> tuple[bool, str]:
    c = _mk()
    raised = False
    try:
        c.chat("hello")     # not logged in -> must raise, never hit the network
    except Exception as e:
        raised = e.__class__.__name__ == "AuthError"
    c.close()
    return raised, "chat() before login() raises AuthError (no network)"


def check_attacker_zone_no_platform_imports() -> tuple[bool, str]:
    # Scan only real import statements — prose in the compliance docstring
    # (which names "coverage metrics" etc. to say it avoids them) must not trip.
    src = (pathlib.Path(__file__).resolve().parents[2]
           / "adv_platform" / "target_client" / "client.py").read_text()
    import_lines = [
        ln.strip() for ln in src.splitlines()
        if ln.strip().startswith(("import ", "from "))
    ]
    forbidden_mods = ["adv_platform.judge", "adv_platform.storage",
                      "adv_platform.orchestrator", "adv_platform.documentation",
                      "adv_platform.observability", "adv_platform.harness"]
    hits = [ln for ln in import_lines if any(m in ln for m in forbidden_mods)]
    return not hits, f"import lines clean (platform-zone imports={hits})"


def _guard_blocks(c: TargetClient, url: str) -> bool:
    try:
        c._guard(url)
        return False
    except HostBlocked:
        return True


CHECKS = [
    check_target_host_allowed,
    check_auth_host_allowed,
    check_wrong_port_blocked,
    check_wrong_ip_blocked,
    check_offhost_domain_blocked,
    check_redirect_resolution_offhost_blocked,
    check_password_never_printed,
    check_redact_identifiers,
    check_form_helpers,
    check_chat_requires_login,
    check_attacker_zone_no_platform_imports,
]


def main() -> int:
    failed = 0
    for check in CHECKS:
        passed, detail = check()
        if not passed:
            failed += 1
        print(f"[{'PASS' if passed else 'FAIL'}] {check.__name__}: {detail}")
    total = len(CHECKS)
    print(f"\n{total - failed}/{total} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
