"""Phase 0 authenticated recon (DEV-ONLY) — ATTACKER ZONE.

Completes the recon that `probe.py` couldn't: drives the OpenEMR OAuth2
authorization-code + PKCE-less* login discovered in Phase 0, establishes a session,
then does ONE benign chat POST to learn the `/chat` request/response shape and probes
for an upload endpoint. (*the browser flow uses PKCE; a confidential server-side client
may not need it — this script discovers which.)

Run it YOURSELF so no permission prompt is needed and creds stay in .env:
    ! PYTHONPATH=. python3 adv_platform/target_client/probe_auth.py

HARD RULES honored (CLAUDE.md §1):
  - ATTACKER ZONE: stdlib + httpx only; no platform-zone imports.
  - Benign only: ONE chat message ("hello, this is a connectivity test"), no attacks.
  - Host allow-list = {:8420 target, :9300 its OWN OAuth server} — nothing else (R9).
  - SHAPES ONLY in output; PHI/identifiers redacted (R4); password never printed (R6).
"""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlparse

import httpx

try:
    from dotenv import load_dotenv

    load_dotenv(".env")  # explicit: stdin/CLI scripts have no __file__ anchor
except Exception:
    pass

BASE = os.environ.get("TARGET_BASE_URL", "http://localhost:8420").rstrip("/")
TARGET_HOST = urlparse(BASE).netloc
AUTH_HOST = "localhost:9300"          # the target's OWN OpenEMR OAuth server
ALLOW = {TARGET_HOST, AUTH_HOST}
U = os.environ.get("TARGET_USERNAME", "").strip()
P = os.environ.get("TARGET_PASSWORD", "")

_REDACT = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "[DATE]"),
    (re.compile(r"\bMRN[:\s#]*\d+\b", re.I), "[MRN]"),
    (re.compile(r"\b\d{6,10}\b"), "[ID]"),
]


def redact(text: object, limit: int = 400) -> str:
    s = text if isinstance(text, str) else str(text)
    for pat, repl in _REDACT:
        s = pat.sub(repl, s)
    if P:
        s = s.replace(P, "[REDACTED_PW]")
    s = s.replace("\n", " ").strip()
    return (s[:limit] + "…") if len(s) > limit else s


def field(html: str, name: str) -> str | None:
    m = re.search(rf'name=["\']{re.escape(name)}["\'][^>]*value=["\']([^"\']*)["\']', html, re.I)
    if not m:
        m = re.search(rf'value=["\']([^"\']*)["\'][^>]*name=["\']{re.escape(name)}["\']', html, re.I)
    return m.group(1) if m else None


def all_fields(html: str) -> dict[str, str]:
    """Serialize every <input> (name -> value) so we can re-POST a form faithfully."""
    out: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", html, re.I):
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        if not nm:
            continue
        vm = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        out[nm.group(1)] = vm.group(1) if vm else ""
    return out


class HostBlocked(Exception):
    pass


def main() -> int:
    if not (U and P):
        print("No creds in .env (TARGET_USERNAME / TARGET_PASSWORD). Fill them and re-run.")
        return 2

    print("=" * 72)
    print(f"Authenticated recon — target {BASE}, user='{U}' (password withheld)")
    print("=" * 72)

    client = httpx.Client(timeout=25.0, verify=False, follow_redirects=False,
                          headers={"User-Agent": "adv-platform-probe/0.0"})

    def hop(method: str, url: str, **kw):
        """Follow redirects manually, refusing any hop off the allow-list (R9)."""
        n = 0
        while True:
            r = client.request(method, url, **kw)
            kw = {}
            method = "GET"
            host = urlparse(str(r.url)).netloc
            print(f"    {r.request.method:4s} {host}{urlparse(str(r.url)).path} -> {r.status_code}")
            if r.is_redirect:
                loc = r.headers.get("location", "")
                full = loc if loc.startswith("http") else f"{urlparse(str(r.url)).scheme}://{host}{loc}"
                if urlparse(full).netloc not in ALLOW:
                    print(f"      OFF-HOST {urlparse(full).netloc} -> refused (R9)")
                    raise HostBlocked(full)
                url = full
                n += 1
                if n > 12:
                    print("      too many redirects")
                    return r
                continue
            return r

    # [A] load login page + CSRF
    print("[A] GET /login -> OpenEMR login page")
    r = hop("GET", BASE + "/login")
    html = r.text
    csrf = field(html, "csrf_token_form")
    m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
    action = m.group(1) if m else "/oauth2/default/login"
    login_url = f"https://{AUTH_HOST}{action}" if action.startswith("/") else action
    print(f"    csrf_present={bool(csrf)} form_action={action}")

    # [B] submit credentials
    print("[B] POST credentials")
    data = {"csrf_token_form": csrf or "", "user_role": "api", "email": "",
            "username": U, "password": P, "persist_login": "0"}
    try:
        r = hop("POST", login_url, data=data)
    except HostBlocked:
        print("    login redirected off-host; stopping.")
        return 1
    h = r.text
    title = re.findall(r"<title>(.*?)</title>", h, re.I)
    forms = re.findall(r"<form[^>]*>", h, re.I)
    names = sorted(set(re.findall(r'<(?:button|input)[^>]*name=["\']([^"\']+)["\']', h, re.I)))
    landed_path = urlparse(str(r.url)).path
    landed = f"{urlparse(str(r.url)).netloc}{landed_path}"
    # Consent detected by the scope-authorize page, a `proceed` control, or scope[...] fields.
    consent = ("scope-authorize" in landed_path) or ("authorize-confirm" in landed_path) \
        or ("proceed" in names) or bool(re.search(r'name=["\']scope\[', h, re.I))
    print(f"    landed={landed} status={r.status_code} title={title} forms={len(forms)} consent_like={consent}")
    print(f"    field names on page={names[:15]}")

    # [B2] consent/scope-authorize screen: submit the form faithfully (proceed=1 + all scopes)
    if consent and forms:
        print("[B2] consent/scope screen -> submitting the authorize form (proceed)")
        m2 = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', h, re.I)
        caction = m2.group(1) if m2 else action
        curl = caction if caction.startswith("http") else f"https://{AUTH_HOST}{caction}"
        cdata = all_fields(h)                     # keep csrf + all scope[...] values
        cdata.setdefault("csrf_token_form", field(h, "csrf_token_form") or "")
        cdata["proceed"] = "1"                    # click "Authorize"/"Continue"
        try:
            r = hop("POST", curl, data=cdata)
        except HostBlocked:
            print("    consent redirected off-host; stopping.")
            return 1
        print(f"    after consent: landed={urlparse(str(r.url)).netloc}{urlparse(str(r.url)).path} status={r.status_code}")

    # [C] session state
    cookies = list(client.cookies.keys())
    print(f"[C] cookies after login: {cookies}")
    r_ui = client.get(BASE + "/ui")
    authed = r_ui.status_code == 200
    print(f"[C] GET /ui -> {r_ui.status_code} (authenticated_session={authed})")

    # [D] discover POST /chat shape via a benign message
    print("[D] POST /chat — benign connectivity message, discover request/response shape")
    benign = "hello, this is a connectivity test"
    candidates = [
        {"message": benign},
        {"query": benign},
        {"prompt": benign},
        {"messages": [{"role": "user", "content": benign}]},
        {"text": benign},
    ]
    chat_shape = None
    for body in candidates:
        try:
            rc = client.post(BASE + "/chat", json=body)
        except httpx.HTTPError as e:
            print(f"    body keys {list(body)} -> ERROR {type(e).__name__}")
            continue
        ct = rc.headers.get("content-type", "")
        print(f"    body keys {list(body)} -> {rc.status_code} {ct.split(';')[0]}")
        if rc.status_code == 422:
            # FastAPI validation error names the required fields — pure shape, no PHI
            try:
                print(f"        422 detail: {redact(json.dumps(rc.json().get('detail', rc.json())), 300)}")
            except Exception:
                pass
        if rc.status_code == 200:
            try:
                j = rc.json()
                chat_shape = {"request_keys": list(body), "response_keys": list(j) if isinstance(j, dict) else type(j).__name__}
                print(f"        200 response keys={chat_shape['response_keys']}")
                print(f"        response sample (redacted): {redact(json.dumps(j), 300)}")
            except Exception:
                print(f"        200 non-json (redacted): {redact(rc.text, 200)}")
            break

    # [E] probe for an upload endpoint (existence only; no file sent yet)
    print("[E] upload endpoint discovery (existence only)")
    for path in ["/upload", "/api/upload", "/documents", "/document", "/chat/upload", "/files"]:
        try:
            ro = client.request("OPTIONS", BASE + path)
            allow = ro.headers.get("allow", "")
            rg = client.get(BASE + path)
            print(f"    {path}: OPTIONS {ro.status_code} allow='{allow}' | GET {rg.status_code}")
        except httpx.HTTPError as e:
            print(f"    {path}: ERROR {type(e).__name__}")

    print("\n" + "=" * 72)
    print("AUTH RECON SUMMARY (paste-ready; no PHI, no secrets):")
    print(json.dumps({
        "authenticated_session": authed,
        "session_cookies": cookies,
        "chat_endpoint": "POST /chat",
        "chat_shape": chat_shape,
    }, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
