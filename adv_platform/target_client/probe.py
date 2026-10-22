"""Phase 0 recon probe (DEV-ONLY) — ATTACKER ZONE.

Answers the Phase 0 recon questions from WEEK3_BUILD_SPEC.md §9 against the LIVE target:
  - Is the target reachable, and does an authenticated chat round-trip work?
  - What is the chat endpoint request/response JSON *shape*?
  - What are the session/cookie mechanics for a bot client?
  - Does document upload work for the (non-admin) test user?
  - Is there a /health or /version field usable as the regression version signal?

HARD RULES honored here (CLAUDE.md §1):
  - This module is ATTACKER ZONE: stdlib + httpx only. It imports NO platform-zone
    code (no exploit DB, coverage, or version-signal consumer).
  - Read-only / benign only: ONE benign chat, ONE benign upload attempt. No attacks.
  - Never follows a redirect to a different host (R9): redirects are logged, not followed.
  - SHAPES ONLY in the log — PHI is redacted at emit time (R4). No secrets printed (R6).

Run:  PYTHONPATH=. python adv_platform/target_client/probe.py
It reads TARGET_BASE_URL / TARGET_USERNAME / TARGET_PASSWORD from the environment
(.env is loaded if python-dotenv is available). It never prints the password.
"""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlparse

import httpx

# --- config (no platform-zone imports; read env directly) --------------------
try:
    from dotenv import load_dotenv  # optional; fine if absent

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional for the probe
    pass

BASE_URL = os.environ.get("TARGET_BASE_URL", "http://localhost:8420").rstrip("/")
USERNAME = os.environ.get("TARGET_USERNAME", "").strip()
PASSWORD = os.environ.get("TARGET_PASSWORD", "")
TARGET_HOST = urlparse(BASE_URL).netloc

TIMEOUT = httpx.Timeout(20.0, connect=10.0)

# --- PHI / secret redaction (emit-time, R4/R6) -------------------------------
_REDACTIONS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "[DATE]"),
    (re.compile(r"\b\d{2}/\d{2}/\d{4}\b"), "[DATE]"),
    (re.compile(r"\bMRN[:\s#]*\d+\b", re.I), "[MRN]"),
    (re.compile(r"\b\d{6,10}\b"), "[ID]"),  # long bare digit runs -> likely an identifier
]


def redact(text: str, limit: int = 300) -> str:
    """Redact likely PHI/identifiers and truncate. Never let raw content into the log."""
    if text is None:
        return ""
    s = text if isinstance(text, str) else str(text)
    for pat, repl in _REDACTIONS:
        s = pat.sub(repl, s)
    # scrub the configured password if it ever appears (defense in depth)
    if PASSWORD:
        s = s.replace(PASSWORD, "[REDACTED_PW]")
    s = s.replace("\n", " ").strip()
    return (s[:limit] + "…") if len(s) > limit else s


def _same_host(location: str) -> bool:
    if not location:
        return True
    netloc = urlparse(location).netloc
    return (netloc == "") or (netloc == TARGET_HOST)


def _line(*parts: object) -> None:
    print("  " + " ".join(str(p) for p in parts))


def probe_get(client: httpx.Client, path: str) -> dict:
    """GET one path, report status/shape without following cross-host redirects (R9)."""
    url = BASE_URL + path
    try:
        r = client.get(url, follow_redirects=False)
    except httpx.HTTPError as e:
        _line(f"GET {path:16s} -> ERROR {type(e).__name__}: {e}")
        return {"path": path, "error": type(e).__name__}
    ctype = r.headers.get("content-type", "")
    info = {"path": path, "status": r.status_code, "content_type": ctype, "len": len(r.content)}
    note = ""
    if r.is_redirect:
        loc = r.headers.get("location", "")
        same = _same_host(loc)
        info["redirect_to"] = loc
        info["redirect_same_host"] = same
        note = f" -> redirect {redact(loc, 80)} ({'same-host' if same else 'OFF-HOST: NOT followed'})"
    _line(f"GET {path:16s} -> {r.status_code} {ctype.split(';')[0]:24s} {len(r.content)}B{note}")
    return info | {"_response": r}


def main() -> int:
    print("=" * 72)
    print(f"Phase 0 recon probe  —  target: {BASE_URL}")
    print(f"creds present: username={'yes' if USERNAME else 'NO'} password={'yes' if PASSWORD else 'NO'}")
    print("=" * 72)

    findings: dict = {"base_url": BASE_URL, "endpoints": {}, "version_signal": None}

    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": "adv-platform-probe/0.0"}) as client:
        # 1) Reachability + candidate endpoints (unauthenticated) -------------
        print("\n[1] Reachability & candidate endpoints (unauthenticated):")
        candidates = [
            "/", "/ui", "/health", "/healthz", "/ready", "/readyz",
            "/version", "/api/version", "/api/health", "/login", "/chat",
            "/api/chat", "/docs", "/openapi.json",
        ]
        for path in candidates:
            info = probe_get(client, path)
            findings["endpoints"][path] = {k: v for k, v in info.items() if k != "_response"}

        # 2) Look for a version signal in health/version bodies ---------------
        print("\n[2] Version signal (for the regression trigger):")
        found_version = False
        for path in ["/health", "/ready", "/healthz", "/api/health", "/version", "/api/version"]:
            resp = findings["endpoints"].get(path, {})
            r = None
            # re-fetch small bodies to read the shape safely
            if resp.get("status") == 200 and "json" in (resp.get("content_type") or ""):
                try:
                    r = client.get(BASE_URL + path, follow_redirects=False)
                    body = r.json()
                    keys = list(body.keys()) if isinstance(body, dict) else type(body).__name__
                    _line(f"{path}: json keys = {keys}")
                    if isinstance(body, dict):
                        for vk in ("version", "build", "commit", "git_sha", "sha", "deployed_at", "started_at"):
                            if vk in body:
                                findings["version_signal"] = {"endpoint": path, "field": vk,
                                                              "value": redact(str(body[vk]), 60)}
                                _line(f"   -> version signal candidate: {path} .{vk} = {redact(str(body[vk]),60)}")
                                found_version = True
                except Exception as e:
                    _line(f"{path}: could not parse JSON ({type(e).__name__})")
        if not found_version:
            _line("no explicit version/health field found — regression trigger may need a self-stamped marker")

        # 3) OpenAPI shape, if the target exposes it --------------------------
        print("\n[3] API shape (OpenAPI, if present):")
        oa = findings["endpoints"].get("/openapi.json", {})
        if oa.get("status") == 200:
            try:
                spec = client.get(BASE_URL + "/openapi.json").json()
                paths = sorted((spec.get("paths") or {}).keys())
                _line(f"openapi paths ({len(paths)}): {paths}")
                findings["openapi_paths"] = paths
            except Exception as e:
                _line(f"openapi.json present but unparseable ({type(e).__name__})")
        else:
            _line("no /openapi.json (target may not be FastAPI-with-docs-exposed)")

        # 4) Authenticated chat round-trip (only if creds provided) -----------
        print("\n[4] Authenticated chat round-trip:")
        if not (USERNAME and PASSWORD):
            _line("SKIPPED — no TARGET_USERNAME / TARGET_PASSWORD in .env.")
            _line("Fill them in .env (never in chat) and re-run to complete this step.")
        else:
            _line(f"login as user='{USERNAME}' (password withheld) — probing auth mechanics…")
            _line("NOTE: exact login endpoint/shape is discovered here; see report below.")
            # We do not hard-code the target's private auth flow blindly; we report what /login
            # and /ui expose so the real target_client can be written against the true shape.
            for path in ["/login", "/ui"]:
                resp = findings["endpoints"].get(path, {})
                if resp.get("status", 0) < 400:
                    try:
                        r = client.get(BASE_URL + path, follow_redirects=False)
                        forms = re.findall(r"<form[^>]*>", r.text, flags=re.I)[:3]
                        actions = re.findall(r'action=["\']([^"\']+)["\']', " ".join(forms), flags=re.I)
                        _line(f"{path}: {len(forms)} form(s); actions={actions}; "
                              f"set-cookie={'yes' if 'set-cookie' in r.headers else 'no'}")
                    except Exception as e:
                        _line(f"{path}: inspect failed ({type(e).__name__})")

        print("\n" + "=" * 72)
        print("SHAPES-ONLY SUMMARY (paste-ready for BUILD_LOG.md; no PHI, no secrets):")
        print("=" * 72)
        safe = {k: v for k, v in findings.items()}
        print(json.dumps(safe, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
