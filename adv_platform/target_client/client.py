"""Target client — ATTACKER ZONE.

Encapsulates the authenticated round-trip Phase 0 mapped against the live
Co-Pilot: OpenEMR OAuth2 authorization-code login (+ consent), the `copilot_session`
cookie, `POST /chat {"message": ...}`, multi-turn, and document upload.

HARD RULES honored (CLAUDE.md §1):
  - ATTACKER ZONE: stdlib + httpx only. NO platform-zone imports (no exploit DB,
    coverage metrics, version signal, or judge). The Red Team maps our raw results
    into `Transcript` on its side.
  - **Host allow-list is enforced HERE, in code** — not by any Bash permission rule
    (a command-prefix rule cannot scope by URL). Every request and every redirect
    hop is checked against {target `:8420`, its OWN OAuth server `:9300`}. `:9300` is
    allow-listed for LOGIN ONLY; nothing follows a redirect off these hosts (R9).
  - Never print the password (R6); redact identifiers before logging (R4).

This module makes NO network call at import time. The single operational entry
point is `run_client.py` (the one command the local allow-rule permits).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


# ─────────────────────────────────────────────────────────────────────────────
# Errors (typed; the Red Team maps these to PlatformError on the platform side)
# ─────────────────────────────────────────────────────────────────────────────
class HostBlocked(Exception):
    """A request/redirect targeted a host outside the allow-list (R9)."""


class AuthError(Exception):
    """Login did not establish an authenticated session."""


class TargetUnreachable(Exception):
    """The target host could not be reached / timed out."""


# ─────────────────────────────────────────────────────────────────────────────
# Redaction for safe logging (attacker-zone local copy; the judge has its own)
# ─────────────────────────────────────────────────────────────────────────────
_REDACT: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "[DATE]"),
    (re.compile(r"\bMRN[:\s#]*\d+\b", re.I), "[MRN]"),
    (re.compile(r"\b\d{6,10}\b"), "[ID]"),
]


def redact(text: object, password: str = "", limit: int = 400,
           canaries: Optional[list[str]] = None) -> str:
    s = text if isinstance(text, str) else str(text)
    for pat, repl in _REDACT:
        s = pat.sub(repl, s)
    # Mask known non-authorized identifiers (case-insensitive) so a successful
    # leak never prints raw to the console (R4).
    for c in canaries or []:
        if c:
            s = re.compile(re.escape(c), re.IGNORECASE).sub("[CANARY]", s)
    if password:
        s = s.replace(password, "[REDACTED_PW]")
    s = s.replace("\n", " ").strip()
    return (s[:limit] + "…") if len(s) > limit else s


# ─────────────────────────────────────────────────────────────────────────────
# HTML form helpers (login/consent pages)
# ─────────────────────────────────────────────────────────────────────────────
def _field(html: str, name: str) -> Optional[str]:
    m = re.search(rf'name=["\']{re.escape(name)}["\'][^>]*value=["\']([^"\']*)["\']', html, re.I)
    if not m:
        m = re.search(rf'value=["\']([^"\']*)["\'][^>]*name=["\']{re.escape(name)}["\']', html, re.I)
    return m.group(1) if m else None


def _all_fields(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", html, re.I):
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        if not nm:
            continue
        vm = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        out[nm.group(1)] = vm.group(1) if vm else ""
    return out


def _form_action(html: str) -> Optional[str]:
    m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ChatResult:
    """Raw, parsed `/chat` response (SHAPES the Judge cares about live here)."""

    status_code: int
    conversation_id: Optional[str] = None
    correlation_id: Optional[str] = None      # the TARGET's own correlation id
    response: str = ""
    verification_passed: Optional[bool] = None
    flagged_claims: list[Any] = field(default_factory=list)
    enforced_warnings: list[Any] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def meta(self) -> dict[str, Any]:
        """The subset of signals the deterministic judge reads from a target turn."""
        return {
            "verification_passed": self.verification_passed,
            "flagged_claims": self.flagged_claims,
            "enforced_warnings": self.enforced_warnings,
            "target_correlation_id": self.correlation_id,
        }


# ─────────────────────────────────────────────────────────────────────────────
# The client
# ─────────────────────────────────────────────────────────────────────────────
class TargetClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        *,
        auth_host: str = "localhost:9300",
        timeout: float = 25.0,
        verify: bool = False,
        user_agent: str = "adv-platform-client/0.1",
    ) -> None:
        self.base = (base_url or os.environ.get("TARGET_BASE_URL", "")).rstrip("/")
        if not self.base:
            raise ValueError("TARGET_BASE_URL is required (set in .env or pass base_url).")
        self.username = (username if username is not None else os.environ.get("TARGET_USERNAME", "")).strip()
        self.password = password if password is not None else os.environ.get("TARGET_PASSWORD", "")
        self.target_host = urlparse(self.base).netloc
        self.auth_host = auth_host
        # The ONLY hosts this client may ever contact. `:9300` = login only (R9).
        self.allow: set[str] = {self.target_host, self.auth_host}
        # Connection handling only: the multi-hop OAuth login reuses same-host
        # connections (:9300 twice), and a keep-alive socket Apache closes between
        # hops surfaces as httpx.RemoteProtocolError ("server disconnected without
        # sending a response"). Disable keep-alive reuse so every hop opens a fresh
        # connection (deterministic), and retry transient connect failures. verify
        # lives on the transport since a custom transport ignores Client(verify=...).
        transport = httpx.HTTPTransport(
            verify=verify,
            retries=2,
            limits=httpx.Limits(max_keepalive_connections=0),
        )
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,       # we follow manually so we can gate every hop
            headers={"User-Agent": user_agent},
            transport=transport,
        )
        self.authenticated = False

    # ---- host allow-list (the security-critical core) -----------------------
    def _is_allowed(self, url: str) -> bool:
        return urlparse(url).netloc in self.allow

    def _guard(self, url: str) -> None:
        if not self._is_allowed(url):
            raise HostBlocked(f"off-host request refused (R9): {urlparse(url).netloc}")

    def _resolve(self, current_url: str, location: str) -> str:
        """Absolutise a redirect Location against the current URL."""
        if location.startswith("http"):
            return location
        cur = urlparse(current_url)
        return f"{cur.scheme}://{cur.netloc}{location}"

    def _send(self, method: str, url: str, **kw: Any) -> httpx.Response:
        """Single request with a one-time retry on a stale keep-alive socket.
        Connection handling only — does NOT touch host-guard or auth logic."""
        try:
            return self._client.request(method, url, **kw)
        except httpx.RemoteProtocolError:
            # server closed a reused connection before responding — retry once fresh
            return self._client.request(method, url, **kw)

    def _hop(self, method: str, url: str, *, max_hops: int = 12, **kw: Any) -> httpx.Response:
        """Issue a request, then follow redirects manually — refusing any off-host hop."""
        self._guard(url)
        hops = 0
        while True:
            try:
                r = self._send(method, url, **kw)
            except httpx.HTTPError as e:
                raise TargetUnreachable(f"{type(e).__name__}: {e}") from e
            kw, method = {}, "GET"           # subsequent hops are plain GETs
            if not r.is_redirect:
                return r
            loc = r.headers.get("location", "")
            nxt = self._resolve(str(r.url), loc)
            self._guard(nxt)                 # <-- every redirect target is checked
            url = nxt
            hops += 1
            if hops > max_hops:
                return r

    # ---- auth ---------------------------------------------------------------
    def login(self) -> bool:
        """Run the OAuth authorization-code + consent flow; set `copilot_session`."""
        if not (self.username and self.password):
            raise AuthError("missing TARGET_USERNAME / TARGET_PASSWORD")

        # [A] login page + CSRF
        r = self._hop("GET", self.base + "/login")
        html = r.text
        csrf = _field(html, "csrf_token_form")
        action = _form_action(html) or "/oauth2/default/login"
        login_url = f"https://{self.auth_host}{action}" if action.startswith("/") else action

        # [B] submit credentials
        data = {
            "csrf_token_form": csrf or "",
            "user_role": "api",
            "email": "",
            "username": self.username,
            "password": self.password,
            "persist_login": "0",
        }
        r = self._hop("POST", login_url, data=data)
        h = r.text
        landed_path = urlparse(str(r.url)).path
        names = set(re.findall(r'<(?:button|input)[^>]*name=["\']([^"\']+)["\']', h, re.I))
        consent = (
            "scope-authorize" in landed_path
            or "authorize-confirm" in landed_path
            or "proceed" in names
            or bool(re.search(r'name=["\']scope\[', h, re.I))
        )

        # [B2] consent / scope-authorize screen -> submit faithfully (proceed=1)
        if consent and re.search(r"<form", h, re.I):
            caction = _form_action(h) or action
            curl = caction if caction.startswith("http") else f"https://{self.auth_host}{caction}"
            cdata = _all_fields(h)
            cdata.setdefault("csrf_token_form", _field(h, "csrf_token_form") or "")
            cdata["proceed"] = "1"
            self._hop("POST", curl, data=cdata)

        # [C] verify session
        r_ui = self._hop("GET", self.base + "/ui")
        self.authenticated = r_ui.status_code == 200 and "copilot_session" in self._client.cookies.keys()
        if not self.authenticated:
            raise AuthError(
                f"session not established (GET /ui -> {r_ui.status_code}, "
                f"cookies={list(self._client.cookies.keys())})"
            )
        return True

    # ---- chat ---------------------------------------------------------------
    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        """POST /chat with the confirmed `{\"message\": ...}` shape."""
        if not self.authenticated:
            raise AuthError("call login() before chat()")
        body: dict[str, Any] = {"message": message}
        if conversation_id:
            body["conversation_id"] = conversation_id   # multi-turn threading (unverified live)
        self._guard(self.base + "/chat")
        try:
            r = self._send("POST", self.base + "/chat", json=body)
        except httpx.HTTPError as e:
            raise TargetUnreachable(f"{type(e).__name__}: {e}") from e
        j: dict[str, Any] = {}
        try:
            j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        except Exception:
            j = {}
        return ChatResult(
            status_code=r.status_code,
            conversation_id=j.get("conversation_id"),
            correlation_id=j.get("correlation_id"),
            response=j.get("response", "") or "",
            verification_passed=j.get("verification_passed"),
            flagged_claims=j.get("flagged_claims") or [],
            enforced_warnings=j.get("enforced_warnings") or [],
            raw=j,
        )

    def chat_sequence(self, messages: list[str]) -> list[ChatResult]:
        """Multi-turn: thread the conversation_id the target returns across turns."""
        results: list[ChatResult] = []
        conv: Optional[str] = None
        for msg in messages:
            res = self.chat(msg, conversation_id=conv)
            conv = res.conversation_id or conv
            results.append(res)
        return results

    # ---- upload -------------------------------------------------------------
    def upload(self, filename: str, content: bytes, content_type: str = "text/plain") -> httpx.Response:
        """POST /documents (multipart). Endpoint existence confirmed in Phase 0;
        exact field name is unverified live — adjust once the first upload round-trips."""
        if not self.authenticated:
            raise AuthError("call login() before upload()")
        url = self.base + "/documents"
        self._guard(url)
        try:
            return self._send("POST", url, files={"file": (filename, content, content_type)})
        except httpx.HTTPError as e:
            raise TargetUnreachable(f"{type(e).__name__}: {e}") from e

    # ---- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TargetClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
