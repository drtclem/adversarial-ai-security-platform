"""Local model backend (Ollama) — PLATFORM_ZONE, $0 always.

Powers the Red Team and Orchestrator in every mode, and ALL roles (including Judge
and Documentation) in local-only mode. Talks to Ollama over plain HTTP via httpx.

Cost is always $0.0 here — this is the whole point of local-only development.
"""

from __future__ import annotations

from typing import Optional

import httpx

from adv_platform.llm.base import (
    LLMResponse,
    LocalModelUnavailable,
    ModelRefused,
    estimate_tokens,
)
from adv_platform.models import AgentRole

# crude refusal detection — a refusing red team is a coverage hole; we LOG it (D2)
_REFUSAL_MARKERS = (
    "i can't help with that",
    "i cannot help with that",
    "i can't assist",
    "i cannot assist",
    "i'm not able to help",
    "i am not able to help",
    "as an ai",
    "i won't",
)


class LocalClient:
    """Thin Ollama client. Uses /api/chat (system + user)."""

    def __init__(self, base_url: str, model: str, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def health(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=10.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def available_models(self) -> list[str]:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=10.0)
            r.raise_for_status()
            return [m.get("name", "") for m in r.json().get("models", [])]
        except httpx.HTTPError as e:
            raise LocalModelUnavailable(f"Ollama unreachable at {self.base_url}: {e}") from e

    def complete(
        self,
        role: AgentRole,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.8,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
    ) -> LLMResponse:
        use_model = model or self.model
        if not use_model:
            raise LocalModelUnavailable("No LOCAL_MODEL configured (set it in .env / Phase 1).")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": use_model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens

        try:
            r = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        except httpx.HTTPError as e:
            raise LocalModelUnavailable(f"Ollama call failed at {self.base_url}: {e}") from e

        if r.status_code == 404:
            raise LocalModelUnavailable(
                f"Model '{use_model}' not found on Ollama (pull it first): {r.text[:200]}"
            )
        try:
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise LocalModelUnavailable(f"Ollama error {r.status_code}: {r.text[:200]}") from e

        body = r.json()
        text = (body.get("message") or {}).get("content", "")
        tokens_in = int(body.get("prompt_eval_count") or estimate_tokens((system or "") + prompt))
        tokens_out = int(body.get("eval_count") or estimate_tokens(text))

        refused = any(mk in text.lower() for mk in _REFUSAL_MARKERS)

        return LLMResponse(
            text=text,
            role=role,
            model=use_model,
            backend="local",
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=0.0,            # local is ALWAYS free (CLAUDE.md §0)
            refused=refused,
            meta={"done_reason": body.get("done_reason", "")},
        )
