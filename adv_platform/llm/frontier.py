"""Frontier model backend (paid Anthropic API) — PLATFORM_ZONE.

Used ONLY in `live` mode, and ONLY for the Judge and Documentation agents.

THE HARD RULE (CLAUDE.md §0.5): this client must refuse to make a call whenever the
platform is not in `live` mode (i.e. whenever `config.dry_run` is True). A paid call
in the wrong mode is a bug, not an option — so we raise before any network/SDK use.
"""

from __future__ import annotations

from typing import Optional

from adv_platform.config import Config
from adv_platform.llm.base import (
    FrontierRefusedInDryRun,
    LLMError,
    LLMResponse,
    estimate_cost_usd,
    estimate_tokens,
)
from adv_platform.models import AgentRole


class FrontierClient:
    """Anthropic client that hard-refuses to spend outside `live` mode."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def _guard_dry_run(self) -> None:
        # First line of defense: never spend unless explicitly live.
        if self.config.dry_run:
            raise FrontierRefusedInDryRun(
                f"Refusing paid call: PLATFORM_MODE={self.config.platform_mode.value} "
                f"(dry_run=True). Frontier calls are only allowed in `live` mode."
            )

    def complete(
        self,
        role: AgentRole,
        prompt: str,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        self._guard_dry_run()  # <-- refuses in local-only / dry_run

        if role not in (AgentRole.JUDGE, AgentRole.DOCUMENTATION):
            # Red Team + Orchestrator are ALWAYS local (CLAUDE.md §0.2). Defense in depth.
            raise LLMError(f"Frontier is not permitted for role={role.value} (must be local).")

        use_model = model or (
            self.config.judge_model if role == AgentRole.JUDGE else self.config.doc_model
        )
        if not use_model:
            raise LLMError(f"No frontier model configured for role={role.value}.")
        if not self.config.anthropic_api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set; cannot make a live call.")

        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise LLMError("anthropic SDK not installed (pip install -r requirements.txt).") from e

        client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
        kwargs = {
            "model": use_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system

        msg = client.messages.create(**kwargs)
        # Only real text blocks: newer models can return other block types (e.g. thinking)
        # that the pinned SDK surfaces with text=None.
        text = "".join(b.text for b in msg.content
                       if getattr(b, "type", "") == "text" and isinstance(getattr(b, "text", None), str))
        tokens_in = getattr(getattr(msg, "usage", None), "input_tokens", None) or estimate_tokens(
            (system or "") + prompt
        )
        tokens_out = getattr(getattr(msg, "usage", None), "output_tokens", None) or estimate_tokens(
            text
        )
        cost = estimate_cost_usd(use_model, tokens_in, tokens_out)

        return LLMResponse(
            text=text,
            role=role,
            model=use_model,
            backend="frontier",
            tokens_in=int(tokens_in),
            tokens_out=int(tokens_out),
            cost_usd=cost,
            meta={"stop_reason": getattr(msg, "stop_reason", "")},
        )
