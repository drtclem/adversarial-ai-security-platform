"""The cost gate — PLATFORM_ZONE (CLAUDE.md §0, §4).

Routes each agent role to local or frontier by mode, tracks estimated spend, and
enforces the hard per-run budget cap. This is the single place that decides whether
money can be spent.

Routing table:
                       local-only            live
  Red Team             LOCAL                 LOCAL      (always local, §0.2)
  Orchestrator         LOCAL                 LOCAL      (always local, §0.2)
  Judge                LOCAL                 FRONTIER   (paid, pre-filtered)
  Documentation        LOCAL                 FRONTIER   (paid, rare)

Spend rules:
  - Local calls cost $0 (never touch the budget).
  - Before any frontier call, we project its cost; if that would exceed MAX_RUN_USD,
    we DO NOT call — we raise BudgetExceeded so the run stops gracefully (§0.4).
"""

from __future__ import annotations

from typing import Optional

from adv_platform.config import Config, PlatformMode
from adv_platform.llm.base import (
    BudgetExceeded,
    LLMResponse,
    estimate_cost_usd,
    estimate_tokens,
)
from adv_platform.llm.frontier import FrontierClient
from adv_platform.llm.local import LocalClient
from adv_platform.models import AgentRole

# roles that are ALWAYS local, in every mode (CLAUDE.md §0.2)
_ALWAYS_LOCAL = {AgentRole.REDTEAM, AgentRole.ORCHESTRATOR}
# roles that MAY use the paid frontier — but only in live mode
_FRONTIER_CAPABLE = {AgentRole.JUDGE, AgentRole.DOCUMENTATION}


class SpendTracker:
    """Accumulates estimated USD for one run and enforces the cap."""

    def __init__(self, cap_usd: float) -> None:
        self.cap_usd = cap_usd
        self.total_usd = 0.0
        self.calls = 0

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.cap_usd - self.total_usd)

    def would_exceed(self, projected_usd: float) -> bool:
        return (self.total_usd + projected_usd) > self.cap_usd

    def add(self, usd: float) -> None:
        self.total_usd += usd
        self.calls += 1


class LLMRouter:
    """Role- and mode-aware LLM dispatch with a hard budget cap."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.local = LocalClient(config.ollama_base_url, config.local_model)
        self.frontier = FrontierClient(config)
        self.spend = SpendTracker(config.max_run_usd)

    def backend_for(self, role: AgentRole) -> str:
        """Return 'local' or 'frontier' for this role under the current mode."""
        if role in _ALWAYS_LOCAL:
            return "local"
        if self.config.platform_mode == PlatformMode.LIVE and role in _FRONTIER_CAPABLE:
            return "frontier"
        return "local"  # local-only: EVERY role is local (Judge/Docs included)

    def complete(
        self,
        role: AgentRole,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: Optional[float] = None,
        model: Optional[str] = None,
    ) -> LLMResponse:
        backend = self.backend_for(role)

        if backend == "local":
            temp = 0.8 if temperature is None else temperature
            return self.local.complete(
                role, prompt, system=system, temperature=temp,
                max_tokens=max_tokens, model=model,
            )

        # frontier (live only) — project cost and enforce the cap BEFORE spending
        use_model = model or (
            self.config.judge_model if role == AgentRole.JUDGE else self.config.doc_model
        )
        projected = estimate_cost_usd(
            use_model, estimate_tokens((system or "") + prompt), max_tokens
        )
        if self.spend.would_exceed(projected):
            raise BudgetExceeded(
                f"Projected ${projected:.4f} would exceed cap ${self.config.max_run_usd:.2f} "
                f"(spent ${self.spend.total_usd:.4f}). Stopping run gracefully."
            )

        temp = 0.0 if temperature is None else temperature
        resp = self.frontier.complete(
            role, prompt, system=system, model=model, max_tokens=max_tokens, temperature=temp,
        )
        self.spend.add(resp.cost_usd)
        return resp
