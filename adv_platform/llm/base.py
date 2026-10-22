"""Shared LLM types, pricing, and exceptions — PLATFORM_ZONE.

The router (router.py) is the cost gate; local.py and frontier.py are the two
backends. Everything they share lives here so the gate logic stays in one place.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from adv_platform.models import AgentRole


# ── result of any LLM call (local or frontier) ───────────────────────────────
class LLMResponse(BaseModel):
    text: str
    role: AgentRole
    model: str
    backend: str                       # "local" | "frontier" | "deterministic"
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0              # ALWAYS 0.0 for local (CLAUDE.md §0)
    refused: bool = False             # model declined (logged, not hidden)
    meta: dict[str, Any] = Field(default_factory=dict)


# ── exceptions ───────────────────────────────────────────────────────────────
class LLMError(Exception):
    """Base for all LLM-layer errors."""


class LocalModelUnavailable(LLMError):
    """Ollama unreachable or the model tag isn't pulled."""


class ModelRefused(LLMError):
    """The (local) model refused to produce output. Logged, never scored as pass."""


class FrontierRefusedInDryRun(LLMError):
    """A paid call was attempted while not in `live` mode. This is a BUG, not an
    option (CLAUDE.md §0.5) — the frontier client hard-refuses."""


class BudgetExceeded(LLMError):
    """The per-run USD cap would be exceeded. The run stops gracefully (§0.4)."""


# ── pricing (USD per 1M tokens) — ONLY used to estimate `live` spend ─────────
# Conservative Haiku-class defaults; matched by case-insensitive substring on the
# model id. Local models are always $0 and never consult this table.
_PRICE_PER_MTOK: list[tuple[str, float, float]] = [
    # (substring, input_price_per_1M, output_price_per_1M)
    ("haiku", 1.00, 5.00),     # Haiku 4.5 list price (Haiku 3.5 was 0.80/4.00)
    ("sonnet", 3.00, 15.00),
    ("opus", 15.00, 75.00),
]
_DEFAULT_PRICE = (1.00, 5.00)  # unknown frontier model → conservative-ish


def price_for(model: str) -> tuple[float, float]:
    m = (model or "").lower()
    for sub, pin, pout in _PRICE_PER_MTOK:
        if sub in m:
            return pin, pout
    return _DEFAULT_PRICE


def estimate_cost_usd(model: str, tokens_in: int, tokens_out: int) -> float:
    pin, pout = price_for(model)
    return (tokens_in / 1_000_000.0) * pin + (tokens_out / 1_000_000.0) * pout


def estimate_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token) for budgeting before a call."""
    if not text:
        return 0
    return max(1, len(text) // 4)
