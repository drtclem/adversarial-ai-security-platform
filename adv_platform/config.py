"""Platform configuration — PLATFORM_ZONE.

Single source of truth for mode, cost caps, target coordinates, and model names.
Loaded from environment (.env). NEVER logs secrets: `TARGET_PASSWORD` and
`ANTHROPIC_API_KEY` are masked in every repr/str (CLAUDE.md §1, R6).

Cost-control invariants this module encodes (CLAUDE.md §0):
  - Default mode is `local-only` (zero paid API).
  - `dry_run` is True whenever mode != `live` — the frontier client keys off this to
    hard-refuse paid calls.
  - `MAX_RUN_USD` is the hard per-run budget cap the router enforces.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache

from pydantic import BaseModel, Field, field_validator


class PlatformMode(str, Enum):
    """The two run modes. `local-only` is the default and spends $0."""

    LOCAL_ONLY = "local-only"
    LIVE = "live"


def _env(key: str, default: str = "") -> str:
    """Read one setting. A blank value followed by a comment (`KEY=   # note`, the
    shape .env.example uses) is read by python-dotenv as the comment text itself;
    treat that as unset, so e.g. JUDGE_MODEL never becomes '# cheap frontier...'."""
    value = os.environ.get(key)
    if value is None:
        return default
    if value.strip().startswith("#"):
        return default
    return value


def _load_dotenv_once() -> None:
    """Best-effort .env load; harmless if python-dotenv is absent or file missing."""
    try:
        from dotenv import load_dotenv

        # explicit path so CLI/stdin scripts (no __file__) still find it
        load_dotenv(os.path.join(os.getcwd(), ".env"))
    except Exception:
        pass


class Config(BaseModel):
    """Immutable-ish settings snapshot. Build via `Config.load()`."""

    # ── mode & cost ──────────────────────────────────────────────────────
    platform_mode: PlatformMode = PlatformMode.LOCAL_ONLY
    max_run_usd: float = Field(default=0.50, ge=0.0)
    default_campaign_size: int = Field(default=8, ge=1)

    # ── target (attacker zone reads these) ───────────────────────────────
    target_base_url: str = "http://localhost:8420"
    target_username: str = ""
    target_password: str = ""
    # the target's OWN OAuth server (scoped auth exception, R9) — derived, overridable
    target_auth_host: str = "localhost:9300"

    # ── local model (Red Team + Orchestrator; all roles in local-only) ───
    ollama_base_url: str = "http://localhost:11434"
    local_model: str = ""

    # ── frontier (ONLY used in live: Judge + Documentation) ──────────────
    anthropic_api_key: str = ""
    judge_model: str = ""
    judge_escalation_model: str = ""
    doc_model: str = ""

    # ── target version marker (operator-stamped; triggers the regression suite) ──
    target_version: str = ""
    version_ledger_path: str = "./platform_data/target_versions.json"

    # ── calibrated-classifier tier (Laya) — SHADOW MODE, off by default ───
    # judge_shadow="laya" records Laya's opinion next to every LLM-tier verdict
    # without changing any verdict. Local, $0 (self-hosted weights; PHI stays here).
    judge_shadow: str = ""
    laya_model: str = "convaiinnovations/laya"
    laya_device: str = ""                  # "" = auto (mps on Apple Silicon)
    laya_calibration: str = ""             # optional temperature JSON from laya.fit_temperatures
    laya_accept_hi: float = Field(default=0.9, ge=0.5, le=1.0)
    laya_accept_lo: float = Field(default=0.1, ge=0.0, le=0.5)

    # ── observability (optional; off in local-only) ──────────────────────
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = ""

    # ── storage ───────────────────────────────────────────────────────────
    exploit_db_path: str = "./platform_data/exploits.db"
    event_store_path: str = "./platform_data/events.db"

    @field_validator("platform_mode", mode="before")
    @classmethod
    def _coerce_mode(cls, v: object) -> object:
        if isinstance(v, str):
            return v.strip().lower()
        return v

    # ── derived helpers ───────────────────────────────────────────────────
    @property
    def is_local_only(self) -> bool:
        return self.platform_mode == PlatformMode.LOCAL_ONLY

    @property
    def is_live(self) -> bool:
        return self.platform_mode == PlatformMode.LIVE

    @property
    def dry_run(self) -> bool:
        """True whenever we are NOT in live mode. The frontier client refuses to
        spend when this is True — a paid call in dry_run is a bug (CLAUDE.md §0.5)."""
        return not self.is_live

    # ── construction ────────────────────────────────────────────────────
    @classmethod
    def load(cls) -> "Config":
        _load_dotenv_once()

        def num(key: str, default: float) -> float:
            raw = _env(key)
            try:
                return float(raw) if raw != "" else default
            except ValueError:
                return default

        def integer(key: str, default: int) -> int:
            raw = _env(key)
            try:
                return int(raw) if raw != "" else default
            except ValueError:
                return default

        return cls(
            platform_mode=_env("PLATFORM_MODE", PlatformMode.LOCAL_ONLY.value),
            max_run_usd=num("MAX_RUN_USD", 0.50),
            default_campaign_size=integer("DEFAULT_CAMPAIGN_SIZE", 8),
            target_base_url=_env("TARGET_BASE_URL", "http://localhost:8420").rstrip("/"),
            target_username=_env("TARGET_USERNAME").strip(),
            target_password=_env("TARGET_PASSWORD"),
            target_auth_host=_env("TARGET_AUTH_HOST", "localhost:9300"),
            ollama_base_url=_env("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
            local_model=_env("LOCAL_MODEL").strip(),
            anthropic_api_key=_env("ANTHROPIC_API_KEY").strip(),
            judge_model=_env("JUDGE_MODEL").strip(),
            judge_escalation_model=_env("JUDGE_ESCALATION_MODEL").strip(),
            doc_model=_env("DOC_MODEL").strip(),
            target_version=_env("TARGET_VERSION").strip(),
            version_ledger_path=_env("VERSION_LEDGER_PATH", "./platform_data/target_versions.json"),
            judge_shadow=_env("JUDGE_SHADOW").strip().lower(),
            laya_model=_env("LAYA_MODEL", "convaiinnovations/laya").strip(),
            laya_device=_env("LAYA_DEVICE").strip(),
            laya_calibration=_env("LAYA_CALIBRATION").strip(),
            laya_accept_hi=num("LAYA_ACCEPT_HI", 0.9),
            laya_accept_lo=num("LAYA_ACCEPT_LO", 0.1),
            langfuse_public_key=_env("LANGFUSE_PUBLIC_KEY").strip(),
            langfuse_secret_key=_env("LANGFUSE_SECRET_KEY").strip(),
            langfuse_host=_env("LANGFUSE_HOST").strip(),
            exploit_db_path=_env("EXPLOIT_DB_PATH", "./platform_data/exploits.db"),
            event_store_path=_env("EVENT_STORE_PATH", "./platform_data/events.db"),
        )

    # ── secret-safe rendering (R6) ────────────────────────────────────────
    @staticmethod
    def _mask(value: str) -> str:
        if not value:
            return ""
        return f"***set(len={len(value)})***"

    def safe_dict(self) -> dict:
        """Config as a dict with secrets masked — safe to log / show on a dashboard."""
        d = self.model_dump()
        d["target_password"] = self._mask(self.target_password)
        d["anthropic_api_key"] = self._mask(self.anthropic_api_key)
        d["langfuse_secret_key"] = self._mask(self.langfuse_secret_key)
        d["platform_mode"] = self.platform_mode.value
        return d

    def __repr__(self) -> str:  # never leak secrets in a repr
        return f"Config({self.safe_dict()})"

    __str__ = __repr__


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Process-wide cached config. Call `get_config.cache_clear()` in tests to reload."""
    return Config.load()
