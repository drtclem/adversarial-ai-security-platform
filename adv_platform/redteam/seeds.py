"""Seed loader — ATTACKER ZONE.

Loads the synthetic attack seeds from `evals/seeds/<category>.yaml` into typed
`AttackCase` models. Synthetic data only (R5). Imports only stdlib + yaml +
`models` (a shared contract, not the exploit DB / coverage / version signal).
"""

from __future__ import annotations

import pathlib
from typing import Optional

import yaml

from adv_platform.models import AttackCase, AttackCategory

# repo_root/evals/seeds — three levels up from this file (adv_platform/redteam/seeds.py)
_SEEDS_DIR = pathlib.Path(__file__).resolve().parents[2] / "evals" / "seeds"


def seeds_dir() -> pathlib.Path:
    return _SEEDS_DIR


def load_category(category: AttackCategory, path: Optional[pathlib.Path] = None) -> list[AttackCase]:
    """Load all seeds for one category from its YAML file."""
    base = path or _SEEDS_DIR
    f = base / f"{category.value}.yaml"
    if not f.exists():
        return []
    raw = yaml.safe_load(f.read_text()) or []
    return [AttackCase(**item) for item in raw]


def load_all(path: Optional[pathlib.Path] = None) -> list[AttackCase]:
    """Load every seed across all category files present."""
    out: list[AttackCase] = []
    for category in AttackCategory:
        out.extend(load_category(category, path=path))
    return out


def by_ids(cases: list[AttackCase], ids: list[str]) -> list[AttackCase]:
    """Filter to the given seed ids (order preserved); empty ids -> all."""
    if not ids:
        return cases
    wanted = set(ids)
    return [c for c in cases if c.id in wanted]
