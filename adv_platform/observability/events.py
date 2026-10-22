"""Event substrate (append-only) — PLATFORM ZONE.

Every agent emits typed `Event`s here, threaded by correlation ID, so a run is
reconstructable from the store alone (CLAUDE.md §2). Payloads are PHI-redacted at
emit time (R4) via the judge's `redact()` (platform zone).

This is the minimal in-memory sink for the Phase-3 skeleton; the SQLite-backed
store + SSE dashboard (D8/D9) wrap this same interface next.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from adv_platform.judge.deterministic import redact
from adv_platform.models import AgentRole, Event, EventType, Zone


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Redact string values in a shallow payload (R4). Non-strings pass through."""
    out: dict[str, Any] = {}
    for k, v in payload.items():
        out[k] = redact(v) if isinstance(v, str) else v
    return out


class EventSink:
    def __init__(self) -> None:
        self._events: list[Event] = []
        self._subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        self._subscribers.append(fn)

    def emit(
        self,
        type: EventType,
        correlation_id: str,
        *,
        agent: Optional[AgentRole] = None,
        zone: Zone = Zone.PLATFORM,
        payload: Optional[dict[str, Any]] = None,
        cost_usd: float = 0.0,
    ) -> Event:
        ev = Event(
            type=type,
            correlation_id=correlation_id,
            agent=agent,
            zone=zone,
            payload=_redact_payload(payload or {}),
            cost_usd=cost_usd,
        )
        self._events.append(ev)
        for fn in self._subscribers:
            try:
                fn(ev)
            except Exception:
                pass  # a bad subscriber must never break the run
        return ev

    def all(self) -> list[Event]:
        return list(self._events)

    def total_cost_usd(self) -> float:
        return sum(e.cost_usd for e in self._events)

    def of_type(self, t: EventType) -> list[Event]:
        return [e for e in self._events if e.type == t]
