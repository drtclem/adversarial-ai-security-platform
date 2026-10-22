"""SQLite-backed event substrate — PLATFORM ZONE.

Append-only, durable version of the EventSink: every agent's `Event`s persist to
SQLite so a run is reconstructable from the store alone (CLAUDE.md §2), and the
live dashboard (D8/D9) can tail it. Same interface as the in-memory `EventSink`
(emit/all/of_type/total_cost_usd/subscribe) plus `tail(after_seq)` — a monotonic
cursor for SSE. Payloads are PHI-redacted at emit time (R4).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable, Optional

from adv_platform.models import AgentRole, Event, EventType, Zone
from adv_platform.observability.events import _redact_payload

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    id             TEXT NOT NULL,
    type           TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    agent          TEXT,
    zone           TEXT NOT NULL,
    payload        TEXT NOT NULL,
    cost_usd       REAL NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_corr ON events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
"""

# Isolation (CLAUDE.md §1 spirit; contamination guard): OFFLINE/demo/fixture runs
# must NOT write into the production event store (the dashboard reads that). Point
# them at this separate path (or an explicit temp file) via `SqliteEventSink.offline()`.
# A live run against the real target uses `config.event_store_path`.
OFFLINE_EVENT_STORE_PATH = "./platform_data/events_offline.db"


class SqliteEventSink:
    def __init__(self, db_path: str = "./platform_data/events.db") -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._subscribers: list[Callable[[Event], None]] = []
        with self._connect() as c:
            c.executescript(_SCHEMA)

    @classmethod
    def offline(cls) -> "SqliteEventSink":
        """A sink on the ISOLATED offline store — for demo/fixture/offline runs so
        they never contaminate the production event store the dashboard reads."""
        return cls(OFFLINE_EVENT_STORE_PATH)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # concurrent dashboard reads
        return conn

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        self._subscribers.append(fn)

    # ---- maintenance: clean-slate + contamination purge ---------------------
    def clear(self) -> int:
        """Delete ALL events (clean slate for a pristine demo run). Returns count."""
        with self._connect() as c:
            n = c.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            c.execute("DELETE FROM events")
        return int(n)

    def purge_untargeted(self) -> int:
        """Remove events from any run that never reached the real target — the
        contamination signature (a `target_response` whose payload carries no
        `target_correlation_id`). All events sharing such a run's correlation_id are
        deleted. Returns the number of rows removed. A genuine live run's
        `target_response` always carries the target's own correlation id."""
        with self._connect() as c:
            rows = c.execute(
                "SELECT correlation_id, payload FROM events WHERE type = ?",
                (EventType.TARGET_RESPONSE.value,),
            ).fetchall()
            bad: set[str] = set()
            for r in rows:
                try:
                    p = json.loads(r["payload"])
                except Exception:
                    p = {}
                if not (p.get("target_correlation_id") or "").strip():
                    bad.add(r["correlation_id"])
            if not bad:
                return 0
            marks = ",".join("?" for _ in bad)
            n = c.execute(
                f"SELECT COUNT(*) AS n FROM events WHERE correlation_id IN ({marks})",
                tuple(bad),
            ).fetchone()["n"]
            c.execute(f"DELETE FROM events WHERE correlation_id IN ({marks})", tuple(bad))
        return int(n)

    # ---- write --------------------------------------------------------------
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
            payload=_redact_payload(payload or {}),  # R4
            cost_usd=cost_usd,
        )
        with self._connect() as c:
            c.execute(
                "INSERT INTO events (id,type,correlation_id,agent,zone,payload,cost_usd,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (ev.id, ev.type.value, ev.correlation_id,
                 ev.agent.value if ev.agent else None, ev.zone.value,
                 json.dumps(ev.payload, default=str), ev.cost_usd,
                 ev.created_at.isoformat()),
            )
        for fn in self._subscribers:
            try:
                fn(ev)
            except Exception:
                pass
        return ev

    # ---- read ---------------------------------------------------------------
    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            id=row["id"],
            type=EventType(row["type"]),
            correlation_id=row["correlation_id"],
            agent=AgentRole(row["agent"]) if row["agent"] else None,
            zone=Zone(row["zone"]),
            payload=json.loads(row["payload"]),
            cost_usd=row["cost_usd"],
        )

    def all(self) -> list[Event]:
        with self._connect() as c:
            rows = c.execute("SELECT * FROM events ORDER BY seq").fetchall()
        return [self._row_to_event(r) for r in rows]

    def tail(self, after_seq: int = 0) -> list[tuple[int, Event]]:
        """Events with seq > after_seq (for the SSE dashboard cursor)."""
        with self._connect() as c:
            rows = c.execute("SELECT * FROM events WHERE seq > ? ORDER BY seq",
                             (after_seq,)).fetchall()
        return [(r["seq"], self._row_to_event(r)) for r in rows]

    def of_type(self, t: EventType) -> list[Event]:
        with self._connect() as c:
            rows = c.execute("SELECT * FROM events WHERE type = ? ORDER BY seq",
                             (t.value,)).fetchall()
        return [self._row_to_event(r) for r in rows]

    def total_cost_usd(self) -> float:
        with self._connect() as c:
            row = c.execute("SELECT COALESCE(SUM(cost_usd),0) AS s FROM events").fetchone()
        return float(row["s"])
