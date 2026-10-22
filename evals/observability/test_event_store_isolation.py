"""Regression tests for the events.db isolation + purge fix (2026-09-29).

The first live campaign's events.db was contaminated by an earlier offline/fixture
run (no target-correlation-id, canned strings) writing into the PRODUCTION store.
Fixes: (1) `SqliteEventSink.offline()` → an isolated store for offline runs;
(2) `clear()` for a pristine demo slate; (3) `purge_untargeted()` to remove any run
that never reached the real target (its target_response carries no target_correlation_id).

Run:  PYTHONPATH=. ./.venv/bin/python evals/observability/test_event_store_isolation.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from adv_platform.models import AgentRole, EventType, Zone
from adv_platform.observability.event_store import (
    OFFLINE_EVENT_STORE_PATH,
    SqliteEventSink,
)


def _sink(d: str, name: str = "events.db") -> SqliteEventSink:
    return SqliteEventSink(str(Path(d) / name))


def check_offline_path_is_isolated() -> tuple[bool, str]:
    live = "./platform_data/events.db"
    ok = OFFLINE_EVENT_STORE_PATH != live and SqliteEventSink.offline().db_path == OFFLINE_EVENT_STORE_PATH
    return ok, f"offline store = {OFFLINE_EVENT_STORE_PATH} (distinct from live {live})"


def check_clear_empties_store() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        s = _sink(d)
        s.emit(EventType.AGENT_STARTED, correlation_id="c1", agent=AgentRole.ORCHESTRATOR)
        s.emit(EventType.VERDICT, correlation_id="c1", agent=AgentRole.JUDGE,
               payload={"result": "pass"})
        n = s.clear()
        after = len(s.all())
    return n == 2 and after == 0, f"cleared {n}, remaining {after}"


def check_purge_removes_untargeted_keeps_real() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        s = _sink(d)
        # A contaminated run: target_response with NO target_correlation_id + a sibling.
        s.emit(EventType.TARGET_RESPONSE, correlation_id="bad", agent=AgentRole.REDTEAM,
               zone=Zone.ATTACKER, payload={"case_id": "X", "target_correlation_id": ""})
        s.emit(EventType.VERDICT, correlation_id="bad", agent=AgentRole.JUDGE,
               payload={"result": "fail"})
        # A real run: target_response WITH a target_correlation_id + a sibling.
        s.emit(EventType.TARGET_RESPONSE, correlation_id="good", agent=AgentRole.REDTEAM,
               zone=Zone.ATTACKER, payload={"case_id": "Y", "target_correlation_id": "tc-123"})
        s.emit(EventType.VERDICT, correlation_id="good", agent=AgentRole.JUDGE,
               payload={"result": "pass"})
        removed = s.purge_untargeted()
        left = {e.correlation_id for e in s.all()}
    ok = removed == 2 and left == {"good"}
    return ok, f"purged {removed}; remaining correlation_ids = {sorted(left)}"


def check_purge_noop_when_all_real() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        s = _sink(d)
        s.emit(EventType.TARGET_RESPONSE, correlation_id="good", agent=AgentRole.REDTEAM,
               payload={"target_correlation_id": "tc-1"})
        removed = s.purge_untargeted()
    return removed == 0, f"purged {removed} when all real (want 0)"


CHECKS = [
    check_offline_path_is_isolated,
    check_clear_empties_store,
    check_purge_removes_untargeted_keeps_real,
    check_purge_noop_when_all_real,
]


def main() -> int:
    failed = 0
    for check in CHECKS:
        try:
            passed, detail = check()
        except Exception as e:
            passed, detail = False, f"EXCEPTION {type(e).__name__}: {e}"
        if not passed:
            failed += 1
        print(f"[{'PASS' if passed else 'FAIL'}] {check.__name__}: {detail}")
    total = len(CHECKS)
    print(f"\n{total - failed}/{total} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
