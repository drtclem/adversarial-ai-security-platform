"""Offline tests for the SQLite event substrate. $0, no network.

Run:  PYTHONPATH=. ./.venv/bin/python evals/observability/test_event_store.py
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass

from adv_platform.config import Config, PlatformMode
from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.judge.judge import Judge
from adv_platform.llm.router import LLMRouter
from adv_platform.models import AgentRole, EventType
from adv_platform.observability.event_store import SqliteEventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.target_client.client import ChatResult


def _db() -> str:
    d = tempfile.mkdtemp()
    return str(pathlib.Path(d) / "events.db")


def check_emit_and_read_back() -> tuple[bool, str]:
    s = SqliteEventSink(_db())
    s.emit(EventType.VERDICT, "corr-1", agent=AgentRole.JUDGE,
           payload={"result": "fail", "note": "SSN 123-45-6789 leaked"}, cost_usd=0.0)
    evs = s.all()
    blob = str([e.payload for e in evs])
    ok = len(evs) == 1 and "123-45-6789" not in blob and "[SSN]" in blob   # R4
    return ok, f"n={len(evs)} redacted={'123-45-6789' not in blob}"


def check_persistence_across_connections() -> tuple[bool, str]:
    path = _db()
    s1 = SqliteEventSink(path)
    s1.emit(EventType.AGENT_STARTED, "corr-a", agent=AgentRole.ORCHESTRATOR)
    s1.emit(EventType.MESSAGE_SENT, "corr-a", agent=AgentRole.ORCHESTRATOR)
    s2 = SqliteEventSink(path)                 # fresh connection, same file
    ok = len(s2.all()) == 2
    return ok, f"reopened store sees {len(s2.all())} events (durable)"


def check_tail_cursor() -> tuple[bool, str]:
    s = SqliteEventSink(_db())
    s.emit(EventType.VERDICT, "c1")
    s.emit(EventType.VERDICT, "c2")
    first = s.tail(0)
    after = s.tail(first[0][0])                 # after the first seq
    ok = len(first) == 2 and len(after) == 1 and after[0][0] > first[0][0]
    return ok, f"tail(0)={len(first)} tail(after_first)={len(after)}"


def check_total_cost_zero() -> tuple[bool, str]:
    s = SqliteEventSink(_db())
    s.emit(EventType.COST_TICK, "c", cost_usd=0.0)
    return s.total_cost_usd() == 0.0, f"total_cost={s.total_cost_usd()}"


def _router() -> LLMRouter:
    try:
        cfg = Config.load()
    except Exception:
        cfg = Config()
    return LLMRouter(cfg.model_copy(update={"platform_mode": PlatformMode.LOCAL_ONLY}))


class FixtureTarget:
    def __init__(self, r: ChatResult) -> None:
        self._r = r

    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return self._r


def check_graph_persists_to_sqlite() -> tuple[bool, str]:
    seeds = seed_loader.load_all()
    path = _db()
    deps = GraphDeps(
        orchestrator=Orchestrator(seeds),
        target=FixtureTarget(ChatResult(status_code=200, response="SSN 123-45-6789")),
        judge=Judge(_router()),
        documentation=Documentation(),
        sink=SqliteEventSink(path),
        max_iterations=2,
        canaries={s.id: s.canaries for s in seeds},
    )
    run_campaign(deps)
    reopened = SqliteEventSink(path)            # durable read after the run
    kinds = {e.type for e in reopened.all()}
    ok = (EventType.FINDING_CREATED in kinds and EventType.VERDICT in kinds
          and reopened.total_cost_usd() == 0.0
          and "123-45-6789" not in str([e.payload for e in reopened.all()]))
    return ok, f"persisted kinds={sorted(k.value for k in kinds)} cost={reopened.total_cost_usd()}"


CHECKS = [
    check_emit_and_read_back,
    check_persistence_across_connections,
    check_tail_cursor,
    check_total_cost_zero,
    check_graph_persists_to_sqlite,
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
