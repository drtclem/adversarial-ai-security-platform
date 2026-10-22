"""Version-triggered regression — offline tests, $0.

Run:  PYTHONPATH=. ./.venv/bin/python evals/harness/test_version_trigger.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Optional

from adv_platform.documentation.documentation import Documentation
from adv_platform.graph import GraphDeps, run_campaign
from adv_platform.harness.version_trigger import VersionLedger, check_and_trigger, default_gate
from adv_platform.judge.judge import Judge
from adv_platform.models import EventType
from adv_platform.observability.events import EventSink
from adv_platform.orchestrator.orchestrator import Orchestrator
from adv_platform.redteam import seeds as seed_loader
from adv_platform.target_client.client import ChatResult


class Gate:
    def __init__(self, regressed: bool = False) -> None:
        self.calls, self.regressed = 0, regressed

    def __call__(self):
        self.calls += 1
        return (["f1.json", "f2.json"], [({"vuln_id": "REG-B-003"}, None)] if self.regressed else [])


def _ledger() -> VersionLedger:
    return VersionLedger(str(Path(tempfile.mkdtemp()) / "versions.json"))


def check_no_marker_is_skipped_and_said() -> tuple[bool, str]:
    g, led = Gate(), _ledger()
    r = check_and_trigger("", led, gate=g)
    return r.action == "skipped-no-marker" and g.calls == 0 and led.load() == [], f"action={r.action}, gate calls={g.calls}"


def check_first_marker_runs_suite() -> tuple[bool, str]:
    g, led = Gate(), _ledger()
    r = check_and_trigger("abc123", led, gate=g)
    return r.action == "regression-run" and g.calls == 1 and led.last_marker() == "abc123", f"{r.to_dict()}"


def check_same_marker_does_not_rerun() -> tuple[bool, str]:
    g, led = Gate(), _ledger()
    check_and_trigger("abc123", led, gate=g)
    r = check_and_trigger("abc123", led, gate=g)
    return r.action == "unchanged" and g.calls == 1, f"second call action={r.action}, gate calls={g.calls}"


def check_new_marker_reruns_and_detects_regression() -> tuple[bool, str]:
    led, sink = _ledger(), EventSink()
    check_and_trigger("v1", led, gate=Gate())
    r = check_and_trigger("v2", led, gate=Gate(regressed=True), sink=sink)
    ev = [e for e in sink.all() if e.type is EventType.REGRESSION_DETECTED]
    ok = r.previous == "v1" and r.blocked and r.regressed == ["REG-B-003"] and len(ev) == 1
    return ok, f"v1 -> v2 regressed={r.regressed}, REGRESSION_DETECTED events={len(ev)}"


def check_ledger_persists_version_history() -> tuple[bool, str]:
    led = _ledger()
    check_and_trigger("v1", led, gate=Gate())
    check_and_trigger("v2", led, gate=Gate(regressed=True))
    rows = VersionLedger(str(led.path)).load()            # fresh instance, same file
    ok = [r["marker"] for r in rows] == ["v1", "v2"] and rows[1]["regression"]["blocked"]
    return ok, f"history={[(r['marker'], r['regression']['blocked']) for r in rows]}"


def check_real_gate_runs_offline() -> tuple[bool, str]:
    fixtures, regressions = default_gate()
    return len(fixtures) >= 1 and regressions == [], f"{len(fixtures)} fixed fixture(s), regressions={len(regressions)}"


class Fixture:
    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return ChatResult(status_code=200, response="I'm sorry, but I can't help with that request.")


def _deps(marker: Optional[str], led: Optional[VersionLedger]) -> tuple[GraphDeps, EventSink]:
    seeds = seed_loader.load_all()
    sink = EventSink()
    return GraphDeps(orchestrator=Orchestrator(seeds), target=Fixture(), judge=Judge(None),
                     documentation=Documentation(), sink=sink, max_iterations=2,
                     canaries={s.id: s.canaries for s in seeds},
                     target_version=marker, version_ledger=led), sink


def check_campaign_checks_version_before_attacking() -> tuple[bool, str]:
    deps, sink = _deps("deploy-42", _ledger())
    st = run_campaign(deps)
    evs = sink.all()
    vi = next(i for i, e in enumerate(evs) if e.payload.get("version_check"))
    first_attack = next(i for i, e in enumerate(evs) if e.type is EventType.TARGET_RESPONSE)
    stamped = {t.target_version_marker for t in st["transcripts"]}
    ok = st["version_check"]["action"] == "regression-run" and vi < first_attack and stamped == {"deploy-42"}
    return ok, f"version event #{vi} before first attack #{first_attack}; transcripts stamped {stamped}"


def check_no_ledger_means_no_check() -> tuple[bool, str]:
    deps, sink = _deps("deploy-42", None)
    st = run_campaign(deps)
    ok = st["version_check"] == {} and not [e for e in sink.all() if e.payload.get("version_check")]
    return ok, "version_ledger=None: no version check, no event"


# ── cross-category regression (#6) ───────────────────────────────────────────
from adv_platform.harness.version_trigger import cross_category_flags  # noqa: E402


def check_cross_category_flags_fix_here_break_there() -> tuple[bool, str]:
    led = _ledger()
    led.record_campaign("v1", {"B": {"fail": 3, "pass": 1}, "E": {"pass": 4}})
    led.record_campaign("v2", {"B": {"pass": 4}, "E": {"fail": 2, "pass": 2}})
    f = cross_category_flags(led, "v2")
    ok = len(f) == 1 and f[0]["improved"] == "B" and f[0]["worsened"] == "E" and f[0]["from_version"] == "v1"
    return ok, f"flags={[(x['improved'], x['worsened']) for x in f]}"


def check_no_flag_when_only_one_direction() -> tuple[bool, str]:
    led = _ledger()
    led.record_campaign("v1", {"B": {"fail": 3, "pass": 1}, "E": {"pass": 4}})
    led.record_campaign("v2", {"B": {"pass": 4}, "E": {"pass": 4}})        # only improvement
    led2 = _ledger()
    led2.record_campaign("v1", {"B": {"pass": 4}, "E": {"pass": 4}})
    led2.record_campaign("v2", {"B": {"pass": 4}, "E": {"fail": 4}})       # only a worsening
    return cross_category_flags(led, "v2") == [] and cross_category_flags(led2, "v2") == [], \
        "improvement alone or worsening alone is not a cross-category regression"


def check_reappeared_fixture_counts_as_worsened() -> tuple[bool, str]:
    led = _ledger()
    led.record_campaign("v1", {"A": {"fail": 2, "pass": 2}, "B": {"pass": 4}})
    check_and_trigger("v2", led, gate=lambda: (["f"], [({"vuln_id": "REG-B-003", "category": "B"}, None)]))
    led.record_campaign("v2", {"A": {"pass": 4}, "B": {"pass": 4}})
    f = cross_category_flags(led, "v2")
    return any(x["improved"] == "A" and x["worsened"] == "B" for x in f), f"flags={[(x['improved'], x['worsened']) for x in f]}"


def check_campaign_records_results_per_version() -> tuple[bool, str]:
    led = _ledger()
    deps, _ = _deps("deploy-42", led)
    st = run_campaign(deps)
    entry = [r for r in led.load() if r["marker"] == "deploy-42"][-1]
    ok = bool(entry.get("campaign")) and st["cross_category"] == []
    return ok, f"deploy-42 campaign results by category: {entry.get('campaign')}"


CHECKS = [
    check_no_marker_is_skipped_and_said,
    check_first_marker_runs_suite,
    check_same_marker_does_not_rerun,
    check_new_marker_reruns_and_detects_regression,
    check_ledger_persists_version_history,
    check_real_gate_runs_offline,
    check_campaign_checks_version_before_attacking,
    check_no_ledger_means_no_check,
    check_cross_category_flags_fix_here_break_there,
    check_no_flag_when_only_one_direction,
    check_reappeared_fixture_counts_as_worsened,
    check_campaign_records_results_per_version,
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
