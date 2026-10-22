"""Version-triggered regression — PLATFORM ZONE, deterministic, $0.

Spec: the platform must trigger regression runs when the target system changes, and
run the full regression suite when the Orchestrator triggers it. The target exposes
no version field, so the platform uses an OPERATOR-STAMPED marker: whoever deploys
the Co-Pilot sets TARGET_VERSION (e.g. the deploy's git commit). The platform never
infers a version by probing the target.

At the start of every campaign the Orchestrator's run calls `check_and_trigger`:
  * no marker set          -> skipped, and the run says so (never silently "unchanged");
  * marker seen before      -> no regression run needed;
  * new marker (or first)   -> run the full regression suite NOW, before attacking, and
                               record the result against that version in the ledger.
                               With `live_gate` (the live campaign and the --live deploy
                               hook), that suite replays every published VULN's attack
                               against the deployed target, so the answer reflects the
                               new version; `default_gate` is the offline stored-fixture
                               check only.
A reappeared vulnerability is emitted as REGRESSION_DETECTED and marks the run.

The ledger (platform_data/target_versions.json) is the version history: which markers
were seen, when, what the regression suite said about each, and per-category campaign
results against each version.

Cross-category regression (spec: "flag when fixing one attack introduces a regression in
another category"): after a campaign, the current version's per-category failure rates
are compared with the previous version that has campaign results. If one category
IMPROVED while a different category got WORSE (or had a fixed vulnerability reappear),
the pair is flagged. It is a co-occurrence signal for a human, not proof of causation.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from adv_platform.models import AgentRole, EventType

# A gate returns (cases run, regressions) and may add a third item: a dict of extra
# results recorded in the ledger (e.g. {"live_replay": {...}} from the live gate).
GateFn = Callable[[], tuple]


def default_gate() -> tuple[list[str], list[tuple[dict, object]]]:
    import sys  # noqa: PLC0415
    root = pathlib.Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "evals" / "regression"))
    from regression_gate import run_gate  # noqa: PLC0415
    return run_gate()


def live_gate(chat_sequence, repeats: int = 3, save_results: bool = True,
              cases: Optional[list] = None, marker: Optional[str] = None) -> GateFn:
    """Gate that re-runs the stored-fixture check AND replays every published VULN's
    attack against the live target (evals/regression/live_replay.py). Needs an
    authenticated TargetClient's `chat_sequence`; sends real traffic. `marker` is the
    deployed TARGET_VERSION, stamped into the saved result file so it stands alone."""
    def gate() -> tuple:
        import sys  # noqa: PLC0415
        root = pathlib.Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(root / "evals" / "regression"))
        import live_replay  # noqa: PLC0415
        fixtures, fixture_regs = default_gate()
        results = live_replay.run_live(chat_sequence, cases=cases, repeats=repeats)
        if save_results:
            live_replay.save(results, marker or "")  # per-attempt evidence (redacted excerpts)
        live_ids, live_regs, extra = live_replay.as_gate(results)
        return fixtures + live_ids, fixture_regs + live_regs, extra
    return gate


@dataclass
class TriggerResult:
    marker: Optional[str]
    previous: Optional[str]
    action: str                       # "skipped-no-marker" | "unchanged" | "regression-run"
    fixtures: int = 0
    regressed: list[str] = field(default_factory=list)   # vuln ids that reappeared

    @property
    def blocked(self) -> bool:
        return bool(self.regressed)

    def to_dict(self) -> dict:
        return {**self.__dict__, "blocked": self.blocked}


class VersionLedger:
    def __init__(self, path: str = "./platform_data/target_versions.json") -> None:
        self.path = pathlib.Path(path)

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

    def last_marker(self) -> Optional[str]:
        rows = self.load()
        return rows[-1]["marker"] if rows else None

    def _save(self, rows: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(rows, indent=2) + "\n")

    def record_campaign(self, marker: str, by_category: dict[str, dict[str, int]]) -> None:
        """Add one campaign's per-category verdict counts to this version's entry."""
        rows = self.load()
        entry = next((r for r in reversed(rows) if r["marker"] == marker), None)
        if entry is None:
            entry = {"marker": marker, "first_seen": datetime.now(timezone.utc).isoformat()}
            rows.append(entry)
        agg = entry.setdefault("campaign", {})
        for cat, counts in by_category.items():
            bucket = agg.setdefault(cat, {})
            for k, n in counts.items():
                bucket[k] = bucket.get(k, 0) + n
        self._save(rows)

    def record(self, marker: str, result: TriggerResult) -> None:
        rows = self.load()
        rows.append({"marker": marker, "first_seen": datetime.now(timezone.utc).isoformat(),
                     "regression": {"fixtures": result.fixtures, "regressed": result.regressed,
                                    "blocked": result.blocked}})
        self._save(rows)


def _fail_rate(counts: dict[str, int]) -> Optional[float]:
    n = sum(counts.values())
    return None if n == 0 else (counts.get("fail", 0) + counts.get("partial", 0)) / n


def cross_category_flags(ledger: VersionLedger, marker: str, min_delta: float = 0.10) -> list[dict]:
    """Compare `marker` with the previous version that has campaign results. A flag is a
    (improved category, worsened category) pair: one got better while another got worse."""
    rows = [r for r in ledger.load() if r.get("campaign")]
    cur = next((r for r in reversed(rows) if r["marker"] == marker), None)
    prev = next((r for r in reversed(rows) if r["marker"] != marker), None)
    if cur is None or prev is None:
        return []
    improved, worsened = [], []
    for cat in sorted(set(cur["campaign"]) & set(prev["campaign"])):
        a, b = _fail_rate(prev["campaign"][cat]), _fail_rate(cur["campaign"][cat])
        if a is None or b is None:
            continue
        if a - b >= min_delta:
            improved.append((cat, round(a, 3), round(b, 3)))
        elif b - a >= min_delta:
            worsened.append((cat, round(a, 3), round(b, 3)))
    # a fixed vuln reappearing in this version counts as its category getting worse
    for cat in cur.get("regression", {}).get("regressed_categories", []):
        if cat not in [w[0] for w in worsened]:
            worsened.append((cat, None, None))
    flags = []
    for fc, fa, fb in improved:
        for wc, wa, wb in worsened:
            if fc != wc:
                flags.append({"from_version": prev["marker"], "to_version": marker,
                              "improved": fc, "improved_fail_rate": [fa, fb],
                              "worsened": wc, "worsened_fail_rate": [wa, wb],
                              "note": f"{fc} improved while {wc} got worse between versions: "
                                      "review whether the fix in one caused the other"})
    return flags


def check_and_trigger(marker: Optional[str], ledger: VersionLedger, gate: GateFn = default_gate,
                      sink=None) -> TriggerResult:
    marker = (marker or "").strip() or None
    previous = ledger.last_marker()
    if marker is None:
        r = TriggerResult(None, previous, "skipped-no-marker")
    elif marker == previous:
        r = TriggerResult(marker, previous, "unchanged")
    else:
        out = gate()
        fixtures, regressions = out[0], out[1]
        extra = out[2] if len(out) > 2 else {}
        r = TriggerResult(marker, previous, "regression-run", fixtures=len(fixtures),
                          regressed=[d.get("vuln_id", "?") for d, _ in regressions])
        ledger.record(marker, r)
        if extra:                                   # e.g. live-replay verdicts per VULN
            rows = ledger.load()
            rows[-1]["regression"].update(extra)
            ledger._save(rows)
        cats = sorted({d.get("category") for d, _ in regressions if d.get("category")})
        if cats:                                    # keep which categories regressed
            rows = ledger.load()
            rows[-1]["regression"]["regressed_categories"] = cats
            ledger._save(rows)
    if sink is not None:
        etype = EventType.REGRESSION_DETECTED if r.blocked else EventType.AGENT_THINKING
        sink.emit(etype, correlation_id="version-trigger", agent=AgentRole.ORCHESTRATOR,
                  payload={"version_check": True, **r.to_dict()})
    return r
